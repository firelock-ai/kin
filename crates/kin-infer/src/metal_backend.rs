// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Metal GPU compute backend for macOS (Apple Silicon).
//!
//! Custom MSL compute shaders for transformer operations.
//! No candle, no ONNX, no MPS — direct Metal API via objc2-metal.

#![cfg(feature = "metal")]

use crate::gpu::{GpuBackend, GpuCompute, GpuDeviceInfo};
use metal::{
    Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device, MTLResourceOptions, MTLSize,
};
use parking_lot::Mutex;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// MSL shader source — all transformer ops in one library
// ---------------------------------------------------------------------------

const SHADER_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

// ---- Matrix multiply: C = A × B^T ----
// A is [M, K], B is [N, K] (row-major), C is [M, N]
// Threadgroup-tiled kernel for projection-heavy transformer workloads.
kernel void matmul_transb(
    device const float* A       [[buffer(0)]],
    device const float* B       [[buffer(1)]],
    device float* C             [[buffer(2)]],
    constant uint& M            [[buffer(3)]],
    constant uint& N            [[buffer(4)]],
    constant uint& K            [[buffer(5)]],
    uint2 gid                   [[thread_position_in_grid]],
    uint2 tid                   [[thread_position_in_threadgroup]],
    uint2 tgs                   [[threads_per_threadgroup]]
) {
    constexpr uint TILE = 16;
    threadgroup float a_tile[TILE][TILE];
    threadgroup float b_tile[TILE][TILE];

    uint row = gid.y;
    uint col = gid.x;

    float sum = 0.0;
    for (uint tile = 0; tile < K; tile += TILE) {
        for (uint a_local = tid.x; a_local < TILE; a_local += tgs.x) {
            uint a_col = tile + a_local;
            if (row < M && a_col < K) {
                a_tile[tid.y][a_local] = A[row * K + a_col];
            } else {
                a_tile[tid.y][a_local] = 0.0;
            }
        }

        for (uint b_local = tid.y; b_local < TILE; b_local += tgs.y) {
            uint b_k = tile + b_local;
            if (col < N && b_k < K) {
                b_tile[b_local][tid.x] = B[col * K + b_k];
            } else {
                b_tile[b_local][tid.x] = 0.0;
            }
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
        for (uint i = 0; i < TILE; i++) {
            sum += a_tile[tid.y][i] * b_tile[i][tid.x];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < M && col < N) {
        C[row * N + col] = sum;
    }
}

// ---- Softmax over rows ----
// data is [rows, cols], normalize each row independently
kernel void softmax_rows(
    device float* data          [[buffer(0)]],
    constant uint& cols         [[buffer(1)]],
    uint gid                    [[thread_position_in_grid]]
) {
    uint row_offset = gid * cols;

    // Find max
    float max_val = -INFINITY;
    for (uint j = 0; j < cols; j++) {
        max_val = max(max_val, data[row_offset + j]);
    }

    // Exp and sum
    float sum = 0.0;
    for (uint j = 0; j < cols; j++) {
        float v = exp(data[row_offset + j] - max_val);
        data[row_offset + j] = v;
        sum += v;
    }

    // Normalize
    if (sum > 0.0) {
        float inv_sum = 1.0 / sum;
        for (uint j = 0; j < cols; j++) {
            data[row_offset + j] *= inv_sum;
        }
    }
}

// ---- LayerNorm ----
kernel void layer_norm(
    device float* data          [[buffer(0)]],
    device const float* gamma   [[buffer(1)]],
    device const float* beta    [[buffer(2)]],
    constant uint& cols         [[buffer(3)]],
    constant float& eps         [[buffer(4)]],
    uint gid                    [[thread_position_in_grid]]
) {
    uint off = gid * cols;
    float len = float(cols);

    // Mean
    float mean = 0.0;
    for (uint j = 0; j < cols; j++) mean += data[off + j];
    mean /= len;

    // Variance
    float var = 0.0;
    for (uint j = 0; j < cols; j++) {
        float d = data[off + j] - mean;
        var += d * d;
    }
    var /= len;

    float inv_std = rsqrt(var + eps);
    for (uint j = 0; j < cols; j++) {
        data[off + j] = (data[off + j] - mean) * inv_std * gamma[j] + beta[j];
    }
}

// ---- RMSNorm ----
kernel void rms_norm(
    device float* data          [[buffer(0)]],
    device const float* weight  [[buffer(1)]],
    constant uint& cols         [[buffer(2)]],
    constant float& eps         [[buffer(3)]],
    uint gid                    [[thread_position_in_grid]]
) {
    uint off = gid * cols;
    float len = float(cols);

    float sq_sum = 0.0;
    for (uint j = 0; j < cols; j++) {
        float v = data[off + j];
        sq_sum += v * v;
    }
    float inv_rms = rsqrt(sq_sum / len + eps);

    for (uint j = 0; j < cols; j++) {
        data[off + j] = data[off + j] * inv_rms * weight[j];
    }
}

// ---- GELU activation (in-place) ----
kernel void gelu_activation(
    device float* data          [[buffer(0)]],
    uint gid                    [[thread_position_in_grid]]
) {
    float x = data[gid];
    data[gid] = x * 0.5 * (1.0 + tanh(x * 0.7978845608 * (1.0 + 0.044715 * x * x)));
}

// ---- SiLU activation (in-place) ----
kernel void silu_activation(
    device float* data          [[buffer(0)]],
    uint gid                    [[thread_position_in_grid]]
) {
    float x = data[gid];
    data[gid] = x / (1.0 + exp(-x));
}

// ---- Element-wise multiply (in-place): a *= b ----
kernel void elementwise_mul(
    device float* a             [[buffer(0)]],
    device const float* b       [[buffer(1)]],
    uint gid                    [[thread_position_in_grid]]
) {
    a[gid] *= b[gid];
}

// ---- RoPE (rotary position encoding, in-place) ----
// data is [seq_len, total_dim], cos/sin tables are [max_seq, half_head_dim]
kernel void rope_apply(
    device float* data              [[buffer(0)]],
    device const float* cos_table   [[buffer(1)]],
    device const float* sin_table   [[buffer(2)]],
    constant uint& seq_offset       [[buffer(3)]],
    constant uint& head_dim         [[buffer(4)]],
    constant uint& total_dim        [[buffer(5)]],
    constant uint& half_dim         [[buffer(6)]],
    uint2 gid                       [[thread_position_in_grid]]
) {
    // gid.y = position in sequence, gid.x = pair index within total_dim
    uint pos = gid.y;
    uint pair = gid.x;

    // Which head does this pair belong to?
    uint head = pair / (head_dim / 2);
    uint d = pair % (head_dim / 2);
    uint base = pos * total_dim + head * head_dim;

    uint table_off = (seq_offset + pos) * half_dim + d;
    float cos_val = cos_table[table_off];
    float sin_val = sin_table[table_off];

    float x0 = data[base + d];
    float x1 = data[base + head_dim / 2 + d];
    data[base + d]              = x0 * cos_val - x1 * sin_val;
    data[base + head_dim / 2 + d] = x1 * cos_val + x0 * sin_val;
}

// ---- Batched matmul: C[h] = A[h] × B[h]^T for all heads ----
// A is [num_heads, seq_len, head_dim] flattened (head-major)
// B is [num_heads, seq_len, head_dim] flattened (head-major)
// C is [num_heads, seq_len, seq_len] flattened
// 3D grid: (seq_len, seq_len, num_heads)
// Threadgroup-tiled to keep attention Q×K^T from falling back to a naive dot
// product per output element.
kernel void batched_matmul_transb(
    device const float* A       [[buffer(0)]],
    device const float* B       [[buffer(1)]],
    device float* C             [[buffer(2)]],
    constant uint& seq_len      [[buffer(3)]],
    constant uint& head_dim     [[buffer(4)]],
    uint3 gid                   [[thread_position_in_grid]],
    uint3 tid                   [[thread_position_in_threadgroup]],
    uint3 tgs                   [[threads_per_threadgroup]]
) {
    constexpr uint TILE = 16;
    threadgroup float a_tile[TILE][TILE];
    threadgroup float b_tile[TILE][TILE];

    uint col  = gid.x;  // j in [0, seq_len)
    uint row  = gid.y;  // i in [0, seq_len)
    uint head = gid.z;  // h in [0, num_heads)

    uint head_off = head * seq_len * head_dim;
    uint c_off = head * seq_len * seq_len + row * seq_len + col;

    float sum = 0.0;
    for (uint tile = 0; tile < head_dim; tile += TILE) {
        for (uint a_local = tid.x; a_local < TILE; a_local += tgs.x) {
            uint d = tile + a_local;
            if (row < seq_len && d < head_dim) {
                a_tile[tid.y][a_local] = A[head_off + row * head_dim + d];
            } else {
                a_tile[tid.y][a_local] = 0.0;
            }
        }

        for (uint b_local = tid.y; b_local < TILE; b_local += tgs.y) {
            uint d = tile + b_local;
            if (col < seq_len && d < head_dim) {
                b_tile[b_local][tid.x] = B[head_off + col * head_dim + d];
            } else {
                b_tile[b_local][tid.x] = 0.0;
            }
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
        for (uint i = 0; i < TILE; i++) {
            sum += a_tile[tid.y][i] * b_tile[i][tid.x];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < seq_len && col < seq_len) {
        C[c_off] = sum;
    }
}

// ---- Batched matmul (non-transposed): C[h] = A[h] × B[h] ----
// For scores × V: A is [num_heads, seq_len, seq_len], B is [num_heads, seq_len, head_dim]
// C is [num_heads, seq_len, head_dim]
// 3D grid: (head_dim, seq_len, num_heads)
// Threadgroup-tiled to keep attention scores×V on the same optimized path.
kernel void batched_matmul_ab(
    device const float* A       [[buffer(0)]],
    device const float* B       [[buffer(1)]],
    device float* C             [[buffer(2)]],
    constant uint& seq_len      [[buffer(3)]],
    constant uint& head_dim     [[buffer(4)]],
    uint3 gid                   [[thread_position_in_grid]],
    uint3 tid                   [[thread_position_in_threadgroup]],
    uint3 tgs                   [[threads_per_threadgroup]]
) {
    constexpr uint TILE = 16;
    threadgroup float a_tile[TILE][TILE];
    threadgroup float b_tile[TILE][TILE];

    uint col  = gid.x;  // j in [0, head_dim)
    uint row  = gid.y;  // i in [0, seq_len)
    uint head = gid.z;  // h in [0, num_heads)

    uint a_head_off = head * seq_len * seq_len;
    uint b_head_off = head * seq_len * head_dim;
    uint c_off = b_head_off + row * head_dim + col;

    float sum = 0.0;
    for (uint tile = 0; tile < seq_len; tile += TILE) {
        for (uint a_local = tid.x; a_local < TILE; a_local += tgs.x) {
            uint k = tile + a_local;
            if (row < seq_len && k < seq_len) {
                a_tile[tid.y][a_local] = A[a_head_off + row * seq_len + k];
            } else {
                a_tile[tid.y][a_local] = 0.0;
            }
        }

        for (uint b_local = tid.y; b_local < TILE; b_local += tgs.y) {
            uint k = tile + b_local;
            if (col < head_dim && k < seq_len) {
                b_tile[b_local][tid.x] = B[b_head_off + k * head_dim + col];
            } else {
                b_tile[b_local][tid.x] = 0.0;
            }
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
        for (uint i = 0; i < TILE; i++) {
            sum += a_tile[tid.y][i] * b_tile[i][tid.x];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < seq_len && col < head_dim) {
        C[c_off] = sum;
    }
}

// ---- Scale + ALiBi + mask (fused, in-place on scores) ----
// scores is [num_heads, seq_len, seq_len] flattened
// alibi_slopes is [num_heads] (or empty if no ALiBi)
// mask is [seq_len] (1 = keep, 0 = mask out)
kernel void scale_mask_alibi(
    device float* scores            [[buffer(0)]],
    device const float* alibi       [[buffer(1)]],
    device const uint* mask         [[buffer(2)]],
    constant float& scale           [[buffer(3)]],
    constant uint& seq_len          [[buffer(4)]],
    constant uint& has_alibi        [[buffer(5)]],
    uint3 gid                       [[thread_position_in_grid]]
) {
    uint col  = gid.x;  // j
    uint row  = gid.y;  // i
    uint head = gid.z;  // h

    if (row >= seq_len || col >= seq_len) return;

    uint idx = head * seq_len * seq_len + row * seq_len + col;
    float val = scores[idx] * scale;

    if (has_alibi) {
        float slope = alibi[head];
        int dist = (int)col - (int)row;
        val += slope * abs(dist);
    }

    if (mask[col] == 0) {
        val = -INFINITY;
    }

    scores[idx] = val;
}

// ---- Scale + ALiBi + grouped mask (fused, in-place on scores) ----
// scores is [num_groups * heads_per_group, seq_len, seq_len] flattened
// alibi is [heads_per_group] (or empty if no ALiBi)
// mask is [num_groups, seq_len] flattened row-major
kernel void scale_mask_alibi_grouped(
    device float* scores            [[buffer(0)]],
    device const float* alibi       [[buffer(1)]],
    device const uint* mask         [[buffer(2)]],
    constant float& scale           [[buffer(3)]],
    constant uint& seq_len          [[buffer(4)]],
    constant uint& has_alibi        [[buffer(5)]],
    constant uint& heads_per_group  [[buffer(6)]],
    uint3 gid                       [[thread_position_in_grid]]
) {
    uint col  = gid.x;  // j
    uint row  = gid.y;  // i
    uint head = gid.z;  // grouped head index

    if (row >= seq_len || col >= seq_len) return;

    uint idx = head * seq_len * seq_len + row * seq_len + col;
    float val = scores[idx] * scale;

    uint head_in_group = head % heads_per_group;
    uint group = head / heads_per_group;

    if (has_alibi) {
        float slope = alibi[head_in_group];
        int dist = (int)col - (int)row;
        val += slope * abs(dist);
    }

    if (mask[group * seq_len + col] == 0) {
        val = -INFINITY;
    }

    scores[idx] = val;
}
"#;

// ---------------------------------------------------------------------------
// Metal compute context
// ---------------------------------------------------------------------------

pub struct MetalCompute {
    device: Device,
    queue: CommandQueue,
    pipelines: HashMap<&'static str, ComputePipelineState>,
    device_name: String,
    /// Cache weight buffers on GPU keyed by (data_ptr, len). Weight matrices
    /// are the same across all forward passes, so allocating once and reusing
    /// eliminates ~100GB of redundant copies for a typical embedding run.
    weight_cache: Mutex<HashMap<(usize, usize), Buffer>>,
    /// Cache stable u32 buffers like flattened masks that are reused across
    /// every layer in a batch.
    u32_cache: Mutex<HashMap<(usize, usize), Buffer>>,
}

impl MetalCompute {
    /// Try to create a Metal compute context. Returns None if Metal is unavailable.
    pub fn try_new() -> Option<Self> {
        let device = Device::system_default()?;
        let queue = device.new_command_queue();
        let device_name = device.name().to_string();

        let opts = CompileOptions::new();
        let library = match device.new_library_with_source(SHADER_SOURCE, &opts) {
            Ok(library) => library,
            Err(err) => {
                eprintln!("kin-infer: Metal shader compile failed: {err}");
                return None;
            }
        };

        let kernel_names: &[&str] = &[
            "matmul_transb",
            "batched_matmul_transb",
            "batched_matmul_ab",
            "scale_mask_alibi",
            "scale_mask_alibi_grouped",
            "softmax_rows",
            "layer_norm",
            "rms_norm",
            "gelu_activation",
            "silu_activation",
            "elementwise_mul",
            "rope_apply",
        ];

        let mut pipelines = HashMap::new();
        for &name in kernel_names {
            let func = match library.get_function(name, None) {
                Ok(func) => func,
                Err(err) => {
                    eprintln!("kin-infer: Metal function lookup failed for {name}: {err}");
                    return None;
                }
            };
            let pipeline = match device.new_compute_pipeline_state_with_function(&func) {
                Ok(pipeline) => pipeline,
                Err(err) => {
                    eprintln!("kin-infer: Metal pipeline build failed for {name}: {err}");
                    return None;
                }
            };
            pipelines.insert(name, pipeline);
        }

        Some(Self {
            device,
            queue,
            pipelines,
            device_name,
            weight_cache: Mutex::new(HashMap::new()),
            u32_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Create a Metal buffer from a slice and copy data in.
    fn buf_from_slice(&self, data: &[f32]) -> Buffer {
        let bytes = data.len() * std::mem::size_of::<f32>();
        self.device.new_buffer_with_data(
            data.as_ptr() as *const _,
            bytes as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    /// Create a zero-filled Metal buffer of given float count.
    fn buf_zeros(&self, count: usize) -> Buffer {
        let bytes = count * std::mem::size_of::<f32>();
        self.device
            .new_buffer(bytes as u64, MTLResourceOptions::StorageModeShared)
    }

    /// Create a buffer containing a single u32 value.
    fn buf_u32(&self, val: u32) -> Buffer {
        let data = [val];
        self.device.new_buffer_with_data(
            data.as_ptr() as *const _,
            std::mem::size_of::<u32>() as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    /// Create a buffer containing a single f32 value.
    fn buf_f32(&self, val: f32) -> Buffer {
        let data = [val];
        self.device.new_buffer_with_data(
            data.as_ptr() as *const _,
            std::mem::size_of::<f32>() as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    /// Get or create a cached buffer for persistent data (weight matrices).
    /// Keyed by (pointer, len) — weight Array2 data pointers are stable
    /// across forward passes, so this hits on every call after the first.
    fn buf_cached(&self, data: &[f32]) -> Buffer {
        let key = (data.as_ptr() as usize, data.len());
        let mut cache = self.weight_cache.lock();
        if let Some(buf) = cache.get(&key) {
            return buf.clone();
        }
        let buf = self.buf_from_slice(data);
        cache.insert(key, buf.clone());
        buf
    }

    /// Get or create a cached buffer for stable u32 payloads.
    fn buf_cached_u32(&self, data: &[u32]) -> Buffer {
        let key = (data.as_ptr() as usize, data.len());
        let mut cache = self.u32_cache.lock();
        if let Some(buf) = cache.get(&key) {
            return buf.clone();
        }
        let bytes = data.len() * std::mem::size_of::<u32>();
        let buf = self.device.new_buffer_with_data(
            data.as_ptr() as *const _,
            bytes as u64,
            MTLResourceOptions::StorageModeShared,
        );
        cache.insert(key, buf.clone());
        buf
    }

    /// Read floats back from a Metal buffer.
    fn read_buf(buf: &Buffer, count: usize) -> Vec<f32> {
        let ptr = buf.contents() as *const f32;
        let slice = unsafe { std::slice::from_raw_parts(ptr, count) };
        slice.to_vec()
    }

    /// Read floats from a shared buffer in-place into a mutable slice.
    fn read_buf_into(buf: &Buffer, dst: &mut [f32]) {
        let ptr = buf.contents() as *const f32;
        let src = unsafe { std::slice::from_raw_parts(ptr, dst.len()) };
        dst.copy_from_slice(src);
    }

    /// Dispatch a 1D compute kernel.
    fn dispatch_1d(&self, pipeline_name: &str, buffers: &[&Buffer], total_threads: usize) {
        let pipeline = &self.pipelines[pipeline_name];
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }

        let thread_w = pipeline.thread_execution_width() as usize;
        let threads = MTLSize::new(total_threads as u64, 1, 1);
        let tg_size = MTLSize::new(thread_w.min(total_threads) as u64, 1, 1);
        enc.dispatch_threads(threads, tg_size);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
    }

    /// Dispatch a 3D compute kernel (for batched multi-head attention).
    fn dispatch_3d(
        &self,
        pipeline_name: &str,
        buffers: &[&Buffer],
        width: usize,
        height: usize,
        depth: usize,
    ) {
        let pipeline = &self.pipelines[pipeline_name];
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }

        let threads = MTLSize::new(width as u64, height as u64, depth as u64);
        let tg_size = MTLSize::new(
            8.min(width) as u64,
            8.min(height) as u64,
            1.min(depth) as u64,
        );
        enc.dispatch_threads(threads, tg_size);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
    }

    /// Dispatch a 2D compute kernel.
    fn dispatch_2d(&self, pipeline_name: &str, buffers: &[&Buffer], width: usize, height: usize) {
        let pipeline = &self.pipelines[pipeline_name];
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }

        let threads = MTLSize::new(width as u64, height as u64, 1);
        let tg_size = MTLSize::new(16.min(width) as u64, 16.min(height) as u64, 1);
        enc.dispatch_threads(threads, tg_size);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
    }
}

impl GpuCompute for MetalCompute {
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, n: usize, k: usize) -> Vec<f32> {
        let buf_a = self.buf_from_slice(a);
        // Cache B (weight matrix): stable pointers across forward passes
        let buf_b = self.buf_cached(b);
        let buf_c = self.buf_zeros(m * n);
        let buf_m = self.buf_u32(m as u32);
        let buf_n = self.buf_u32(n as u32);
        let buf_k = self.buf_u32(k as u32);

        self.dispatch_2d(
            "matmul_transb",
            &[&buf_a, &buf_b, &buf_c, &buf_m, &buf_n, &buf_k],
            n,
            m,
        );

        Self::read_buf(&buf_c, m * n)
    }

    fn matmul_many(
        &self,
        a: &[f32],
        weights: &[&[f32]],
        m: usize,
        ns: &[usize],
        k: usize,
    ) -> Vec<Vec<f32>> {
        if weights.is_empty() {
            return Vec::new();
        }

        let buf_a = self.buf_from_slice(a);
        let buf_m = self.buf_u32(m as u32);
        let buf_k = self.buf_u32(k as u32);
        let pipeline = &self.pipelines["matmul_transb"];
        let cmd = self.queue.new_command_buffer();
        let mut outputs = Vec::with_capacity(weights.len());

        for (weight, n) in weights.iter().zip(ns.iter().copied()) {
            let buf_b = self.buf_cached(weight);
            let buf_c = self.buf_zeros(m * n);
            let buf_n = self.buf_u32(n as u32);
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(pipeline);
            enc.set_buffer(0, Some(&buf_a), 0);
            enc.set_buffer(1, Some(&buf_b), 0);
            enc.set_buffer(2, Some(&buf_c), 0);
            enc.set_buffer(3, Some(&buf_m), 0);
            enc.set_buffer(4, Some(&buf_n), 0);
            enc.set_buffer(5, Some(&buf_k), 0);
            let threads = MTLSize::new(n as u64, m as u64, 1);
            let tg_size = MTLSize::new(16.min(n) as u64, 16.min(m) as u64, 1);
            enc.dispatch_threads(threads, tg_size);
            enc.end_encoding();

            outputs.push((buf_c, n));
        }

        cmd.commit();
        cmd.wait_until_completed();

        outputs
            .into_iter()
            .map(|(buf, n)| Self::read_buf(&buf, m * n))
            .collect()
    }

    fn batched_matmul(
        &self,
        q: &[f32],
        k: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Vec<f32> {
        // Single 3D dispatch: all heads computed in one GPU submission.
        let buf_q = self.buf_from_slice(q);
        let buf_k = self.buf_from_slice(k);
        let buf_c = self.buf_zeros(num_heads * seq_len * seq_len);
        let buf_seq = self.buf_u32(seq_len as u32);
        let buf_dim = self.buf_u32(head_dim as u32);

        self.dispatch_3d(
            "batched_matmul_transb",
            &[&buf_q, &buf_k, &buf_c, &buf_seq, &buf_dim],
            seq_len,
            seq_len,
            num_heads,
        );

        Self::read_buf(&buf_c, num_heads * seq_len * seq_len)
    }

    fn batched_attn_values(
        &self,
        scores: &[f32],
        v: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Vec<f32> {
        // Single 3D dispatch: scores[h] × V[h] for all heads.
        let buf_s = self.buf_from_slice(scores);
        let buf_v = self.buf_from_slice(v);
        let buf_c = self.buf_zeros(num_heads * seq_len * head_dim);
        let buf_seq = self.buf_u32(seq_len as u32);
        let buf_dim = self.buf_u32(head_dim as u32);

        self.dispatch_3d(
            "batched_matmul_ab",
            &[&buf_s, &buf_v, &buf_c, &buf_seq, &buf_dim],
            head_dim,
            seq_len,
            num_heads,
        );

        Self::read_buf(&buf_c, num_heads * seq_len * head_dim)
    }

    fn softmax(&self, data: &mut [f32], rows: usize, cols: usize) {
        let buf = self.buf_from_slice(data);
        let buf_cols = self.buf_u32(cols as u32);
        self.dispatch_1d("softmax_rows", &[&buf, &buf_cols], rows);
        Self::read_buf_into(&buf, data);
    }

    fn layer_norm(
        &self,
        data: &mut [f32],
        gamma: &[f32],
        beta: &[f32],
        rows: usize,
        cols: usize,
        eps: f32,
    ) {
        let buf = self.buf_from_slice(data);
        let buf_gamma = self.buf_cached(gamma);
        let buf_beta = self.buf_cached(beta);
        let buf_cols = self.buf_u32(cols as u32);
        let buf_eps = self.buf_f32(eps);
        self.dispatch_1d(
            "layer_norm",
            &[&buf, &buf_gamma, &buf_beta, &buf_cols, &buf_eps],
            rows,
        );
        Self::read_buf_into(&buf, data);
    }

    fn rms_norm(&self, data: &mut [f32], weight: &[f32], rows: usize, cols: usize, eps: f32) {
        let buf = self.buf_from_slice(data);
        let buf_weight = self.buf_cached(weight);
        let buf_cols = self.buf_u32(cols as u32);
        let buf_eps = self.buf_f32(eps);
        self.dispatch_1d("rms_norm", &[&buf, &buf_weight, &buf_cols, &buf_eps], rows);
        Self::read_buf_into(&buf, data);
    }

    fn gelu(&self, data: &mut [f32]) {
        let buf = self.buf_from_slice(data);
        self.dispatch_1d("gelu_activation", &[&buf], data.len());
        Self::read_buf_into(&buf, data);
    }

    fn silu(&self, data: &mut [f32]) {
        let buf = self.buf_from_slice(data);
        self.dispatch_1d("silu_activation", &[&buf], data.len());
        Self::read_buf_into(&buf, data);
    }

    fn elementwise_mul(&self, a: &mut [f32], b: &[f32]) {
        let buf_a = self.buf_from_slice(a);
        let buf_b = self.buf_from_slice(b);
        self.dispatch_1d("elementwise_mul", &[&buf_a, &buf_b], a.len());
        Self::read_buf_into(&buf_a, a);
    }

    fn rope(
        &self,
        data: &mut [f32],
        cos_table: &[f32],
        sin_table: &[f32],
        seq_offset: usize,
        seq_len: usize,
        head_dim: usize,
        total_dim: usize,
    ) {
        let half = head_dim / 2;
        let num_pairs = total_dim / head_dim * half;

        let buf = self.buf_from_slice(data);
        let buf_cos = self.buf_cached(cos_table);
        let buf_sin = self.buf_cached(sin_table);
        let buf_offset = self.buf_u32(seq_offset as u32);
        let buf_head_dim = self.buf_u32(head_dim as u32);
        let buf_total_dim = self.buf_u32(total_dim as u32);
        let buf_half = self.buf_u32(half as u32);

        self.dispatch_2d(
            "rope_apply",
            &[
                &buf,
                &buf_cos,
                &buf_sin,
                &buf_offset,
                &buf_head_dim,
                &buf_total_dim,
                &buf_half,
            ],
            num_pairs,
            seq_len,
        );
        Self::read_buf_into(&buf, data);
    }

    fn fused_attention(
        &self,
        q: &[f32],
        k: &[f32],
        v: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
        scale: f32,
        alibi_slopes: &[f32],
        mask: &[u32],
    ) -> Vec<f32> {
        // All 4 ops in ONE command buffer — 1 commit+wait instead of 4.
        let buf_q = self.buf_from_slice(q);
        let buf_k = self.buf_from_slice(k);
        let buf_v = self.buf_from_slice(v);
        let buf_scores = self.buf_zeros(num_heads * seq_len * seq_len);
        let buf_out = self.buf_zeros(num_heads * seq_len * head_dim);
        let buf_seq = self.buf_u32(seq_len as u32);
        let buf_dim = self.buf_u32(head_dim as u32);
        let buf_scale = self.buf_f32(scale);
        let has_alibi = !alibi_slopes.is_empty();
        let buf_alibi = if has_alibi {
            self.buf_cached(alibi_slopes)
        } else {
            self.buf_from_slice(&[0.0f32])
        };
        let mask_u32: Vec<u32> = mask.to_vec();
        let buf_mask = self.buf_cached_u32(&mask_u32);
        let buf_has_alibi = self.buf_u32(has_alibi as u32);

        let cmd = self.queue.new_command_buffer();

        // Op 1: Q × K^T → scores
        {
            let p = &self.pipelines["batched_matmul_transb"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(p);
            enc.set_buffer(0, Some(&buf_q), 0);
            enc.set_buffer(1, Some(&buf_k), 0);
            enc.set_buffer(2, Some(&buf_scores), 0);
            enc.set_buffer(3, Some(&buf_seq), 0);
            enc.set_buffer(4, Some(&buf_dim), 0);
            let threads = MTLSize::new(seq_len as u64, seq_len as u64, num_heads as u64);
            let tg = MTLSize::new(16.min(seq_len) as u64, 16.min(seq_len) as u64, 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();
        }

        // Op 2: scale + ALiBi + mask (in-place on scores)
        {
            let p = &self.pipelines["scale_mask_alibi"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(p);
            enc.set_buffer(0, Some(&buf_scores), 0);
            enc.set_buffer(1, Some(&buf_alibi), 0);
            enc.set_buffer(2, Some(&buf_mask), 0);
            enc.set_buffer(3, Some(&buf_scale), 0);
            enc.set_buffer(4, Some(&buf_seq), 0);
            enc.set_buffer(5, Some(&buf_has_alibi), 0);
            let threads = MTLSize::new(seq_len as u64, seq_len as u64, num_heads as u64);
            let tg = MTLSize::new(8.min(seq_len) as u64, 8.min(seq_len) as u64, 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();
        }

        // Op 3: softmax (in-place on scores)
        {
            let p = &self.pipelines["softmax_rows"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(p);
            enc.set_buffer(0, Some(&buf_scores), 0);
            let buf_cols = self.buf_u32(seq_len as u32);
            enc.set_buffer(1, Some(&buf_cols), 0);
            let total_rows = num_heads * seq_len;
            let tw = p.thread_execution_width() as usize;
            let threads = MTLSize::new(total_rows as u64, 1, 1);
            let tg = MTLSize::new(tw.min(total_rows) as u64, 1, 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();
        }

        // Op 4: scores × V → output
        {
            let p = &self.pipelines["batched_matmul_ab"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(p);
            enc.set_buffer(0, Some(&buf_scores), 0);
            enc.set_buffer(1, Some(&buf_v), 0);
            enc.set_buffer(2, Some(&buf_out), 0);
            enc.set_buffer(3, Some(&buf_seq), 0);
            enc.set_buffer(4, Some(&buf_dim), 0);
            let threads = MTLSize::new(head_dim as u64, seq_len as u64, num_heads as u64);
            let tg = MTLSize::new(16.min(head_dim) as u64, 16.min(seq_len) as u64, 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();
        }

        // ONE commit + wait for all 4 ops
        cmd.commit();
        cmd.wait_until_completed();

        Self::read_buf(&buf_out, num_heads * seq_len * head_dim)
    }

    fn fused_attention_batched(
        &self,
        q: &[f32],
        k: &[f32],
        v: &[f32],
        num_groups: usize,
        heads_per_group: usize,
        seq_len: usize,
        head_dim: usize,
        scale: f32,
        alibi_slopes: &[f32],
        masks: &[u32],
    ) -> Vec<f32> {
        let total_heads = num_groups * heads_per_group;
        let buf_q = self.buf_from_slice(q);
        let buf_k = self.buf_from_slice(k);
        let buf_v = self.buf_from_slice(v);
        let buf_scores = self.buf_zeros(total_heads * seq_len * seq_len);
        let buf_out = self.buf_zeros(total_heads * seq_len * head_dim);
        let buf_seq = self.buf_u32(seq_len as u32);
        let buf_dim = self.buf_u32(head_dim as u32);
        let buf_scale = self.buf_f32(scale);
        let has_alibi = !alibi_slopes.is_empty();
        let buf_alibi = if has_alibi {
            self.buf_cached(alibi_slopes)
        } else {
            self.buf_from_slice(&[0.0f32])
        };
        let buf_masks = self.buf_cached_u32(masks);
        let buf_has_alibi = self.buf_u32(has_alibi as u32);
        let buf_heads_per_group = self.buf_u32(heads_per_group as u32);

        let cmd = self.queue.new_command_buffer();

        {
            let p = &self.pipelines["batched_matmul_transb"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(p);
            enc.set_buffer(0, Some(&buf_q), 0);
            enc.set_buffer(1, Some(&buf_k), 0);
            enc.set_buffer(2, Some(&buf_scores), 0);
            enc.set_buffer(3, Some(&buf_seq), 0);
            enc.set_buffer(4, Some(&buf_dim), 0);
            let threads = MTLSize::new(seq_len as u64, seq_len as u64, total_heads as u64);
            let tg = MTLSize::new(16.min(seq_len) as u64, 16.min(seq_len) as u64, 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();
        }

        {
            let p = &self.pipelines["scale_mask_alibi_grouped"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(p);
            enc.set_buffer(0, Some(&buf_scores), 0);
            enc.set_buffer(1, Some(&buf_alibi), 0);
            enc.set_buffer(2, Some(&buf_masks), 0);
            enc.set_buffer(3, Some(&buf_scale), 0);
            enc.set_buffer(4, Some(&buf_seq), 0);
            enc.set_buffer(5, Some(&buf_has_alibi), 0);
            enc.set_buffer(6, Some(&buf_heads_per_group), 0);
            let threads = MTLSize::new(seq_len as u64, seq_len as u64, total_heads as u64);
            let tg = MTLSize::new(8.min(seq_len) as u64, 8.min(seq_len) as u64, 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();
        }

        {
            let p = &self.pipelines["softmax_rows"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(p);
            enc.set_buffer(0, Some(&buf_scores), 0);
            let buf_cols = self.buf_u32(seq_len as u32);
            enc.set_buffer(1, Some(&buf_cols), 0);
            let total_rows = total_heads * seq_len;
            let tw = p.thread_execution_width() as usize;
            let threads = MTLSize::new(total_rows as u64, 1, 1);
            let tg = MTLSize::new(tw.min(total_rows) as u64, 1, 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();
        }

        {
            let p = &self.pipelines["batched_matmul_ab"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(p);
            enc.set_buffer(0, Some(&buf_scores), 0);
            enc.set_buffer(1, Some(&buf_v), 0);
            enc.set_buffer(2, Some(&buf_out), 0);
            enc.set_buffer(3, Some(&buf_seq), 0);
            enc.set_buffer(4, Some(&buf_dim), 0);
            let threads = MTLSize::new(head_dim as u64, seq_len as u64, total_heads as u64);
            let tg = MTLSize::new(16.min(head_dim) as u64, 16.min(seq_len) as u64, 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();
        }

        cmd.commit();
        cmd.wait_until_completed();

        Self::read_buf(&buf_out, total_heads * seq_len * head_dim)
    }

    fn backend(&self) -> GpuBackend {
        GpuBackend::Metal
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }
}

// ---------------------------------------------------------------------------
// Device discovery
// ---------------------------------------------------------------------------

pub fn discover_devices() -> Vec<GpuDeviceInfo> {
    let mut devices = Vec::new();
    if let Some(device) = Device::system_default() {
        let name = device.name().to_string();
        // Apple Silicon has unified memory — report recommended working set
        let memory = device.recommended_max_working_set_size();
        devices.push(GpuDeviceInfo {
            backend: GpuBackend::Metal,
            name,
            memory_bytes: memory,
            unified_memory: true,
        });
    }
    devices
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn get_metal() -> Option<MetalCompute> {
        MetalCompute::try_new()
    }

    #[test]
    fn test_metal_discovery() {
        let devices = discover_devices();
        // On macOS, should find at least one Metal device
        if cfg!(target_os = "macos") {
            assert!(!devices.is_empty(), "No Metal devices found on macOS");
            println!("Metal device: {}", devices[0]);
        }
    }

    #[test]
    fn test_metal_matmul() {
        let Some(metal) = get_metal() else { return };
        let a = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let b = vec![7.0, 8.0, 9.0, 10.0, 11.0, 12.0];
        let c = metal.matmul(&a, &b, 2, 2, 3);
        assert!((c[0] - 50.0).abs() < 1e-3, "got {}", c[0]);
        assert!((c[1] - 68.0).abs() < 1e-3, "got {}", c[1]);
        assert!((c[2] - 122.0).abs() < 1e-3, "got {}", c[2]);
        assert!((c[3] - 167.0).abs() < 1e-3, "got {}", c[3]);
    }

    #[test]
    fn test_metal_softmax() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![1.0, 2.0, 3.0];
        metal.softmax(&mut data, 1, 3);
        let sum: f32 = data.iter().sum();
        assert!((sum - 1.0).abs() < 1e-4, "sum={}", sum);
    }

    #[test]
    fn test_metal_gelu() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![0.0, 1.0, -1.0];
        metal.gelu(&mut data);
        assert!(data[0].abs() < 1e-5);
        assert!((data[1] - 0.8413).abs() < 0.01);
    }

    #[test]
    fn test_metal_layer_norm() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![1.0, 2.0, 3.0, 4.0];
        let gamma = vec![1.0; 4];
        let beta = vec![0.0; 4];
        metal.layer_norm(&mut data, &gamma, &beta, 1, 4, 1e-5);
        let mean: f32 = data.iter().sum::<f32>() / 4.0;
        assert!(mean.abs() < 1e-3, "mean={}", mean);
    }

    #[test]
    fn test_metal_silu() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![0.0, 1.0];
        metal.silu(&mut data);
        assert!(data[0].abs() < 1e-5);
        assert!((data[1] - 0.7311).abs() < 0.01);
    }

    #[test]
    fn test_metal_matches_cpu() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        // Test matmul consistency with larger matrix
        let m = 32;
        let n = 64;
        let k = 128;
        let a: Vec<f32> = (0..m * k).map(|i| (i as f32) * 0.01).collect();
        let b: Vec<f32> = (0..n * k).map(|i| (i as f32) * 0.01).collect();

        let c_metal = metal.matmul(&a, &b, m, n, k);
        let c_cpu = cpu.matmul(&a, &b, m, n, k);

        // Check relative error — accumulation order differs between GPU and CPU,
        // so absolute diff grows with magnitude. Relative error should be < 1e-4.
        let max_rel_err: f32 = c_metal
            .iter()
            .zip(c_cpu.iter())
            .map(|(a, b)| {
                let denom = a.abs().max(b.abs()).max(1e-6);
                (a - b).abs() / denom
            })
            .fold(0.0f32, f32::max);

        assert!(
            max_rel_err < 1e-4,
            "Metal vs CPU matmul max relative error: {} (should be < 1e-4)",
            max_rel_err
        );
    }

    #[test]
    fn test_metal_batched_matmul_matches_cpu() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        let num_heads = 4;
        let seq_len = 16;
        let head_dim = 32;
        let total = num_heads * seq_len * head_dim;
        let q: Vec<f32> = (0..total)
            .map(|i| ((i % 97) as f32 - 48.0) * 0.01)
            .collect();
        let k: Vec<f32> = (0..total)
            .map(|i| ((i % 83) as f32 - 41.0) * 0.01)
            .collect();

        let scores_metal = metal.batched_matmul(&q, &k, num_heads, seq_len, head_dim);
        let scores_cpu = cpu.batched_matmul(&q, &k, num_heads, seq_len, head_dim);

        assert_eq!(scores_metal.len(), num_heads * seq_len * seq_len);
        let max_err: f32 = scores_metal
            .iter()
            .zip(scores_cpu.iter())
            .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(max_err < 1e-3, "batched_matmul max err: {}", max_err);
    }

    #[test]
    fn test_metal_batched_attn_values_matches_cpu() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        let num_heads = 4;
        let seq_len = 16;
        let head_dim = 32;

        // Scores: [num_heads, seq_len, seq_len] — make them look like softmax output
        let mut scores: Vec<f32> = (0..num_heads * seq_len * seq_len)
            .map(|i| ((i % 67) as f32) * 0.01)
            .collect();
        // Normalize each row so it sums to ~1
        for h in 0..num_heads {
            for i in 0..seq_len {
                let base = h * seq_len * seq_len + i * seq_len;
                let sum: f32 = scores[base..base + seq_len].iter().sum();
                if sum > 0.0 {
                    for j in 0..seq_len {
                        scores[base + j] /= sum;
                    }
                }
            }
        }

        let v: Vec<f32> = (0..num_heads * seq_len * head_dim)
            .map(|i| ((i % 71) as f32 - 35.0) * 0.01)
            .collect();

        let out_metal = metal.batched_attn_values(&scores, &v, num_heads, seq_len, head_dim);
        let out_cpu = cpu.batched_attn_values(&scores, &v, num_heads, seq_len, head_dim);

        assert_eq!(out_metal.len(), num_heads * seq_len * head_dim);
        let max_err: f32 = out_metal
            .iter()
            .zip(out_cpu.iter())
            .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(max_err < 5e-3, "batched_attn_values max err: {}", max_err);
    }

    #[test]
    fn test_metal_fused_attention_batched_matches_cpu() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        let num_groups = 3;
        let heads_per_group = 2;
        let seq_len = 7;
        let head_dim = 16;
        let total_heads = num_groups * heads_per_group;

        let q: Vec<f32> = (0..total_heads * seq_len * head_dim)
            .map(|i| ((i % 89) as f32 - 44.0) * 0.01)
            .collect();
        let k: Vec<f32> = (0..total_heads * seq_len * head_dim)
            .map(|i| ((i % 73) as f32 - 36.0) * 0.01)
            .collect();
        let v: Vec<f32> = (0..total_heads * seq_len * head_dim)
            .map(|i| ((i % 61) as f32 - 30.0) * 0.01)
            .collect();

        let masks = vec![
            1, 1, 1, 1, 1, 0, 0, // group 0
            1, 1, 1, 1, 1, 1, 1, // group 1
            1, 1, 1, 0, 0, 0, 0, // group 2
        ];
        let alibi = vec![0.0, 0.0625];
        let scale = 1.0 / (head_dim as f32).sqrt();

        let out_metal = metal.fused_attention_batched(
            &q,
            &k,
            &v,
            num_groups,
            heads_per_group,
            seq_len,
            head_dim,
            scale,
            &alibi,
            &masks,
        );
        let out_cpu = cpu.fused_attention_batched(
            &q,
            &k,
            &v,
            num_groups,
            heads_per_group,
            seq_len,
            head_dim,
            scale,
            &alibi,
            &masks,
        );

        assert_eq!(out_metal.len(), total_heads * seq_len * head_dim);
        let max_err: f32 = out_metal
            .iter()
            .zip(out_cpu.iter())
            .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(
            max_err < 5e-3,
            "fused_attention_batched max err: {}",
            max_err
        );
    }

    #[test]
    fn test_metal_matmul_many_matches_individual_calls() {
        let Some(metal) = get_metal() else { return };

        let m = 16;
        let n = 24;
        let k = 32;
        let a: Vec<f32> = (0..m * k).map(|i| (i as f32) * 0.01).collect();
        let b0: Vec<f32> = (0..n * k)
            .map(|i| ((i % 29) as f32 - 14.0) * 0.01)
            .collect();
        let b1: Vec<f32> = (0..n * k)
            .map(|i| ((i % 31) as f32 - 15.0) * 0.01)
            .collect();
        let b2: Vec<f32> = (0..n * k)
            .map(|i| ((i % 37) as f32 - 18.0) * 0.01)
            .collect();

        let many = metal.matmul_many(&a, &[&b0, &b1, &b2], m, &[n, n, n], k);
        let single = vec![
            metal.matmul(&a, &b0, m, n, k),
            metal.matmul(&a, &b1, m, n, k),
            metal.matmul(&a, &b2, m, n, k),
        ];

        assert_eq!(many.len(), single.len());
        for (many_mat, single_mat) in many.iter().zip(single.iter()) {
            let max_err: f32 = many_mat
                .iter()
                .zip(single_mat.iter())
                .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
                .fold(0.0f32, f32::max);
            assert!(max_err < 1e-4, "matmul_many max err: {}", max_err);
        }
    }
}

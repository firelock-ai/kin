// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Metal GPU compute backend for macOS (Apple Silicon).
//!
//! Custom MSL compute shaders for transformer operations.
//! No candle, no ONNX, no MPS — direct Metal API via objc2-metal.

#![cfg(feature = "metal")]

use crate::gpu::{GpuBackend, GpuCompute, GpuDeviceInfo};
use metal::{
    Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device, MTLResourceOptions,
    MTLSize,
};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// MSL shader source — all transformer ops in one library
// ---------------------------------------------------------------------------

const SHADER_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

// ---- Matrix multiply: C = A × B^T ----
// A is [M, K], B is [N, K] (row-major), C is [M, N]
// Simple per-element kernel — robust for all sizes.
kernel void matmul_transb(
    device const float* A       [[buffer(0)]],
    device const float* B       [[buffer(1)]],
    device float* C             [[buffer(2)]],
    constant uint& M            [[buffer(3)]],
    constant uint& N            [[buffer(4)]],
    constant uint& K            [[buffer(5)]],
    uint2 gid                   [[thread_position_in_grid]]
) {
    uint row = gid.y;
    uint col = gid.x;

    if (row >= M || col >= N) return;

    float sum = 0.0;
    for (uint i = 0; i < K; i++) {
        sum += A[row * K + i] * B[col * K + i];
    }
    C[row * N + col] = sum;
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
kernel void batched_matmul_transb(
    device const float* A       [[buffer(0)]],
    device const float* B       [[buffer(1)]],
    device float* C             [[buffer(2)]],
    constant uint& seq_len      [[buffer(3)]],
    constant uint& head_dim     [[buffer(4)]],
    uint3 gid                   [[thread_position_in_grid]]
) {
    uint col  = gid.x;  // j in [0, seq_len)
    uint row  = gid.y;  // i in [0, seq_len)
    uint head = gid.z;  // h in [0, num_heads)

    if (row >= seq_len || col >= seq_len) return;

    uint a_off = head * seq_len * head_dim + row * head_dim;
    uint b_off = head * seq_len * head_dim + col * head_dim;
    uint c_off = head * seq_len * seq_len  + row * seq_len + col;

    float sum = 0.0;
    for (uint d = 0; d < head_dim; d++) {
        sum += A[a_off + d] * B[b_off + d];
    }
    C[c_off] = sum;
}

// ---- Batched matmul (non-transposed): C[h] = A[h] × B[h] ----
// For scores × V: A is [num_heads, seq_len, seq_len], B is [num_heads, seq_len, head_dim]
// C is [num_heads, seq_len, head_dim]
// 3D grid: (head_dim, seq_len, num_heads)
kernel void batched_matmul_ab(
    device const float* A       [[buffer(0)]],
    device const float* B       [[buffer(1)]],
    device float* C             [[buffer(2)]],
    constant uint& seq_len      [[buffer(3)]],
    constant uint& head_dim     [[buffer(4)]],
    uint3 gid                   [[thread_position_in_grid]]
) {
    uint col  = gid.x;  // j in [0, head_dim)
    uint row  = gid.y;  // i in [0, seq_len)
    uint head = gid.z;  // h in [0, num_heads)

    if (row >= seq_len || col >= head_dim) return;

    uint a_off = head * seq_len * seq_len  + row * seq_len;
    uint b_off = head * seq_len * head_dim;
    uint c_off = head * seq_len * head_dim + row * head_dim + col;

    float sum = 0.0;
    for (uint k = 0; k < seq_len; k++) {
        sum += A[a_off + k] * B[b_off + k * head_dim + col];
    }
    C[c_off] = sum;
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
}

impl MetalCompute {
    /// Try to create a Metal compute context. Returns None if Metal is unavailable.
    pub fn try_new() -> Option<Self> {
        let device = Device::system_default()?;
        let queue = device.new_command_queue();
        let device_name = device.name().to_string();

        let opts = CompileOptions::new();
        let library = device.new_library_with_source(SHADER_SOURCE, &opts).ok()?;

        let kernel_names: &[&str] = &[
            "matmul_transb",
            "batched_matmul_transb",
            "batched_matmul_ab",
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
            let func = library.get_function(name, None).ok()?;
            let pipeline = device
                .new_compute_pipeline_state_with_function(&func)
                .ok()?;
            pipelines.insert(name, pipeline);
        }

        Some(Self {
            device,
            queue,
            pipelines,
            device_name,
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
    fn dispatch_2d(
        &self,
        pipeline_name: &str,
        buffers: &[&Buffer],
        width: usize,
        height: usize,
    ) {
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
        let buf_b = self.buf_from_slice(b);
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
        let buf_gamma = self.buf_from_slice(gamma);
        let buf_beta = self.buf_from_slice(beta);
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
        let buf_weight = self.buf_from_slice(weight);
        let buf_cols = self.buf_u32(cols as u32);
        let buf_eps = self.buf_f32(eps);
        self.dispatch_1d(
            "rms_norm",
            &[&buf, &buf_weight, &buf_cols, &buf_eps],
            rows,
        );
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
        let buf_cos = self.buf_from_slice(cos_table);
        let buf_sin = self.buf_from_slice(sin_table);
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
        let q: Vec<f32> = (0..total).map(|i| ((i % 97) as f32 - 48.0) * 0.01).collect();
        let k: Vec<f32> = (0..total).map(|i| ((i % 83) as f32 - 41.0) * 0.01).collect();

        let scores_metal = metal.batched_matmul(&q, &k, num_heads, seq_len, head_dim);
        let scores_cpu = cpu.batched_matmul(&q, &k, num_heads, seq_len, head_dim);

        assert_eq!(scores_metal.len(), num_heads * seq_len * seq_len);
        let max_err: f32 = scores_metal.iter().zip(scores_cpu.iter())
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
        let max_err: f32 = out_metal.iter().zip(out_cpu.iter())
            .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(max_err < 5e-3, "batched_attn_values max err: {}", max_err);
    }
}

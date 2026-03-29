// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! GPU compute abstraction — custom Metal, CUDA, and CPU backends.
//!
//! No external ML frameworks. Direct platform API calls behind feature flags.
//! Device discovery is automatic; callers get the best available backend.

use std::fmt;

use rayon::prelude::*;

// ---------------------------------------------------------------------------
// Device discovery and selection
// ---------------------------------------------------------------------------

/// Available GPU compute backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuBackend {
    /// Apple Metal (macOS/iOS) — M1/M2/M3 GPU families.
    Metal,
    /// NVIDIA CUDA via driver API.
    Cuda,
    /// CPU fallback (SIMD-accelerated).
    Cpu,
}

impl fmt::Display for GpuBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metal => write!(f, "Metal"),
            Self::Cuda => write!(f, "CUDA"),
            Self::Cpu => write!(f, "CPU"),
        }
    }
}

/// Information about a discovered GPU device.
#[derive(Debug, Clone)]
pub struct GpuDeviceInfo {
    pub backend: GpuBackend,
    pub name: String,
    /// Total device memory in bytes (0 for unified memory architectures).
    pub memory_bytes: u64,
    /// Whether this device shares memory with the CPU (Apple Silicon).
    pub unified_memory: bool,
}

impl fmt::Display for GpuDeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mem_mb = self.memory_bytes / (1024 * 1024);
        write!(f, "{} ({}, {}MB", self.name, self.backend, mem_mb)?;
        if self.unified_memory {
            write!(f, ", unified")?;
        }
        write!(f, ")")
    }
}

/// Discover all available GPU devices on the system.
///
/// Returns devices sorted by preference: Metal > CUDA > CPU.
/// Always includes at least one CPU device as fallback.
pub fn discover_devices() -> Vec<GpuDeviceInfo> {
    let mut devices = Vec::new();

    #[cfg(feature = "metal")]
    {
        devices.extend(discover_metal_devices());
    }

    #[cfg(feature = "cuda")]
    {
        devices.extend(discover_cuda_devices());
    }

    // CPU fallback is always available
    devices.push(GpuDeviceInfo {
        backend: GpuBackend::Cpu,
        name: cpu_name(),
        memory_bytes: 0,
        unified_memory: false,
    });

    devices
}

/// Select the best available device for compute.
pub fn best_device() -> GpuDeviceInfo {
    discover_devices()
        .into_iter()
        .next()
        .expect("at least CPU should be available")
}

fn cpu_name() -> String {
    #[cfg(target_arch = "aarch64")]
    {
        "ARM64 (NEON)".to_string()
    }
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64 (AVX2+FMA)".to_string()
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        "CPU (scalar)".to_string()
    }
}

// ---------------------------------------------------------------------------
// Metal device discovery (macOS)
// ---------------------------------------------------------------------------

#[cfg(feature = "metal")]
fn discover_metal_devices() -> Vec<GpuDeviceInfo> {
    use crate::metal_backend;
    metal_backend::discover_devices()
}

// ---------------------------------------------------------------------------
// CUDA device discovery (Linux/Windows)
// ---------------------------------------------------------------------------

#[cfg(feature = "cuda")]
fn discover_cuda_devices() -> Vec<GpuDeviceInfo> {
    use crate::cuda_backend;
    cuda_backend::discover_devices()
}

// ---------------------------------------------------------------------------
// Compute operations trait
// ---------------------------------------------------------------------------

/// GPU-accelerated tensor operations for transformer inference.
///
/// Each method mirrors a CPU operation in lib.rs. Implementations
/// own their device buffers and handle host↔device transfers.
pub trait GpuCompute: Send + Sync {
    /// Matrix multiply: C = A × B^T. A is [M, K], B is [N, K], result is [M, N].
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, n: usize, k: usize) -> Vec<f32>;

    /// Batched matmul for multi-head attention: scores = Q × K^T per head.
    fn batched_matmul(
        &self,
        q: &[f32],
        k: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Vec<f32>;

    /// Batched scores × V (non-transposed): output = scores × V per head.
    /// scores is [num_heads, seq_len, seq_len], V is [num_heads, seq_len, head_dim].
    /// Returns [num_heads, seq_len, head_dim].
    fn batched_attn_values(
        &self,
        scores: &[f32],
        v: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Vec<f32>;

    /// Softmax over rows: each row of [M, N] independently normalized.
    fn softmax(&self, data: &mut [f32], rows: usize, cols: usize);

    /// LayerNorm: (x - mean) / sqrt(var + eps) * gamma + beta.
    fn layer_norm(
        &self,
        data: &mut [f32],
        gamma: &[f32],
        beta: &[f32],
        rows: usize,
        cols: usize,
        eps: f32,
    );

    /// RMSNorm: x * rsqrt(mean(x^2) + eps) * weight.
    fn rms_norm(&self, data: &mut [f32], weight: &[f32], rows: usize, cols: usize, eps: f32);

    /// GELU activation in-place.
    fn gelu(&self, data: &mut [f32]);

    /// SiLU activation in-place.
    fn silu(&self, data: &mut [f32]);

    /// Element-wise multiply: out[i] = a[i] * b[i].
    fn elementwise_mul(&self, a: &mut [f32], b: &[f32]);

    /// RoPE: apply rotary position encoding in-place.
    fn rope(
        &self,
        data: &mut [f32],
        cos_table: &[f32],
        sin_table: &[f32],
        seq_offset: usize,
        seq_len: usize,
        head_dim: usize,
        total_dim: usize,
    );

    /// Fused attention: Q×K^T → scale+ALiBi+mask → softmax → scores×V
    /// in a single GPU submission. Returns [num_heads, seq_len, head_dim].
    /// `alibi_slopes`: per-head slopes, or empty slice for no ALiBi.
    /// `mask`: per-position mask (1=keep, 0=mask), length seq_len.
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
        // Default: fall back to separate operations
        let mut scores = self.batched_matmul(q, k, num_heads, seq_len, head_dim);
        let has_alibi = !alibi_slopes.is_empty();
        for hd in 0..num_heads {
            let base = hd * seq_len * seq_len;
            let slope = if has_alibi { alibi_slopes[hd] } else { 0.0 };
            for i in 0..seq_len {
                for j in 0..seq_len {
                    let idx = base + i * seq_len + j;
                    scores[idx] *= scale;
                    if has_alibi {
                        scores[idx] += slope * i.abs_diff(j) as f32;
                    }
                    if mask[j] == 0 {
                        scores[idx] = f32::NEG_INFINITY;
                    }
                }
            }
        }
        self.softmax(&mut scores, num_heads * seq_len, seq_len);
        self.batched_attn_values(&scores, v, num_heads, seq_len, head_dim)
    }

    /// Which backend this compute instance uses.
    fn backend(&self) -> GpuBackend;

    /// Device name for logging.
    fn device_name(&self) -> &str;
}

/// Create the best available compute backend.
pub fn create_compute() -> Box<dyn GpuCompute> {
    #[cfg(feature = "metal")]
    {
        if let Some(compute) = crate::metal_backend::MetalCompute::try_new() {
            return Box::new(compute);
        }
    }

    #[cfg(feature = "cuda")]
    {
        if let Some(compute) = crate::cuda_backend::CudaCompute::try_new() {
            return Box::new(compute);
        }
    }

    Box::new(CpuCompute)
}

fn should_parallelize(work_items: usize) -> bool {
    rayon::current_num_threads() > 1 && work_items >= 8_192
}

// ---------------------------------------------------------------------------
// CPU compute backend (always available)
// ---------------------------------------------------------------------------

/// CPU compute using SIMD-accelerated operations from the main engine.
pub struct CpuCompute;

impl GpuCompute for CpuCompute {
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, n: usize, k: usize) -> Vec<f32> {
        // A is [M, K] row-major, B is [N, K] row-major (we compute A × B^T)
        let mut c = vec![0.0f32; m * n];
        if should_parallelize(m * n * k) {
            c.par_chunks_mut(n).enumerate().for_each(|(i, row)| {
                let a_row = &a[i * k..(i + 1) * k];
                for (j, slot) in row.iter_mut().enumerate() {
                    let b_row = &b[j * k..(j + 1) * k];
                    *slot = crate::dot_product(a_row, b_row);
                }
            });
        } else {
            for i in 0..m {
                let a_row = &a[i * k..(i + 1) * k];
                for j in 0..n {
                    let b_row = &b[j * k..(j + 1) * k];
                    c[i * n + j] = crate::dot_product(a_row, b_row);
                }
            }
        }
        c
    }

    fn batched_matmul(
        &self,
        q: &[f32],
        k: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Vec<f32> {
        // Q, K are [num_heads, seq_len, head_dim] flattened
        // Output is [num_heads, seq_len, seq_len]
        let mut scores = vec![0.0f32; num_heads * seq_len * seq_len];
        let head_stride = seq_len * head_dim;
        let out_stride = seq_len * seq_len;

        if should_parallelize(num_heads * seq_len * seq_len * head_dim) {
            scores
                .par_chunks_mut(out_stride)
                .enumerate()
                .for_each(|(h, head_scores)| {
                    let q_head = &q[h * head_stride..(h + 1) * head_stride];
                    let k_head = &k[h * head_stride..(h + 1) * head_stride];
                    for i in 0..seq_len {
                        let q_row = &q_head[i * head_dim..(i + 1) * head_dim];
                        let row = &mut head_scores[i * seq_len..(i + 1) * seq_len];
                        for (j, slot) in row.iter_mut().enumerate() {
                            let k_row = &k_head[j * head_dim..(j + 1) * head_dim];
                            *slot = crate::dot_product(q_row, k_row);
                        }
                    }
                });
        } else {
            for h in 0..num_heads {
                let q_head = &q[h * head_stride..(h + 1) * head_stride];
                let k_head = &k[h * head_stride..(h + 1) * head_stride];
                for i in 0..seq_len {
                    let q_row = &q_head[i * head_dim..(i + 1) * head_dim];
                    for j in 0..seq_len {
                        let k_row = &k_head[j * head_dim..(j + 1) * head_dim];
                        scores[h * out_stride + i * seq_len + j] = crate::dot_product(q_row, k_row);
                    }
                }
            }
        }
        scores
    }

    fn batched_attn_values(
        &self,
        scores: &[f32],
        v: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Vec<f32> {
        // scores is [num_heads, seq_len, seq_len], V is [num_heads, seq_len, head_dim]
        // output is [num_heads, seq_len, head_dim]
        let s_stride = seq_len * seq_len;
        let v_stride = seq_len * head_dim;
        let mut result = vec![0.0f32; num_heads * v_stride];

        if should_parallelize(num_heads * seq_len * seq_len * head_dim) {
            result
                .par_chunks_mut(v_stride)
                .enumerate()
                .for_each(|(h, head_out)| {
                    for i in 0..seq_len {
                        let row = &mut head_out[i * head_dim..(i + 1) * head_dim];
                        for (j, slot) in row.iter_mut().enumerate() {
                            let mut sum = 0.0f32;
                            for k_idx in 0..seq_len {
                                sum += scores[h * s_stride + i * seq_len + k_idx]
                                    * v[h * v_stride + k_idx * head_dim + j];
                            }
                            *slot = sum;
                        }
                    }
                });
        } else {
            for h in 0..num_heads {
                for i in 0..seq_len {
                    for j in 0..head_dim {
                        let mut sum = 0.0f32;
                        for k_idx in 0..seq_len {
                            sum += scores[h * s_stride + i * seq_len + k_idx]
                                * v[h * v_stride + k_idx * head_dim + j];
                        }
                        result[h * v_stride + i * head_dim + j] = sum;
                    }
                }
            }
        }
        result
    }

    fn softmax(&self, data: &mut [f32], rows: usize, cols: usize) {
        if should_parallelize(rows * cols) {
            data.par_chunks_mut(cols).for_each(|row| {
                let max = row.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
                let mut sum = 0.0f32;
                for v in row.iter_mut() {
                    *v = (*v - max).exp();
                    sum += *v;
                }
                if sum > 0.0 {
                    for v in row.iter_mut() {
                        *v /= sum;
                    }
                }
            });
        } else {
            for r in 0..rows {
                let row = &mut data[r * cols..(r + 1) * cols];
                let max = row.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
                let mut sum = 0.0f32;
                for v in row.iter_mut() {
                    *v = (*v - max).exp();
                    sum += *v;
                }
                if sum > 0.0 {
                    for v in row.iter_mut() {
                        *v /= sum;
                    }
                }
            }
        }
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
        if should_parallelize(rows * cols) {
            data.par_chunks_mut(cols).for_each(|row| {
                let len = cols as f32;
                let mean: f32 = row.iter().sum::<f32>() / len;
                let var: f32 = row.iter().map(|&v| (v - mean) * (v - mean)).sum::<f32>() / len;
                let inv_std = 1.0 / (var + eps).sqrt();
                for (i, v) in row.iter_mut().enumerate() {
                    *v = (*v - mean) * inv_std * gamma[i] + beta[i];
                }
            });
        } else {
            for r in 0..rows {
                let row = &mut data[r * cols..(r + 1) * cols];
                let len = cols as f32;
                let mean: f32 = row.iter().sum::<f32>() / len;
                let var: f32 = row.iter().map(|&v| (v - mean) * (v - mean)).sum::<f32>() / len;
                let inv_std = 1.0 / (var + eps).sqrt();
                for (i, v) in row.iter_mut().enumerate() {
                    *v = (*v - mean) * inv_std * gamma[i] + beta[i];
                }
            }
        }
    }

    fn rms_norm(&self, data: &mut [f32], weight: &[f32], rows: usize, cols: usize, eps: f32) {
        if should_parallelize(rows * cols) {
            data.par_chunks_mut(cols).for_each(|row| {
                let len = cols as f32;
                let rms = (row.iter().map(|&v| v * v).sum::<f32>() / len + eps).sqrt();
                let inv_rms = 1.0 / rms;
                for (i, v) in row.iter_mut().enumerate() {
                    *v = *v * inv_rms * weight[i];
                }
            });
        } else {
            for r in 0..rows {
                let row = &mut data[r * cols..(r + 1) * cols];
                let len = cols as f32;
                let rms = (row.iter().map(|&v| v * v).sum::<f32>() / len + eps).sqrt();
                let inv_rms = 1.0 / rms;
                for (i, v) in row.iter_mut().enumerate() {
                    *v = *v * inv_rms * weight[i];
                }
            }
        }
    }

    fn gelu(&self, data: &mut [f32]) {
        if should_parallelize(data.len()) {
            data.par_iter_mut().for_each(|v| {
                *v = *v * 0.5 * (1.0 + (*v * 0.7978845608 * (1.0 + 0.044715 * *v * *v)).tanh());
            });
        } else {
            for v in data.iter_mut() {
                *v = *v * 0.5 * (1.0 + (*v * 0.7978845608 * (1.0 + 0.044715 * *v * *v)).tanh());
            }
        }
    }

    fn silu(&self, data: &mut [f32]) {
        if should_parallelize(data.len()) {
            data.par_iter_mut().for_each(|v| {
                *v = *v / (1.0 + (-*v).exp());
            });
        } else {
            for v in data.iter_mut() {
                *v = *v / (1.0 + (-*v).exp());
            }
        }
    }

    fn elementwise_mul(&self, a: &mut [f32], b: &[f32]) {
        if should_parallelize(a.len()) {
            a.par_iter_mut()
                .zip(b.par_iter())
                .for_each(|(x, y)| *x *= *y);
        } else {
            for (x, y) in a.iter_mut().zip(b.iter()) {
                *x *= y;
            }
        }
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
        if should_parallelize(seq_len * total_dim) {
            data.par_chunks_mut(total_dim)
                .take(seq_len)
                .enumerate()
                .for_each(|(pos, row)| {
                    let cos_row_off = (seq_offset + pos) * half;
                    let sin_row_off = (seq_offset + pos) * half;
                    let mut offset = 0;
                    while offset + head_dim <= total_dim {
                        for d in 0..half {
                            let cos_val = cos_table[cos_row_off + d];
                            let sin_val = sin_table[sin_row_off + d];
                            let x0 = row[offset + d];
                            let x1 = row[offset + half + d];
                            row[offset + d] = x0 * cos_val - x1 * sin_val;
                            row[offset + half + d] = x1 * cos_val + x0 * sin_val;
                        }
                        offset += head_dim;
                    }
                });
        } else {
            for pos in 0..seq_len {
                let cos_row_off = (seq_offset + pos) * half;
                let sin_row_off = (seq_offset + pos) * half;
                let row_off = pos * total_dim;
                // Apply to each head in the row
                let mut offset = 0;
                while offset + head_dim <= total_dim {
                    for d in 0..half {
                        let cos_val = cos_table[cos_row_off + d];
                        let sin_val = sin_table[sin_row_off + d];
                        let x0 = data[row_off + offset + d];
                        let x1 = data[row_off + offset + half + d];
                        data[row_off + offset + d] = x0 * cos_val - x1 * sin_val;
                        data[row_off + offset + half + d] = x1 * cos_val + x0 * sin_val;
                    }
                    offset += head_dim;
                }
            }
        }
    }

    fn backend(&self) -> GpuBackend {
        GpuBackend::Cpu
    }

    fn device_name(&self) -> &str {
        "CPU"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_devices_always_has_cpu() {
        let devices = discover_devices();
        assert!(!devices.is_empty());
        assert!(devices.iter().any(|d| d.backend == GpuBackend::Cpu));
    }

    #[test]
    fn test_best_device_returns_something() {
        let dev = best_device();
        // On macOS with Metal feature, should prefer Metal; otherwise CPU
        println!("Best device: {}", dev);
    }

    #[test]
    fn test_cpu_matmul() {
        let cpu = CpuCompute;
        // [2,3] × [2,3]^T = [2,2]
        let a = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let b = vec![7.0, 8.0, 9.0, 10.0, 11.0, 12.0];
        let c = cpu.matmul(&a, &b, 2, 2, 3);
        // Row 0: [1,2,3]·[7,8,9]=50, [1,2,3]·[10,11,12]=68
        assert!((c[0] - 50.0).abs() < 1e-4);
        assert!((c[1] - 68.0).abs() < 1e-4);
        // Row 1: [4,5,6]·[7,8,9]=122, [4,5,6]·[10,11,12]=167
        assert!((c[2] - 122.0).abs() < 1e-4);
        assert!((c[3] - 167.0).abs() < 1e-4);
    }

    #[test]
    fn test_cpu_softmax() {
        let cpu = CpuCompute;
        let mut data = vec![1.0, 2.0, 3.0];
        cpu.softmax(&mut data, 1, 3);
        let sum: f32 = data.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5);
        assert!(data[0] < data[1]);
        assert!(data[1] < data[2]);
    }

    #[test]
    fn test_cpu_layer_norm() {
        let cpu = CpuCompute;
        let mut data = vec![1.0, 2.0, 3.0, 4.0];
        let gamma = vec![1.0; 4];
        let beta = vec![0.0; 4];
        cpu.layer_norm(&mut data, &gamma, &beta, 1, 4, 1e-5);
        let mean: f32 = data.iter().sum::<f32>() / 4.0;
        assert!(mean.abs() < 1e-4);
    }

    #[test]
    fn test_cpu_rms_norm() {
        let cpu = CpuCompute;
        let mut data = vec![1.0, 2.0, 3.0, 4.0];
        let weight = vec![1.0; 4];
        cpu.rms_norm(&mut data, &weight, 1, 4, 1e-6);
        let rms = (30.0f32 / 4.0).sqrt();
        assert!((data[0] - 1.0 / rms).abs() < 1e-4);
    }

    #[test]
    fn test_cpu_gelu() {
        let cpu = CpuCompute;
        let mut data = vec![0.0, 1.0];
        cpu.gelu(&mut data);
        assert!(data[0].abs() < 1e-6);
        assert!((data[1] - 0.8413).abs() < 0.01);
    }

    #[test]
    fn test_cpu_silu() {
        let cpu = CpuCompute;
        let mut data = vec![0.0, 1.0];
        cpu.silu(&mut data);
        assert!(data[0].abs() < 1e-6);
        assert!((data[1] - 0.7311).abs() < 0.01);
    }

    #[test]
    fn test_create_compute_returns_backend() {
        let compute = create_compute();
        println!(
            "Compute backend: {} on {}",
            compute.backend(),
            compute.device_name()
        );
    }
}

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

/// References to all tensor slices for a single transformer layer.
#[derive(Default, Clone)]
pub struct LayerTensors<'a> {
    pub norm1_weight: &'a [f32],
    pub norm1_bias: Option<&'a [f32]>,
    
    // QKV Projection
    pub qkv_weight: Option<&'a [f32]>,
    pub qkv_bias: Option<&'a [f32]>,
    pub q_weight: Option<&'a [f32]>,
    pub q_bias: Option<&'a [f32]>,
    pub k_weight: Option<&'a [f32]>,
    pub k_bias: Option<&'a [f32]>,
    pub v_weight: Option<&'a [f32]>,
    pub v_bias: Option<&'a [f32]>,
    pub q_ln_weight: Option<&'a [f32]>,
    pub q_ln_bias: Option<&'a [f32]>,
    pub k_ln_weight: Option<&'a [f32]>,
    pub k_ln_bias: Option<&'a [f32]>,

    // Attention Output Projection
    pub attn_out_weight: &'a [f32],
    pub attn_out_bias: Option<&'a [f32]>,
    
    pub norm2_weight: &'a [f32],
    pub norm2_bias: Option<&'a [f32]>,
    
    // FFN
    pub ffn_gate_weight: Option<&'a [f32]>,
    pub ffn_up_weight: Option<&'a [f32]>,
    pub ffn_up_bias: Option<&'a [f32]>,
    pub ffn_down_weight: &'a [f32],
    pub ffn_down_bias: Option<&'a [f32]>,
    pub ffn_up_gated_weight: Option<&'a [f32]>,

    // Advanced Position Embeddings
    pub relative_attention_bias: Option<&'a [f32]>,
    pub rel_pos_embeddings: Option<&'a [f32]>,
}

/// Scalar parameters and dimensions for a single transformer layer.
#[derive(Clone)]
pub struct LayerConfig<'a> {
    pub batch_size: usize,
    pub max_len: usize,
    pub hidden_size: usize,
    pub num_heads: usize,
    pub head_dim: usize,
    pub inter_size: usize,
    
    pub eps: f32,
    pub rms_eps: f32,
    pub use_rms: bool,
    pub pre_ln: bool,
    pub scale: f32,
    
    pub alibi_slopes: Option<&'a [f32]>,
}

/// GPU-accelerated tensor operations for transformer inference.
///
/// Each method mirrors a CPU operation in lib.rs. Implementations
/// own their device buffers and handle host↔device transfers.
pub trait GpuCompute: Send + Sync {
    /// Matrix multiply: C = A × B^T. A is [M, K], B is [N, K], result is [M, N].
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, n: usize, k: usize) -> Vec<f32>;

    /// Matrix multiply against multiple weight matrices sharing the same input A.
    ///
    /// Each weight in `weights` is `[n_i, k]` row-major. Returns one `[m, n_i]`
    /// output vector per weight in the same order.
    fn matmul_many(
        &self,
        a: &[f32],
        weights: &[&[f32]],
        m: usize,
        ns: &[usize],
        k: usize,
    ) -> Vec<Vec<f32>> {
        weights
            .iter()
            .zip(ns.iter().copied())
            .map(|(weight, n)| self.matmul(a, weight, m, n, k))
            .collect()
    }

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

    /// Fused SwiGLU feed-forward block in a single GPU submission:
    ///
    /// ```text
    /// gate = x @ w_gate^T          // [rows, inter]
    /// up   = x @ w_up^T            // [rows, inter]
    /// act  = silu(gate) * up       // [rows, inter]
    /// out  = act @ w_down^T        // [rows, hidden]
    /// ```
    ///
    /// `x` is `[rows, hidden]` row-major; `w_gate`/`w_up` are `[inter, hidden]`,
    /// `w_down` is `[hidden, inter]` (all row-major, matmul-`B^T` convention).
    /// Returns the `[rows, hidden]` down-projection.
    ///
    /// The default implementation chains the existing primitives and is the
    /// numerical reference; accelerator backends override this to keep the whole
    /// chain resident on-device with a single host synchronization.
    fn fused_ffn_swiglu(
        &self,
        x: &[f32],
        w_gate: &[f32],
        w_up: &[f32],
        w_down: &[f32],
        rows: usize,
        hidden: usize,
        inter: usize,
    ) -> Vec<f32> {
        let mut gate = self.matmul(x, w_gate, rows, inter, hidden);
        let up = self.matmul(x, w_up, rows, inter, hidden);
        self.silu(&mut gate);
        self.elementwise_mul(&mut gate, &up);
        self.matmul(&gate, w_down, rows, hidden, inter)
    }

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

    /// Apply RoPE to two tensors (typically Q and K) sharing the same cos/sin
    /// tables, in a single GPU submission. Q and K are independent, so a backend
    /// can encode both rotations into one command buffer and synchronize once.
    /// The default applies them sequentially via `rope`.
    #[allow(clippy::too_many_arguments)]
    fn rope_pair(
        &self,
        q: &mut [f32],
        k: &mut [f32],
        cos_table: &[f32],
        sin_table: &[f32],
        seq_offset: usize,
        seq_len: usize,
        head_dim: usize,
        total_dim: usize,
    ) {
        self.rope(q, cos_table, sin_table, seq_offset, seq_len, head_dim, total_dim);
        self.rope(k, cos_table, sin_table, seq_offset, seq_len, head_dim, total_dim);
    }

    /// Apply RoPE to Q and K for a WHOLE BATCH in one submission. `q`/`k` are
    /// `[batch_size * max_len, total_dim]`; positions restart at 0 for every input
    /// (so the per-row position is `row % max_len`), and only positions `< actual`
    /// are rotated (matching the table-bounded per-element path). `cos_table`/
    /// `sin_table` are the compact `[actual, head_dim/2]` tables. The default
    /// applies the batch per-element via `rope_pair` (one submission per input).
    #[allow(clippy::too_many_arguments)]
    fn rope_pair_batched(
        &self,
        q: &mut [f32],
        k: &mut [f32],
        cos_table: &[f32],
        sin_table: &[f32],
        batch_size: usize,
        max_len: usize,
        actual: usize,
        head_dim: usize,
        total_dim: usize,
    ) {
        for b in 0..batch_size {
            let base = b * max_len * total_dim;
            let rows = actual * total_dim;
            let (q_block, k_block) = (
                &mut q[base..base + rows],
                &mut k[base..base + rows],
            );
            self.rope_pair(
                q_block, k_block, cos_table, sin_table, 0, actual, head_dim, total_dim,
            );
        }
    }

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

    /// Batched fused attention for grouped masks.
    ///
    /// `q`, `k`, and `v` are laid out as `[num_groups * heads_per_group, seq_len, head_dim]`
    /// in head-major order. `masks` is `[num_groups, seq_len]`, flattened row-major.
    /// `alibi_slopes` is per-head within a group, or empty for no ALiBi.
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
        let mut scores = self.batched_matmul(q, k, total_heads, seq_len, head_dim);
        let has_alibi = !alibi_slopes.is_empty();

        for group in 0..num_groups {
            let mask = &masks[group * seq_len..(group + 1) * seq_len];
            for head in 0..heads_per_group {
                let head_idx = group * heads_per_group + head;
                let base = head_idx * seq_len * seq_len;
                let slope = if has_alibi { alibi_slopes[head] } else { 0.0 };
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
        }

        self.softmax(&mut scores, total_heads * seq_len, seq_len);
        self.batched_attn_values(&scores, v, total_heads, seq_len, head_dim)
    }

    /// Position-major fused attention ("Lever A").
    ///
    /// Consumes `q`/`k`/`v` in the forward-pass position-major layout
    /// `[num_groups*seq_len, heads_per_group*head_dim]` (i.e. `[batch*seq,
    /// hidden]`) and returns the attention output in the *same* position-major
    /// layout. A GPU backend that overrides this can do the head-major reshape
    /// on-device so the per-layer scatter never round-trips to host memory.
    ///
    /// The default implementation reproduces the host scatter exactly: reshape
    /// to head-major, run [`fused_attention_batched`], reshape back. It is the
    /// byte-for-byte reference and the path CPU/non-Metal backends take.
    #[allow(clippy::too_many_arguments)]
    fn fused_attention_batched_posmajor(
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
        let total_dim = heads_per_group * head_dim;
        let elems = total_heads * seq_len * head_dim;

        // Position-major [group*seq, total_dim] -> head-major
        // [(group*heads), seq, head_dim].
        let mut qf = vec![0.0f32; elems];
        let mut kf = vec![0.0f32; elems];
        let mut vf = vec![0.0f32; elems];
        for b in 0..num_groups {
            for s in 0..seq_len {
                for hd in 0..heads_per_group {
                    let src = (b * seq_len + s) * total_dim + hd * head_dim;
                    let dst = (b * heads_per_group + hd) * seq_len * head_dim + s * head_dim;
                    qf[dst..dst + head_dim].copy_from_slice(&q[src..src + head_dim]);
                    kf[dst..dst + head_dim].copy_from_slice(&k[src..src + head_dim]);
                    vf[dst..dst + head_dim].copy_from_slice(&v[src..src + head_dim]);
                }
            }
        }

        let out_head = self.fused_attention_batched(
            &qf,
            &kf,
            &vf,
            num_groups,
            heads_per_group,
            seq_len,
            head_dim,
            scale,
            alibi_slopes,
            masks,
        );

        // Head-major [(group*heads), seq, head_dim] -> position-major
        // [group*seq, total_dim].
        let mut out = vec![0.0f32; elems];
        for b in 0..num_groups {
            for s in 0..seq_len {
                for hd in 0..heads_per_group {
                    let src = (b * heads_per_group + hd) * seq_len * head_dim + s * head_dim;
                    let dst = (b * seq_len + s) * total_dim + hd * head_dim;
                    out[dst..dst + head_dim].copy_from_slice(&out_head[src..src + head_dim]);
                }
            }
        }
        out
    }

    /// Fused SwiGLU feed-forward + residual + LayerNorm in a single GPU
    /// submission — the post-LN FFN block:
    ///
    /// ```text
    /// down = fused_ffn_swiglu(x, w_gate, w_up, w_down)   // [rows, hidden]
    /// sum  = residual + down                              // residual add
    /// out  = layer_norm(sum, gamma, beta, eps)
    /// ```
    ///
    /// Same shapes as `fused_ffn_swiglu`, plus `residual`/`gamma`/`beta` of
    /// `[rows, hidden]` / `[hidden]`. Folds the residual add and norm2 into the
    /// FFN's own command buffer so the down-projection never round-trips to host
    /// memory un-normed. The default chains the primitives and is the reference.
    #[allow(clippy::too_many_arguments)]
    fn fused_ffn_swiglu_add_norm(
        &self,
        x: &[f32],
        w_gate: &[f32],
        w_up: &[f32],
        w_down: &[f32],
        residual: &[f32],
        gamma: &[f32],
        beta: &[f32],
        rows: usize,
        hidden: usize,
        inter: usize,
        eps: f32,
    ) -> Vec<f32> {
        let mut sum = self.fused_ffn_swiglu(x, w_gate, w_up, w_down, rows, hidden, inter);
        for (s, r) in sum.iter_mut().zip(residual.iter()) {
            *s += *r;
        }
        self.layer_norm(&mut sum, gamma, beta, rows, hidden, eps);
        sum
    }

    /// Fused projection + residual + LayerNorm in a single GPU submission:
    ///
    /// ```text
    /// proj = x @ weight^T              // [rows, hidden]
    /// sum  = residual + proj           // [rows, hidden]  (residual add)
    /// out  = layer_norm(sum, gamma, beta, eps)
    /// ```
    ///
    /// `x` is `[rows, cols]` row-major; `weight` is `[hidden, cols]` (matmul-`B^T`
    /// convention); `residual`, `gamma`, `beta`, and the output are `[rows, hidden]`
    /// / `[hidden]`. This is the post-attention output-projection block of a
    /// post-LN transformer (and the structurally identical post-FFN block), folded
    /// so the projection result and the residual sum stay RESIDENT on-device — the
    /// intermediate never round-trips through host memory between the matmul and
    /// the norm.
    ///
    /// The default chains the existing primitives and is the numerical reference;
    /// accelerator backends override it to keep the chain resident with a single
    /// host synchronization.
    #[allow(clippy::too_many_arguments)]
    fn fused_linear_add_norm(
        &self,
        x: &[f32],
        weight: &[f32],
        residual: &[f32],
        gamma: &[f32],
        beta: &[f32],
        rows: usize,
        cols: usize,
        hidden: usize,
        eps: f32,
    ) -> Vec<f32> {
        let mut sum = self.matmul(x, weight, rows, hidden, cols);
        for (s, r) in sum.iter_mut().zip(residual.iter()) {
            *s += *r;
        }
        self.layer_norm(&mut sum, gamma, beta, rows, hidden, eps);
        sum
    }

    /// Evaluates an entire Transformer layer in a single GPU submission, keeping
    /// intermediate activations resident on-device.
    ///
    /// Accepts a position-major input `hidden` of shape `[batch_size * max_len, hidden_size]`.
    /// `masks` is the flattened per-batch mask `[batch_size * max_len]`.
    ///
    /// Returns `Some(Vec<f32>)` containing the position-major output if the backend 
    /// supports fusing this specific layer configuration. 
    /// Returns `None` to signal the caller to fall back to the per-operation path 
    /// (which acts as both the fallback and the CPU parity reference).
    #[allow(clippy::too_many_arguments)]
    fn forward_layer_batched(
        &self,
        _hidden: &[f32],
        _masks: &[u32],
        _weights: &LayerTensors,
        _config: &LayerConfig,
        _rope_cos: &[f32],
        _rope_sin: &[f32],
    ) -> Option<Vec<f32>> {
        None
    }

    /// Which backend this compute instance uses.
    fn backend(&self) -> GpuBackend;

    /// Device name for logging.
    fn device_name(&self) -> &str;
}

/// Create the best available compute backend.
///
/// Respects `KIN_INFER_FORCE_CPU=1` as a short-circuit escape hatch: when set,
/// skips GPU discovery and returns `CpuCompute` regardless of feature flags.
/// Callers that need to force CPU for a specific `BertModel` construction
/// (e.g. kin-db's embedding dispatcher falling back around broken Metal
/// attention at long sequences) can set this env var around the `load()`
/// call and unset it afterward.
pub fn create_compute() -> Box<dyn GpuCompute> {
    if std::env::var_os("KIN_INFER_FORCE_CPU")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false)
    {
        return Box::new(CpuCompute);
    }

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
    // Parallelize once there is enough work to amortize rayon's per-task dispatch.
    // The heavy kernels (matmul m*n*k) are millions of items and always cross this;
    // the floor only governs the cheap element-wise/norm ops. 4096 is below a
    // single short-sequence LayerNorm/softmax (so those engage the cores too) while
    // still keeping trivially small tensors single-threaded.
    rayon::current_num_threads() > 1 && work_items >= 4_096
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
            // Parallelize over (head x query-row): num_heads*seq_len work units, so
            // all cores engage even when num_heads (e.g. 12) < core count (18).
            // One output score-row [seq_len] per unit.
            scores
                .par_chunks_mut(seq_len)
                .enumerate()
                .for_each(|(unit, row)| {
                    let h = unit / seq_len;
                    let i = unit % seq_len;
                    let q_head = &q[h * head_stride..(h + 1) * head_stride];
                    let k_head = &k[h * head_stride..(h + 1) * head_stride];
                    let q_row = &q_head[i * head_dim..(i + 1) * head_dim];
                    for (j, slot) in row.iter_mut().enumerate() {
                        let k_row = &k_head[j * head_dim..(j + 1) * head_dim];
                        *slot = crate::dot_product(q_row, k_row);
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
            // Parallelize over (head x query-row): one output row [head_dim] per
            // unit, so all cores engage even when num_heads < core count.
            result
                .par_chunks_mut(head_dim)
                .enumerate()
                .for_each(|(unit, row)| {
                    let h = unit / seq_len;
                    let i = unit % seq_len;
                    for (j, slot) in row.iter_mut().enumerate() {
                        let mut sum = 0.0f32;
                        for k_idx in 0..seq_len {
                            sum += scores[h * s_stride + i * seq_len + k_idx]
                                * v[h * v_stride + k_idx * head_dim + j];
                        }
                        *slot = sum;
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
    fn test_cpu_matmul_many() {
        let cpu = CpuCompute;
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b1 = vec![1.0, 0.0, 0.0, 1.0];
        let b2 = vec![2.0, 1.0, 1.0, 2.0];

        let outs = cpu.matmul_many(&a, &[&b1, &b2], 2, &[2, 2], 2);

        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0], vec![1.0, 2.0, 3.0, 4.0]);
        assert_eq!(outs[1], vec![4.0, 5.0, 10.0, 11.0]);
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
    fn test_cpu_fused_attention_batched_uses_group_masks() {
        let cpu = CpuCompute;
        let q = vec![
            1.0, 0.0, 0.0, 1.0, // group 0, head 0
            1.0, 0.0, 0.0, 1.0, // group 1, head 0
        ];
        let k = q.clone();
        let v = q.clone();
        let masks = vec![
            1, 0, // group 0 masks out the second token
            1, 1, // group 1 keeps both tokens
        ];

        let out = cpu.fused_attention_batched(&q, &k, &v, 2, 1, 2, 2, 1.0, &[], &masks);

        assert_eq!(out.len(), 8);

        // Group 0 can only attend to the first token.
        assert!((out[0] - 1.0).abs() < 1e-5);
        assert!(out[1].abs() < 1e-5);
        assert!((out[2] - 1.0).abs() < 1e-5);
        assert!(out[3].abs() < 1e-5);

        // Group 1 keeps both tokens and should produce a non-degenerate softmax mix.
        assert!((out[4] - 0.7310586).abs() < 1e-5);
        assert!((out[5] - 0.26894143).abs() < 1e-5);
        assert!((out[6] - 0.26894143).abs() < 1e-5);
        assert!((out[7] - 0.7310586).abs() < 1e-5);
    }

    #[test]
    fn test_cpu_fused_attention_batched_posmajor_matches_head_major() {
        // The position-major entry point must be a pure relayout of the
        // head-major path: feed it the position-major view of the same tensors
        // and the (un-reshaped) output must match `fused_attention_batched`
        // bit-for-bit. Guards the reshape index math (Lever A) without a GPU.
        let cpu = CpuCompute;
        let num_groups = 3;
        let heads_per_group = 2;
        let seq_len = 5;
        let head_dim = 4;
        let total_dim = heads_per_group * head_dim;
        let total_heads = num_groups * heads_per_group;
        let elems = total_heads * seq_len * head_dim;

        // Head-major reference inputs.
        let qh: Vec<f32> = (0..elems).map(|i| ((i % 89) as f32 - 44.0) * 0.01).collect();
        let kh: Vec<f32> = (0..elems).map(|i| ((i % 73) as f32 - 36.0) * 0.01).collect();
        let vh: Vec<f32> = (0..elems).map(|i| ((i % 61) as f32 - 30.0) * 0.01).collect();
        let masks = vec![
            1, 1, 1, 1, 0, // group 0
            1, 1, 1, 1, 1, // group 1
            1, 1, 0, 0, 0, // group 2
        ];
        let alibi = vec![0.0, 0.0625]; // per-head within a group
        let scale = 1.0 / (head_dim as f32).sqrt();

        // Scatter head-major -> position-major to feed the posmajor entry point.
        let mut qp = vec![0.0f32; elems];
        let mut kp = vec![0.0f32; elems];
        let mut vp = vec![0.0f32; elems];
        for b in 0..num_groups {
            for s in 0..seq_len {
                for hd in 0..heads_per_group {
                    let src = (b * heads_per_group + hd) * seq_len * head_dim + s * head_dim;
                    let dst = (b * seq_len + s) * total_dim + hd * head_dim;
                    qp[dst..dst + head_dim].copy_from_slice(&qh[src..src + head_dim]);
                    kp[dst..dst + head_dim].copy_from_slice(&kh[src..src + head_dim]);
                    vp[dst..dst + head_dim].copy_from_slice(&vh[src..src + head_dim]);
                }
            }
        }

        let out_pos = cpu.fused_attention_batched_posmajor(
            &qp, &kp, &vp, num_groups, heads_per_group, seq_len, head_dim, scale, &alibi, &masks,
        );
        let out_head = cpu.fused_attention_batched(
            &qh, &kh, &vh, num_groups, heads_per_group, seq_len, head_dim, scale, &alibi, &masks,
        );

        assert_eq!(out_pos.len(), elems);
        // Un-reshape out_pos -> head-major and compare exactly (deterministic CPU).
        for b in 0..num_groups {
            for s in 0..seq_len {
                for hd in 0..heads_per_group {
                    let pos = (b * seq_len + s) * total_dim + hd * head_dim;
                    let head = (b * heads_per_group + hd) * seq_len * head_dim + s * head_dim;
                    assert_eq!(
                        &out_pos[pos..pos + head_dim],
                        &out_head[head..head + head_dim],
                        "posmajor mismatch at group={b} seq={s} head={hd}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_cpu_matmul_many_matches_individual_calls() {
        let cpu = CpuCompute;
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b0 = vec![1.0, 0.0, 0.0, 1.0];
        let b1 = vec![2.0, 1.0, 1.0, 2.0];

        let many = cpu.matmul_many(&a, &[&b0, &b1], 2, &[2, 2], 2);
        let single0 = cpu.matmul(&a, &b0, 2, 2, 2);
        let single1 = cpu.matmul(&a, &b1, 2, 2, 2);

        assert_eq!(many.len(), 2);
        assert_eq!(many[0], single0);
        assert_eq!(many[1], single1);
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

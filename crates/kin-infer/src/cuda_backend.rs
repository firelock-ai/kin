// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! CUDA GPU compute backend for Linux/Windows (NVIDIA GPUs).
//!
//! Uses CUDA driver API FFI — no cuDNN, no cuBLAS, no toolkit required at build time.
//! PTX kernels are embedded as strings and JIT-compiled at runtime.
//! Only requires the NVIDIA driver to be installed.

#![cfg(feature = "cuda")]

use crate::gpu::{GpuBackend, GpuCompute, GpuDeviceInfo};
use std::ffi::{c_void, CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;
use std::sync::Once;

// ---------------------------------------------------------------------------
// CUDA driver API FFI bindings (minimal set)
// ---------------------------------------------------------------------------

type CUresult = c_int;
type CUdevice = c_int;
type CUcontext = *mut c_void;
type CUmodule = *mut c_void;
type CUfunction = *mut c_void;
type CUdeviceptr = u64;
type CUstream = *mut c_void;

const CUDA_SUCCESS: CUresult = 0;

#[cfg_attr(target_os = "linux", link(name = "cuda"))]
#[cfg_attr(target_os = "windows", link(name = "nvcuda"))]
extern "C" {
    fn cuInit(flags: c_uint) -> CUresult;
    fn cuDeviceGetCount(count: *mut c_int) -> CUresult;
    fn cuDeviceGet(device: *mut CUdevice, ordinal: c_int) -> CUresult;
    fn cuDeviceGetName(name: *mut c_char, len: c_int, dev: CUdevice) -> CUresult;
    fn cuDeviceTotalMem_v2(bytes: *mut usize, dev: CUdevice) -> CUresult;
    fn cuCtxCreate_v2(ctx: *mut CUcontext, flags: c_uint, dev: CUdevice) -> CUresult;
    fn cuCtxDestroy_v2(ctx: CUcontext) -> CUresult;
    fn cuModuleLoadDataEx(
        module: *mut CUmodule,
        image: *const c_char,
        num_options: c_uint,
        options: *mut c_uint,
        option_values: *mut *mut c_void,
    ) -> CUresult;
    fn cuModuleGetFunction(
        hfunc: *mut CUfunction,
        hmod: CUmodule,
        name: *const c_char,
    ) -> CUresult;
    fn cuMemAlloc_v2(dptr: *mut CUdeviceptr, bytesize: usize) -> CUresult;
    fn cuMemFree_v2(dptr: CUdeviceptr) -> CUresult;
    fn cuMemcpyHtoD_v2(dst: CUdeviceptr, src: *const c_void, bytesize: usize) -> CUresult;
    fn cuMemcpyDtoH_v2(dst: *mut c_void, src: CUdeviceptr, bytesize: usize) -> CUresult;
    fn cuLaunchKernel(
        f: CUfunction,
        grid_x: c_uint,
        grid_y: c_uint,
        grid_z: c_uint,
        block_x: c_uint,
        block_y: c_uint,
        block_z: c_uint,
        shared_mem_bytes: c_uint,
        stream: CUstream,
        kernel_params: *mut *mut c_void,
        extra: *mut *mut c_void,
    ) -> CUresult;
    fn cuCtxSynchronize() -> CUresult;
}

// ---------------------------------------------------------------------------
// PTX kernel source — embedded as string, JIT-compiled at load time
// ---------------------------------------------------------------------------

const PTX_SOURCE: &str = r#"
.version 7.0
.target sm_60
.address_size 64

// ---- Tiled matmul: C = A × B^T ----
// A[M,K], B[N,K], C[M,N]
.visible .entry matmul_transb(
    .param .u64 A_ptr,
    .param .u64 B_ptr,
    .param .u64 C_ptr,
    .param .u32 M,
    .param .u32 N,
    .param .u32 K
) {
    .reg .u32 %r<32>;
    .reg .u64 %rd<16>;
    .reg .f32 %f<8>;
    .reg .pred %p<4>;

    // row = blockIdx.y * blockDim.y + threadIdx.y
    mov.u32 %r0, %ctaid.y;
    mov.u32 %r1, %ntid.y;
    mul.lo.u32 %r2, %r0, %r1;
    mov.u32 %r3, %tid.y;
    add.u32 %r4, %r2, %r3;  // row

    // col = blockIdx.x * blockDim.x + threadIdx.x
    mov.u32 %r5, %ctaid.x;
    mov.u32 %r6, %ntid.x;
    mul.lo.u32 %r7, %r5, %r6;
    mov.u32 %r8, %tid.x;
    add.u32 %r9, %r7, %r8;  // col

    ld.param.u32 %r10, [M];
    ld.param.u32 %r11, [N];
    ld.param.u32 %r12, [K];

    // Bounds check
    setp.ge.u32 %p0, %r4, %r10;
    setp.ge.u32 %p1, %r9, %r11;
    or.pred %p2, %p0, %p1;
    @%p2 bra DONE;

    ld.param.u64 %rd0, [A_ptr];
    ld.param.u64 %rd1, [B_ptr];
    ld.param.u64 %rd2, [C_ptr];

    // sum = 0.0
    mov.f32 %f0, 0f00000000;

    // Loop over K
    mov.u32 %r13, 0;  // k index
LOOP:
    setp.ge.u32 %p3, %r13, %r12;
    @%p3 bra STORE;

    // A[row * K + k]
    mul.lo.u32 %r14, %r4, %r12;
    add.u32 %r14, %r14, %r13;
    mul.wide.u32 %rd3, %r14, 4;
    add.u64 %rd4, %rd0, %rd3;
    ld.global.f32 %f1, [%rd4];

    // B[col * K + k]  (B is [N,K], accessing B^T)
    mul.lo.u32 %r15, %r9, %r12;
    add.u32 %r15, %r15, %r13;
    mul.wide.u32 %rd5, %r15, 4;
    add.u64 %rd6, %rd1, %rd5;
    ld.global.f32 %f2, [%rd6];

    fma.rn.f32 %f0, %f1, %f2, %f0;

    add.u32 %r13, %r13, 1;
    bra LOOP;

STORE:
    // C[row * N + col] = sum
    mul.lo.u32 %r16, %r4, %r11;
    add.u32 %r16, %r16, %r9;
    mul.wide.u32 %rd7, %r16, 4;
    add.u64 %rd8, %rd2, %rd7;
    st.global.f32 [%rd8], %f0;

DONE:
    ret;
}

// ---- Softmax rows ----
.visible .entry softmax_rows(
    .param .u64 data_ptr,
    .param .u32 cols
) {
    .reg .u32 %r<16>;
    .reg .u64 %rd<8>;
    .reg .f32 %f<8>;
    .reg .pred %p<4>;

    // row = blockIdx.x * blockDim.x + threadIdx.x
    mov.u32 %r0, %ctaid.x;
    mov.u32 %r1, %ntid.x;
    mul.lo.u32 %r2, %r0, %r1;
    mov.u32 %r3, %tid.x;
    add.u32 %r4, %r2, %r3;  // row index

    ld.param.u64 %rd0, [data_ptr];
    ld.param.u32 %r5, [cols];

    // row_offset = row * cols
    mul.lo.u32 %r6, %r4, %r5;

    // Phase 1: find max
    mov.f32 %f0, 0fFF800000;  // -inf
    mov.u32 %r7, 0;
MAX_LOOP:
    setp.ge.u32 %p0, %r7, %r5;
    @%p0 bra MAX_DONE;
    add.u32 %r8, %r6, %r7;
    mul.wide.u32 %rd1, %r8, 4;
    add.u64 %rd2, %rd0, %rd1;
    ld.global.f32 %f1, [%rd2];
    max.f32 %f0, %f0, %f1;
    add.u32 %r7, %r7, 1;
    bra MAX_LOOP;
MAX_DONE:

    // Phase 2: exp and sum
    mov.f32 %f2, 0f00000000;  // sum = 0
    mov.u32 %r7, 0;
EXP_LOOP:
    setp.ge.u32 %p1, %r7, %r5;
    @%p1 bra EXP_DONE;
    add.u32 %r8, %r6, %r7;
    mul.wide.u32 %rd1, %r8, 4;
    add.u64 %rd2, %rd0, %rd1;
    ld.global.f32 %f1, [%rd2];
    sub.f32 %f3, %f1, %f0;
    // Approximate exp using ex2 (exp2): exp(x) = exp2(x * log2(e))
    mul.f32 %f3, %f3, 0f3FB8AA3B;  // log2(e) ≈ 1.4427
    ex2.approx.f32 %f3, %f3;
    st.global.f32 [%rd2], %f3;
    add.f32 %f2, %f2, %f3;
    add.u32 %r7, %r7, 1;
    bra EXP_LOOP;
EXP_DONE:

    // Phase 3: normalize
    rcp.approx.f32 %f4, %f2;  // 1/sum
    mov.u32 %r7, 0;
NORM_LOOP:
    setp.ge.u32 %p2, %r7, %r5;
    @%p2 bra NORM_DONE;
    add.u32 %r8, %r6, %r7;
    mul.wide.u32 %rd1, %r8, 4;
    add.u64 %rd2, %rd0, %rd1;
    ld.global.f32 %f1, [%rd2];
    mul.f32 %f1, %f1, %f4;
    st.global.f32 [%rd2], %f1;
    add.u32 %r7, %r7, 1;
    bra NORM_LOOP;
NORM_DONE:
    ret;
}

// ---- GELU activation (element-wise) ----
.visible .entry gelu_activation(
    .param .u64 data_ptr,
    .param .u32 count
) {
    .reg .u32 %r<8>;
    .reg .u64 %rd<4>;
    .reg .f32 %f<8>;
    .reg .pred %p<2>;

    mov.u32 %r0, %ctaid.x;
    mov.u32 %r1, %ntid.x;
    mul.lo.u32 %r2, %r0, %r1;
    mov.u32 %r3, %tid.x;
    add.u32 %r4, %r2, %r3;

    ld.param.u32 %r5, [count];
    setp.ge.u32 %p0, %r4, %r5;
    @%p0 bra GELU_DONE;

    ld.param.u64 %rd0, [data_ptr];
    mul.wide.u32 %rd1, %r4, 4;
    add.u64 %rd2, %rd0, %rd1;
    ld.global.f32 %f0, [%rd2];

    // GELU(x) ≈ x * 0.5 * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3)))
    // Simplified: x * 0.5 * (1 + tanh(x * 0.7978845608 * (1 + 0.044715 * x * x)))
    mul.f32 %f1, %f0, %f0;           // x^2
    mul.f32 %f1, %f1, 0f3D372713;    // 0.044715 * x^2
    add.f32 %f1, %f1, 0f3F800000;    // 1 + 0.044715*x^2
    mul.f32 %f1, %f0, %f1;           // x * (1 + ...)
    mul.f32 %f1, %f1, 0f3F4C422A;    // * 0.7978845608
    // tanh approximation: tanh(x) ≈ x for small x, clamp for large
    // Using: tanh(x) = 2*sigmoid(2x) - 1 = 2/(1+exp(-2x)) - 1
    mul.f32 %f2, %f1, 0fC0000000;    // -2x
    mul.f32 %f2, %f2, 0f3FB8AA3B;    // -2x * log2(e)
    ex2.approx.f32 %f2, %f2;          // exp(-2x)
    add.f32 %f2, %f2, 0f3F800000;    // 1 + exp(-2x)
    rcp.approx.f32 %f2, %f2;          // 1/(1+exp(-2x))
    mul.f32 %f2, %f2, 0f40000000;    // 2*sigmoid(2x)
    sub.f32 %f2, %f2, 0f3F800000;    // tanh approx

    add.f32 %f3, %f2, 0f3F800000;    // 1 + tanh(...)
    mul.f32 %f3, %f3, 0f3F000000;    // * 0.5
    mul.f32 %f3, %f0, %f3;           // x * 0.5 * (1 + tanh(...))
    st.global.f32 [%rd2], %f3;
GELU_DONE:
    ret;
}

// ---- SiLU activation (element-wise) ----
.visible .entry silu_activation(
    .param .u64 data_ptr,
    .param .u32 count
) {
    .reg .u32 %r<8>;
    .reg .u64 %rd<4>;
    .reg .f32 %f<4>;
    .reg .pred %p<2>;

    mov.u32 %r0, %ctaid.x;
    mov.u32 %r1, %ntid.x;
    mul.lo.u32 %r2, %r0, %r1;
    mov.u32 %r3, %tid.x;
    add.u32 %r4, %r2, %r3;

    ld.param.u32 %r5, [count];
    setp.ge.u32 %p0, %r4, %r5;
    @%p0 bra SILU_DONE;

    ld.param.u64 %rd0, [data_ptr];
    mul.wide.u32 %rd1, %r4, 4;
    add.u64 %rd2, %rd0, %rd1;
    ld.global.f32 %f0, [%rd2];

    // SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
    neg.f32 %f1, %f0;
    mul.f32 %f1, %f1, 0f3FB8AA3B;    // -x * log2(e)
    ex2.approx.f32 %f1, %f1;          // exp(-x)
    add.f32 %f1, %f1, 0f3F800000;    // 1 + exp(-x)
    rcp.approx.f32 %f1, %f1;          // sigmoid(x)
    mul.f32 %f2, %f0, %f1;           // x * sigmoid(x)
    st.global.f32 [%rd2], %f2;
SILU_DONE:
    ret;
}

// ---- Element-wise multiply: a[i] *= b[i] ----
.visible .entry elementwise_mul(
    .param .u64 a_ptr,
    .param .u64 b_ptr,
    .param .u32 count
) {
    .reg .u32 %r<8>;
    .reg .u64 %rd<6>;
    .reg .f32 %f<4>;
    .reg .pred %p<2>;

    mov.u32 %r0, %ctaid.x;
    mov.u32 %r1, %ntid.x;
    mul.lo.u32 %r2, %r0, %r1;
    mov.u32 %r3, %tid.x;
    add.u32 %r4, %r2, %r3;

    ld.param.u32 %r5, [count];
    setp.ge.u32 %p0, %r4, %r5;
    @%p0 bra EMUL_DONE;

    ld.param.u64 %rd0, [a_ptr];
    ld.param.u64 %rd1, [b_ptr];
    mul.wide.u32 %rd2, %r4, 4;
    add.u64 %rd3, %rd0, %rd2;
    add.u64 %rd4, %rd1, %rd2;
    ld.global.f32 %f0, [%rd3];
    ld.global.f32 %f1, [%rd4];
    mul.f32 %f2, %f0, %f1;
    st.global.f32 [%rd3], %f2;
EMUL_DONE:
    ret;
}

// ---- LayerNorm ----
.visible .entry layer_norm(
    .param .u64 data_ptr,
    .param .u64 gamma_ptr,
    .param .u64 beta_ptr,
    .param .u32 cols,
    .param .f32 eps
) {
    .reg .u32 %r<16>;
    .reg .u64 %rd<12>;
    .reg .f32 %f<12>;
    .reg .pred %p<4>;

    // One thread per row
    mov.u32 %r0, %ctaid.x;
    mov.u32 %r1, %ntid.x;
    mul.lo.u32 %r2, %r0, %r1;
    mov.u32 %r3, %tid.x;
    add.u32 %r4, %r2, %r3;  // row

    ld.param.u64 %rd0, [data_ptr];
    ld.param.u64 %rd1, [gamma_ptr];
    ld.param.u64 %rd2, [beta_ptr];
    ld.param.u32 %r5, [cols];
    ld.param.f32 %f8, [eps];

    // row_offset
    mul.lo.u32 %r6, %r4, %r5;
    cvt.rn.f32.u32 %f9, %r5;  // cols as float

    // Phase 1: compute mean
    mov.f32 %f0, 0f00000000;
    mov.u32 %r7, 0;
LN_MEAN:
    setp.ge.u32 %p0, %r7, %r5;
    @%p0 bra LN_MEAN_DONE;
    add.u32 %r8, %r6, %r7;
    mul.wide.u32 %rd3, %r8, 4;
    add.u64 %rd4, %rd0, %rd3;
    ld.global.f32 %f1, [%rd4];
    add.f32 %f0, %f0, %f1;
    add.u32 %r7, %r7, 1;
    bra LN_MEAN;
LN_MEAN_DONE:
    div.approx.f32 %f0, %f0, %f9;  // mean

    // Phase 2: compute variance
    mov.f32 %f2, 0f00000000;
    mov.u32 %r7, 0;
LN_VAR:
    setp.ge.u32 %p1, %r7, %r5;
    @%p1 bra LN_VAR_DONE;
    add.u32 %r8, %r6, %r7;
    mul.wide.u32 %rd3, %r8, 4;
    add.u64 %rd4, %rd0, %rd3;
    ld.global.f32 %f1, [%rd4];
    sub.f32 %f3, %f1, %f0;
    fma.rn.f32 %f2, %f3, %f3, %f2;
    add.u32 %r7, %r7, 1;
    bra LN_VAR;
LN_VAR_DONE:
    div.approx.f32 %f2, %f2, %f9;  // variance
    add.f32 %f2, %f2, %f8;          // var + eps
    rsqrt.approx.f32 %f4, %f2;      // 1/sqrt(var+eps)

    // Phase 3: normalize
    mov.u32 %r7, 0;
LN_NORM:
    setp.ge.u32 %p2, %r7, %r5;
    @%p2 bra LN_DONE;
    add.u32 %r8, %r6, %r7;
    mul.wide.u32 %rd3, %r8, 4;
    add.u64 %rd4, %rd0, %rd3;  // data[row*cols+j]
    mul.wide.u32 %rd5, %r7, 4;
    add.u64 %rd6, %rd1, %rd5;  // gamma[j]
    add.u64 %rd7, %rd2, %rd5;  // beta[j]
    ld.global.f32 %f1, [%rd4];
    ld.global.f32 %f5, [%rd6];
    ld.global.f32 %f6, [%rd7];
    sub.f32 %f1, %f1, %f0;     // x - mean
    mul.f32 %f1, %f1, %f4;     // * inv_std
    fma.rn.f32 %f1, %f1, %f5, %f6;  // * gamma + beta
    st.global.f32 [%rd4], %f1;
    add.u32 %r7, %r7, 1;
    bra LN_NORM;
LN_DONE:
    ret;
}

// ---- RMSNorm ----
.visible .entry rms_norm(
    .param .u64 data_ptr,
    .param .u64 weight_ptr,
    .param .u32 cols,
    .param .f32 eps
) {
    .reg .u32 %r<16>;
    .reg .u64 %rd<8>;
    .reg .f32 %f<8>;
    .reg .pred %p<4>;

    mov.u32 %r0, %ctaid.x;
    mov.u32 %r1, %ntid.x;
    mul.lo.u32 %r2, %r0, %r1;
    mov.u32 %r3, %tid.x;
    add.u32 %r4, %r2, %r3;

    ld.param.u64 %rd0, [data_ptr];
    ld.param.u64 %rd1, [weight_ptr];
    ld.param.u32 %r5, [cols];
    ld.param.f32 %f5, [eps];

    mul.lo.u32 %r6, %r4, %r5;
    cvt.rn.f32.u32 %f6, %r5;

    // Compute sum of squares
    mov.f32 %f0, 0f00000000;
    mov.u32 %r7, 0;
RMS_SQ:
    setp.ge.u32 %p0, %r7, %r5;
    @%p0 bra RMS_SQ_DONE;
    add.u32 %r8, %r6, %r7;
    mul.wide.u32 %rd2, %r8, 4;
    add.u64 %rd3, %rd0, %rd2;
    ld.global.f32 %f1, [%rd3];
    fma.rn.f32 %f0, %f1, %f1, %f0;
    add.u32 %r7, %r7, 1;
    bra RMS_SQ;
RMS_SQ_DONE:
    div.approx.f32 %f0, %f0, %f6;
    add.f32 %f0, %f0, %f5;
    rsqrt.approx.f32 %f2, %f0;

    // Normalize
    mov.u32 %r7, 0;
RMS_NORM:
    setp.ge.u32 %p1, %r7, %r5;
    @%p1 bra RMS_DONE;
    add.u32 %r8, %r6, %r7;
    mul.wide.u32 %rd2, %r8, 4;
    add.u64 %rd3, %rd0, %rd2;
    mul.wide.u32 %rd4, %r7, 4;
    add.u64 %rd5, %rd1, %rd4;
    ld.global.f32 %f1, [%rd3];
    ld.global.f32 %f3, [%rd5];
    mul.f32 %f1, %f1, %f2;
    mul.f32 %f1, %f1, %f3;
    st.global.f32 [%rd3], %f1;
    add.u32 %r7, %r7, 1;
    bra RMS_NORM;
RMS_DONE:
    ret;
}
"#;

// ---------------------------------------------------------------------------
// CUDA driver wrapper
// ---------------------------------------------------------------------------

static CUDA_INIT: Once = Once::new();
static mut CUDA_AVAILABLE: bool = false;

fn ensure_cuda_init() -> bool {
    unsafe {
        CUDA_INIT.call_once(|| {
            CUDA_AVAILABLE = cuInit(0) == CUDA_SUCCESS;
        });
        CUDA_AVAILABLE
    }
}

/// Safe wrapper for CUDA device memory.
struct CudaBuffer {
    ptr: CUdeviceptr,
    bytes: usize,
}

impl CudaBuffer {
    fn alloc(bytes: usize) -> Option<Self> {
        let mut ptr: CUdeviceptr = 0;
        let res = unsafe { cuMemAlloc_v2(&mut ptr, bytes) };
        if res == CUDA_SUCCESS {
            Some(Self { ptr, bytes })
        } else {
            None
        }
    }

    fn from_slice(data: &[f32]) -> Option<Self> {
        let bytes = data.len() * std::mem::size_of::<f32>();
        let buf = Self::alloc(bytes)?;
        let res = unsafe { cuMemcpyHtoD_v2(buf.ptr, data.as_ptr() as *const c_void, bytes) };
        if res == CUDA_SUCCESS {
            Some(buf)
        } else {
            None
        }
    }

    fn to_vec(&self, count: usize) -> Vec<f32> {
        let mut result = vec![0.0f32; count];
        unsafe {
            cuMemcpyDtoH_v2(
                result.as_mut_ptr() as *mut c_void,
                self.ptr,
                count * std::mem::size_of::<f32>(),
            );
        }
        result
    }

    fn read_into(&self, dst: &mut [f32]) {
        unsafe {
            cuMemcpyDtoH_v2(
                dst.as_mut_ptr() as *mut c_void,
                self.ptr,
                dst.len() * std::mem::size_of::<f32>(),
            );
        }
    }

    fn write_from(&self, src: &[f32]) {
        unsafe {
            cuMemcpyHtoD_v2(
                self.ptr,
                src.as_ptr() as *const c_void,
                src.len() * std::mem::size_of::<f32>(),
            );
        }
    }
}

impl Drop for CudaBuffer {
    fn drop(&mut self) {
        unsafe {
            cuMemFree_v2(self.ptr);
        }
    }
}

// ---------------------------------------------------------------------------
// CUDA compute context
// ---------------------------------------------------------------------------

pub struct CudaCompute {
    _context: CUcontext,
    module: CUmodule,
    device_name: String,
}

// CUcontext and CUmodule are thread-safe via CUDA driver semantics
unsafe impl Send for CudaCompute {}
unsafe impl Sync for CudaCompute {}

impl CudaCompute {
    pub fn try_new() -> Option<Self> {
        if !ensure_cuda_init() {
            return None;
        }

        let mut count: c_int = 0;
        if unsafe { cuDeviceGetCount(&mut count) } != CUDA_SUCCESS || count == 0 {
            return None;
        }

        let mut device: CUdevice = 0;
        if unsafe { cuDeviceGet(&mut device, 0) } != CUDA_SUCCESS {
            return None;
        }

        let mut name_buf = [0u8; 256];
        if unsafe { cuDeviceGetName(name_buf.as_mut_ptr() as *mut c_char, 256, device) }
            != CUDA_SUCCESS
        {
            return None;
        }
        let device_name = unsafe { CStr::from_ptr(name_buf.as_ptr() as *const c_char) }
            .to_string_lossy()
            .to_string();

        let mut context: CUcontext = ptr::null_mut();
        if unsafe { cuCtxCreate_v2(&mut context, 0, device) } != CUDA_SUCCESS {
            return None;
        }

        // Load PTX module
        let ptx_cstr = CString::new(PTX_SOURCE).ok()?;
        let mut module: CUmodule = ptr::null_mut();
        let res = unsafe {
            cuModuleLoadDataEx(
                &mut module,
                ptx_cstr.as_ptr(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if res != CUDA_SUCCESS {
            unsafe { cuCtxDestroy_v2(context) };
            return None;
        }

        Some(Self {
            _context: context,
            module,
            device_name,
        })
    }

    fn get_function(&self, name: &str) -> Option<CUfunction> {
        let cname = CString::new(name).ok()?;
        let mut func: CUfunction = ptr::null_mut();
        let res = unsafe { cuModuleGetFunction(&mut func, self.module, cname.as_ptr()) };
        if res == CUDA_SUCCESS {
            Some(func)
        } else {
            None
        }
    }

    fn launch_1d(&self, func: CUfunction, params: &mut [*mut c_void], total: usize) {
        let block = 256usize;
        let grid = (total + block - 1) / block;
        unsafe {
            cuLaunchKernel(
                func,
                grid as c_uint,
                1,
                1,
                block as c_uint,
                1,
                1,
                0,
                ptr::null_mut(),
                params.as_mut_ptr(),
                ptr::null_mut(),
            );
            cuCtxSynchronize();
        }
    }

    fn launch_2d(
        &self,
        func: CUfunction,
        params: &mut [*mut c_void],
        width: usize,
        height: usize,
    ) {
        let block_x = 16usize;
        let block_y = 16usize;
        let grid_x = (width + block_x - 1) / block_x;
        let grid_y = (height + block_y - 1) / block_y;
        unsafe {
            cuLaunchKernel(
                func,
                grid_x as c_uint,
                grid_y as c_uint,
                1,
                block_x as c_uint,
                block_y as c_uint,
                1,
                0,
                ptr::null_mut(),
                params.as_mut_ptr(),
                ptr::null_mut(),
            );
            cuCtxSynchronize();
        }
    }
}

impl Drop for CudaCompute {
    fn drop(&mut self) {
        unsafe {
            cuCtxDestroy_v2(self._context);
        }
    }
}

impl GpuCompute for CudaCompute {
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, n: usize, k: usize) -> Vec<f32> {
        let func = self.get_function("matmul_transb").unwrap();
        let buf_a = CudaBuffer::from_slice(a).unwrap();
        let buf_b = CudaBuffer::from_slice(b).unwrap();
        let buf_c = CudaBuffer::alloc(m * n * 4).unwrap();
        let mut m_val = m as u32;
        let mut n_val = n as u32;
        let mut k_val = k as u32;

        let mut params: Vec<*mut c_void> = vec![
            &mut buf_a.ptr as *mut _ as *mut c_void,
            &mut buf_b.ptr as *mut _ as *mut c_void,
            &mut buf_c.ptr as *mut _ as *mut c_void,
            &mut m_val as *mut _ as *mut c_void,
            &mut n_val as *mut _ as *mut c_void,
            &mut k_val as *mut _ as *mut c_void,
        ];

        self.launch_2d(func, &mut params, n, m);
        buf_c.to_vec(m * n)
    }

    fn batched_matmul(
        &self,
        q: &[f32],
        k: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Vec<f32> {
        let head_stride = seq_len * head_dim;
        let out_stride = seq_len * seq_len;
        let mut result = vec![0.0f32; num_heads * out_stride];

        for h in 0..num_heads {
            let q_head = &q[h * head_stride..(h + 1) * head_stride];
            let k_head = &k[h * head_stride..(h + 1) * head_stride];
            let head_result = self.matmul(q_head, k_head, seq_len, seq_len, head_dim);
            result[h * out_stride..(h + 1) * out_stride].copy_from_slice(&head_result);
        }
        result
    }

    fn softmax(&self, data: &mut [f32], rows: usize, cols: usize) {
        let func = self.get_function("softmax_rows").unwrap();
        let buf = CudaBuffer::from_slice(data).unwrap();
        let mut cols_val = cols as u32;

        let mut params: Vec<*mut c_void> = vec![
            &mut buf.ptr as *mut _ as *mut c_void,
            &mut cols_val as *mut _ as *mut c_void,
        ];

        self.launch_1d(func, &mut params, rows);
        buf.read_into(data);
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
        let func = self.get_function("layer_norm").unwrap();
        let buf = CudaBuffer::from_slice(data).unwrap();
        let buf_gamma = CudaBuffer::from_slice(gamma).unwrap();
        let buf_beta = CudaBuffer::from_slice(beta).unwrap();
        let mut cols_val = cols as u32;
        let mut eps_val = eps;

        let mut params: Vec<*mut c_void> = vec![
            &mut buf.ptr as *mut _ as *mut c_void,
            &mut buf_gamma.ptr as *mut _ as *mut c_void,
            &mut buf_beta.ptr as *mut _ as *mut c_void,
            &mut cols_val as *mut _ as *mut c_void,
            &mut eps_val as *mut _ as *mut c_void,
        ];

        self.launch_1d(func, &mut params, rows);
        buf.read_into(data);
    }

    fn rms_norm(&self, data: &mut [f32], weight: &[f32], rows: usize, cols: usize, eps: f32) {
        let func = self.get_function("rms_norm").unwrap();
        let buf = CudaBuffer::from_slice(data).unwrap();
        let buf_weight = CudaBuffer::from_slice(weight).unwrap();
        let mut cols_val = cols as u32;
        let mut eps_val = eps;

        let mut params: Vec<*mut c_void> = vec![
            &mut buf.ptr as *mut _ as *mut c_void,
            &mut buf_weight.ptr as *mut _ as *mut c_void,
            &mut cols_val as *mut _ as *mut c_void,
            &mut eps_val as *mut _ as *mut c_void,
        ];

        self.launch_1d(func, &mut params, rows);
        buf.read_into(data);
    }

    fn gelu(&self, data: &mut [f32]) {
        let func = self.get_function("gelu_activation").unwrap();
        let buf = CudaBuffer::from_slice(data).unwrap();
        let mut count = data.len() as u32;

        let mut params: Vec<*mut c_void> = vec![
            &mut buf.ptr as *mut _ as *mut c_void,
            &mut count as *mut _ as *mut c_void,
        ];

        self.launch_1d(func, &mut params, data.len());
        buf.read_into(data);
    }

    fn silu(&self, data: &mut [f32]) {
        let func = self.get_function("silu_activation").unwrap();
        let buf = CudaBuffer::from_slice(data).unwrap();
        let mut count = data.len() as u32;

        let mut params: Vec<*mut c_void> = vec![
            &mut buf.ptr as *mut _ as *mut c_void,
            &mut count as *mut _ as *mut c_void,
        ];

        self.launch_1d(func, &mut params, data.len());
        buf.read_into(data);
    }

    fn elementwise_mul(&self, a: &mut [f32], b: &[f32]) {
        let func = self.get_function("elementwise_mul").unwrap();
        let buf_a = CudaBuffer::from_slice(a).unwrap();
        let buf_b = CudaBuffer::from_slice(b).unwrap();
        let mut count = a.len() as u32;

        let mut params: Vec<*mut c_void> = vec![
            &mut buf_a.ptr as *mut _ as *mut c_void,
            &mut buf_b.ptr as *mut _ as *mut c_void,
            &mut count as *mut _ as *mut c_void,
        ];

        self.launch_1d(func, &mut params, a.len());
        buf_a.read_into(a);
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
        // Fallback to CPU for RoPE (complex indexing, not worth a kernel for this)
        let cpu = crate::gpu::CpuCompute;
        cpu.rope(data, cos_table, sin_table, seq_offset, seq_len, head_dim, total_dim);
    }

    fn backend(&self) -> GpuBackend {
        GpuBackend::Cuda
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }
}

// ---------------------------------------------------------------------------
// Device discovery
// ---------------------------------------------------------------------------

pub fn discover_devices() -> Vec<GpuDeviceInfo> {
    if !ensure_cuda_init() {
        return Vec::new();
    }

    let mut count: c_int = 0;
    if unsafe { cuDeviceGetCount(&mut count) } != CUDA_SUCCESS {
        return Vec::new();
    }

    let mut devices = Vec::new();
    for i in 0..count {
        let mut device: CUdevice = 0;
        if unsafe { cuDeviceGet(&mut device, i) } != CUDA_SUCCESS {
            continue;
        }

        let mut name_buf = [0u8; 256];
        if unsafe { cuDeviceGetName(name_buf.as_mut_ptr() as *mut c_char, 256, device) }
            != CUDA_SUCCESS
        {
            continue;
        }
        let name = unsafe { CStr::from_ptr(name_buf.as_ptr() as *const c_char) }
            .to_string_lossy()
            .to_string();

        let mut mem: usize = 0;
        let _ = unsafe { cuDeviceTotalMem_v2(&mut mem, device) };

        devices.push(GpuDeviceInfo {
            backend: GpuBackend::Cuda,
            name,
            memory_bytes: mem as u64,
            unified_memory: false,
        });
    }

    devices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cuda_discovery() {
        if !ensure_cuda_init() {
            println!("CUDA not available, skipping");
            return;
        }
        let devices = discover_devices();
        for d in &devices {
            println!("CUDA device: {}", d);
        }
    }
}

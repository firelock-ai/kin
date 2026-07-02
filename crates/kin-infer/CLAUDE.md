> **Umbrella guidance:** the workspace-root `AGENTS.md` is the source of truth for cross-repo thesis, boundaries, and rules. This file is the repo-specific authority for `kin-infer`.

# kin-infer

Universal transformer inference engine in pure Rust. Custom GPU compute shaders, no external ML frameworks.

## Build

GPU or Metal test runs must first acquire the umbrella GPU lane with
`bin/kin-lane acquire gpu <lane> --pid <pid>` from the ecosystem root. Do not run
GPU tests in parallel with proof or benchmark work.

```bash
cargo build                          # CPU only
cargo build --features metal         # macOS: Apple Metal GPU
cargo build --features cuda          # Linux/Windows: NVIDIA CUDA GPU
cargo build --features accelerate    # macOS: Accelerate BLAS (CPU)
cargo test --features metal          # run all tests including Metal GPU (Warning: can hit stale binary bugs)
./scripts/run-tests.sh               # RECOMMENDED: runs tests with clean environment (cleans stale binaries + GPU sweep)
```

## Architecture

- `src/lib.rs` — Core engine: model loading, forward pass, SIMD primitives (~2100 lines)
- `src/gpu.rs` — GPU abstraction: `GpuCompute` trait, device discovery, CPU fallback
- `src/metal_backend.rs` — Apple Metal: custom MSL compute shaders for matmul, softmax, norms, activations
- `src/cuda_backend.rs` — NVIDIA CUDA: PTX kernels via driver API FFI (no toolkit needed at build time)

## Feature flags
- `metal` — Apple Metal GPU (macOS, M1/M2/M3). Deps: `metal`, `objc2`
- `cuda` — NVIDIA CUDA via driver API (Linux/Windows). No build-time deps, just needs NVIDIA driver
- `accelerate` — Apple Accelerate BLAS for CPU matmul
- `mkl` — Intel MKL BLAS
- `openblas` — OpenBLAS fallback

## Key types
- `BertConfig` / `ModelArchitecture` — model configuration and auto-detection
- `BertModel` — loaded model with weights
- `KvCache` — decoder-only KV cache for generation
- `SamplingParams` — temperature, top-k, top-p, repetition penalty
- `gpu::GpuCompute` — trait for GPU-accelerated tensor ops
- `gpu::GpuDeviceInfo` — discovered GPU device information
- `gpu::discover_devices()` — enumerate available GPUs
- `gpu::create_compute()` — get best available compute backend

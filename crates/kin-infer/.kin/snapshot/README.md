# kin-infer

**Universal transformer inference engine -- pure Rust, GPU-accelerated.**

kin-infer is a standalone inference engine extracted from the [Kin](https://github.com/firelock-ai/kin) ecosystem. It loads any HuggingFace safetensors model and runs both encoder and decoder-only architectures with custom GPU compute shaders (Metal on macOS, CUDA on Linux/Windows). No external ML frameworks -- custom MSL shaders and PTX kernels, direct platform API calls.

> **Alpha** -- APIs will evolve. The engine is proven: it powers Kin's embedding pipeline and has been validated against reference implementations across all supported architectures.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Rust](https://img.shields.io/badge/Rust-2021_edition-orange.svg)](https://www.rust-lang.org/)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-yellow.svg)](#status)

---

## What kin-infer Does

- **Encoder architectures:** BERT, RoBERTa, ALBERT, DeBERTa, T5 (encoder), Jina, nomic-embed, BGE, GTE
- **Decoder-only architectures:** LLaMA, Mistral, Gemma, GPT-2, Phi, Qwen2
- **Weight formats:** safetensors (single or sharded), F32/F16/BF16/Q8_0/Q4_0
- **Positional encodings:** learned, ALiBi, RoPE, relative bias (T5), disentangled (DeBERTa)
- **Attention:** MHA, GQA, MQA
- **Normalization:** LayerNorm, RMSNorm
- **FFN:** GELU, SwiGLU, GeGLU, ReGLU
- **Generation:** autoregressive decoding with KV cache, temperature, top-k, top-p, repetition penalty
- **SIMD:** ARM NEON and x86 AVX2+FMA accelerated dot products
- **GPU:** Apple Metal (M1/M2/M3), NVIDIA CUDA (via driver API, no toolkit needed)
- **GPU ops:** matmul, softmax, layer_norm, rms_norm, GELU, SiLU, RoPE -- custom shaders

---

## Quick Start

```bash
# Prerequisites: Rust stable
git clone https://github.com/firelock-ai/kin-infer.git
cd kin-infer

# CPU only
cargo build --release

# macOS with Metal GPU acceleration (M1/M2/M3)
cargo build --release --features metal

# Linux/Windows with NVIDIA CUDA GPU
cargo build --release --features cuda

# Run tests
cargo test --features metal   # macOS
cargo test --features cuda    # Linux/Windows with NVIDIA GPU
cargo test                    # CPU only
```

### As a dependency

```toml
[dependencies]
kin-infer = { git = "https://github.com/firelock-ai/kin-infer" }

# With Metal GPU (macOS)
kin-infer = { git = "https://github.com/firelock-ai/kin-infer", features = ["metal"] }

# With CUDA GPU (Linux/Windows)
kin-infer = { git = "https://github.com/firelock-ai/kin-infer", features = ["cuda"] }
```

---

## Usage

```rust
use kin_infer::{BertConfig, BertModel, SamplingParams};
use std::path::Path;

// Load config
let config: BertConfig = serde_json::from_str(
    &std::fs::read_to_string("model/config.json").unwrap()
).unwrap();

// Load model
let model = BertModel::load(Path::new("model/model.safetensors"), config).unwrap();

// Encoder: generate embeddings
let token_ids = vec![vec![101, 2023, 2003, 1037, 3231, 102]];
let attention_masks = vec![vec![1, 1, 1, 1, 1, 1]];
let embeddings = model.forward(&token_ids, &attention_masks).unwrap();

// Decoder: generate text
let prompt = vec![1, 15043, 29892]; // "<s>Hello,"
let mut params = SamplingParams::default();
let generated = model.generate(&prompt, 64, &mut params).unwrap();
```

### GPU device discovery

```rust
use kin_infer::gpu;

// Discover all available devices
for device in gpu::discover_devices() {
    println!("{}", device);  // e.g. "Apple M1 Pro (Metal, 10922MB, unified)"
}

// Auto-select best backend (Metal > CUDA > CPU)
let compute = gpu::create_compute();
println!("Using: {} on {}", compute.backend(), compute.device_name());
```

---

## Status

**Proven now:**
- Full encoder forward pass with mean pooling and L2 normalization
- Full decoder-only forward pass with KV cache
- Autoregressive generation with configurable sampling
- All major attention variants (MHA, GQA, MQA, ALiBi, RoPE, T5 relative, DeBERTa disentangled)
- SIMD-accelerated math primitives (ARM NEON, x86 AVX2+FMA)
- Apple Metal GPU compute (custom MSL shaders, tested on M1/M2/M3)
- NVIDIA CUDA GPU compute (PTX kernels, driver API — no toolkit required)
- Auto device discovery and transparent CPU fallback

**Still hardening:**
- GPU-accelerated forward pass integration (shaders work, wiring in progress)
- Batch decoding
- Streaming generation

---

## Ecosystem

| Component | Description |
|-----------|-------------|
| **[kin](https://github.com/firelock-ai/kin)** | Semantic VCS -- primary consumer |
| **[kin-db](https://github.com/firelock-ai/kin-db)** | Graph engine substrate |
| **[kin-infer](https://github.com/firelock-ai/kin-infer)** | Inference engine (this repo) |
| **[kin-vfs](https://github.com/firelock-ai/kin-vfs)** | Virtual filesystem |

---

## Contributing

Contributions welcome. Please open an issue before submitting large changes.

## License

Apache-2.0.

---

Created by [Troy Fortin](https://www.linkedin.com/in/troy-fortin-jr/) at [Firelock, LLC](https://firelock.ai).

---

*"So neither the one who plants nor the one who waters is anything, but only God, who makes things grow." -- 1 Corinthians 3:7*

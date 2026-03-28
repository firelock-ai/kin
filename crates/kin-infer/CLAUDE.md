# kin-infer

Universal transformer inference engine in pure Rust. Zero framework dependencies.

## Build
```bash
cargo build
cargo test
```

## Architecture
Single-file engine (src/lib.rs). Loads any HuggingFace safetensors model.
Supports encoder and decoder-only architectures.

## Key types
- `BertConfig` / `ModelArchitecture` — model configuration and auto-detection
- `BertModel` — loaded model with weights
- `KvCache` — decoder-only KV cache for generation
- `SamplingParams` — temperature, top-k, top-p, repetition penalty

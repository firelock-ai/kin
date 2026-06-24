# kin-infer

Universal transformer inference engine for the Kin stack.

`kin-infer` runs encoder and decoder transformer models entirely in Rust, with
GPU acceleration and no external ML framework dependency (no PyTorch, no ONNX,
no TensorFlow). Custom compute shaders and kernels drive the GPU backends.

It is the inference primitive in the open Kin local substrate. `kin-db`
consumes it to embed source entities on-device. Kin uses it to power
deterministic, citable embedding inference over local code corpora.

## Build

```bash
cargo build
cargo test
```

Feature flags of note:

| Flag | Default | Purpose |
|------|---------|---------|
| `metal` | off | Apple Metal GPU backend (M1/M2/M3) |
| `cuda` | off | CUDA GPU backend (Linux/Windows) |

With no GPU feature flag, the engine runs on CPU with SIMD acceleration.

## Supported architectures

**Encoder:** BERT, RoBERTa, ALBERT, DeBERTa, T5 (encoder), nomic-embed, GTE

**Decoder:** LLaMA, Mistral, Gemma, GPT-2, Phi, Qwen2

**Weight formats:** safetensors (single or sharded), F32/F16/BF16/Q8_0/Q4_0

**Positional:** learned, ALiBi, RoPE, relative bias (T5), disentangled (DeBERTa)

**Attention:** MHA, GQA, MQA

**Norm:** LayerNorm, RMSNorm

**FFN:** GELU, SwiGLU, GeGLU, ReGLU

## Key types

- `InferError` — typed error enum for model load, inference, and I/O failures.
- `gpu` module — GPU resource management and backend selection.
- `metal_backend` (macOS) — Apple Metal compute shaders for GPU inference.
- `cuda_backend` (Linux/Windows) — CUDA kernels for GPU inference.
- `resource` module — `ResourcePlan` for GPU/CPU resource inspection and
  scheduling.
- `watchdog` module — inference process health monitoring.

## License

Apache-2.0. Part of the open Kin local substrate.

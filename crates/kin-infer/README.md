# kin-infer

> Inference and embedding substrate.

`kin-infer` runs encoder and decoder transformer models entirely in Rust, with
GPU acceleration and no external ML framework dependency (no PyTorch, no ONNX,
no TensorFlow). Custom compute shaders and kernels drive the GPU backends.

It is the inference primitive in the open Kin local substrate. `kin-db`
consumes it to embed source entities on-device. Kin uses it to power
deterministic, citable embedding inference over local code corpora.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Part of Kin](https://img.shields.io/badge/part%20of-Kin-6E56CF.svg)](https://github.com/firelock-ai/kin)

## What is Kin?

Kin is the system of record for AI-written software — your code as a graph of
entities, relations, and intents, not a pile of files and diffs. AI agents and humans
navigate it semantically, with provenance, review, and governance built in. It coexists
with Git and projects graph truth back to a normal filesystem, so any tool works unchanged.

Start at **[firelock-ai/kin](https://github.com/firelock-ai/kin)** · **[kinlab.ai](https://kinlab.ai)**

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

[Apache-2.0](LICENSE).

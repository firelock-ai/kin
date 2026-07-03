// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// A/B reachability evidence for KIN_VECTOR_SIMD after its default-ON graduation:
// with the gate explicitly OFF, the public `cosine_distance` entry point must route
// to the scalar reduction — bit-identical to a sequential reference sum — even on
// aarch64, where the NEON kernel is now the default. A separate binary so the
// once-per-process gate (OnceLock in the lib) is sampled OFF before the first
// distance call: the mirror image of `hnsw_simd_query_path_parity.rs` (gate ON).
//
// The workload is the adversarial vector set from the in-crate delta test, where
// the NEON fold differs from the sequential scalar sum by up to ~2 ulp. So "cosine
// distance equals the sequential reference" holds only on the scalar path — if a
// regression routed an off gate back to NEON, the high-dimension cases here would
// diverge in the low bits and trip the assertion.

#![cfg(all(feature = "simd", target_arch = "aarch64"))]

use kin_vector::cosine_distance;

/// Deterministic pseudo-random vector — the same generator the in-crate parity
/// tests use, so this workload is reproducible across machines and runs.
fn vec_for(seed: u64, dim: usize) -> Vec<f32> {
    (0..dim)
        .map(|d| {
            let h = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add((d as u64).wrapping_mul(1442695040888963407))
                .wrapping_add(0x9E3779B97F4A7C15);
            ((h >> 40) as f32 / (1u64 << 24) as f32 - 0.5) * 2.0
        })
        .collect()
}

/// Sequential scalar cosine distance — the exact reduction order of the crate's
/// private `cosine_distance_scalar`, recomputed here because integration tests only
/// see the public surface. Rust performs no float reassociation, so this is
/// bit-identical to the library's scalar kernel on the same inputs. A degenerate
/// norm short-circuits to 1.0, matching the library.
fn scalar_reference(a: &[f32], b: &[f32]) -> f32 {
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    let denom = (norm_a * norm_b).sqrt();
    if denom < f32::EPSILON {
        return 1.0;
    }
    1.0 - dot / denom
}

#[test]
fn scalar_path_reachable_via_env_off() {
    // Force the scalar reduction for this whole process, before any distance call.
    std::env::set_var("KIN_VECTOR_SIMD", "off");

    let mut checked = 0usize;
    for &dim in &[1usize, 2, 3, 4, 7, 8, 31, 48, 127, 768] {
        for s in 0..8u64 {
            let a = vec_for(dim as u64 * 100 + s, dim);
            let b = vec_for(dim as u64 * 100 + s + 50, dim);
            assert_eq!(
                cosine_distance(&a, &b).to_bits(),
                scalar_reference(&a, &b).to_bits(),
                "KIN_VECTOR_SIMD=off did not route to the scalar reduction (dim {dim}, seed {s})"
            );
            checked += 1;
        }
    }

    println!(
        "[simd-scalar-reachable] KIN_VECTOR_SIMD=off: PASS — {checked} cases bit-identical to the \
         sequential scalar reduction on the public cosine_distance path"
    );
}

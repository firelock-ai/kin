// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Softmax must never emit NaN for a fully-masked row.
//
// Attention masks padded keys to -inf before softmax. A row with EVERY key
// masked has max = -inf, and the naive `exp(score - max)` then computes
// `exp(-inf - -inf) = exp(NaN) = NaN`, which the `sum > 0` normalization guard
// cannot scrub (NaN > 0 is false). Both the CPU reference and the Metal
// `softmax_rows` kernel now detect the non-finite max and emit zeros, so a
// fully-masked row contributes nothing instead of poisoning the embedding.
//
// The CPU check is device-free and runs in the default suite. The Metal-vs-CPU
// long-sequence parity check is `#[ignore]`d (needs a GPU; serialize to one
// workstream); run it with `-- --ignored` under the metal feature.

use kin_infer::gpu::{CpuCompute, GpuCompute};

#[test]
fn cpu_softmax_fully_masked_row_is_zero_not_nan() {
    let cpu = CpuCompute;

    // A single, entirely-masked row.
    let mut row = vec![f32::NEG_INFINITY; 8];
    cpu.softmax(&mut row, 1, 8).unwrap();
    assert!(
        row.iter().all(|x| *x == 0.0),
        "fully-masked softmax row must be all-zero, got {row:?}"
    );

    // Mixed batch: a masked row followed by a normal row — the masked row must be
    // zero and finite, the normal row a valid distribution summing to 1.
    let cols = 4;
    let mut data = vec![
        f32::NEG_INFINITY,
        f32::NEG_INFINITY,
        f32::NEG_INFINITY,
        f32::NEG_INFINITY,
        1.0,
        2.0,
        3.0,
        4.0,
    ];
    cpu.softmax(&mut data, 2, cols).unwrap();
    assert!(data.iter().all(|x| x.is_finite()), "no NaN: {data:?}");
    assert!(data[..cols].iter().all(|x| *x == 0.0), "masked row -> 0");
    let sum: f32 = data[cols..].iter().sum();
    assert!((sum - 1.0).abs() < 1e-5, "normal row sums to 1, got {sum}");
}

#[test]
fn cpu_softmax_masked_rows_parallel_path_is_finite() {
    // Large enough to take the rayon `par_chunks_mut` branch; every other row is
    // fully masked, so the parallel guard must also emit zeros (not NaN).
    let cpu = CpuCompute;
    let (rows, cols) = (256usize, 512usize);
    let mut data = vec![0.0f32; rows * cols];
    for r in 0..rows {
        for j in 0..cols {
            data[r * cols + j] = if r % 2 == 0 {
                f32::NEG_INFINITY
            } else {
                ((j % 13) as f32 - 6.0) * 0.1
            };
        }
    }
    cpu.softmax(&mut data, rows, cols).unwrap();
    assert!(
        data.iter().all(|x| x.is_finite()),
        "no NaN in parallel path"
    );
    for r in (0..rows).step_by(2) {
        assert!(
            data[r * cols..(r + 1) * cols].iter().all(|x| *x == 0.0),
            "masked row {r} -> 0"
        );
    }
}

#[cfg(feature = "metal")]
#[test]
#[ignore = "on-GPU Metal-vs-CPU softmax parity at long sequence + masked rows"]
fn metal_softmax_long_seq_masked_parity() {
    use kin_infer::gpu::{create_compute, GpuBackend};

    let gpu = create_compute();
    if gpu.backend() != GpuBackend::Metal {
        eprintln!("SKIP: backend is {:?}, not Metal", gpu.backend());
        return;
    }
    let cpu = CpuCompute;

    for &cols in &[512usize, 1024, 2048] {
        // Row 0 normal, row 1 fully masked — exercise both the long-sequence
        // reduction and the masked-row guard.
        let rows = 2;
        let mut base = vec![0.0f32; rows * cols];
        for j in 0..cols {
            base[j] = ((j % 13) as f32 - 6.0) * 0.1;
            base[cols + j] = f32::NEG_INFINITY;
        }
        let (mut m, mut c) = (base.clone(), base.clone());
        gpu.softmax(&mut m, rows, cols).unwrap();
        cpu.softmax(&mut c, rows, cols).unwrap();

        for (i, (a, b)) in m.iter().zip(c.iter()).enumerate() {
            assert!(a.is_finite(), "metal[{i}] not finite at cols={cols}");
            let abs = (a - b).abs();
            let rel = abs / a.abs().max(b.abs()).max(f32::MIN_POSITIVE);
            assert!(
                abs < 1e-4 || rel < 1e-3,
                "softmax parity cols={cols} idx={i} metal={a} cpu={b}"
            );
        }
    }
}

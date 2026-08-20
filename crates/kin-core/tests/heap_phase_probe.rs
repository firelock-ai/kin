// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Falsification for the per-phase live-heap probe.
//!
//! The probe exists to answer one question the peak number alone cannot: did a
//! phase HOLD memory, or did it allocate and free it? Those two have opposite
//! fixes, and reading a peak that cannot separate them is how an admission
//! change gets aimed at the wrong half. So the probe is only worth anything if
//! it demonstrably tells them apart, and that is what this asserts, on two
//! phases built to differ in exactly that way and nothing else.
//!
//! Its own binary because the counters are process-wide.

mod support;

#[global_allocator]
static ALLOC: support::Counting = support::Counting;

/// Retained by one probe phase and freed only after the assertions.
const HELD: usize = 8 * 1024 * 1024;

/// Allocated and dropped inside the other probe phase. Larger than [`HELD`] so
/// the churning phase outranks the retaining one on peak while keeping nothing,
/// which is the comparison this test exists to make.
const CHURNED: usize = 24 * 1024 * 1024;

/// Deliberately small. Peak growth is measured against the running high-water
/// mark, so a large allocation before the probe phases would raise that mark and
/// hide their growth. That is correct behaviour for attribution and a trap for a
/// fixture, so the decoy stays under both phases.
const DECOY: usize = 1024 * 1024;

#[test]
fn the_phase_probe_separates_retained_memory_from_churn() {
    support::install_phase_layer();

    // A span outside the admission prefix must not be recorded at all,
    // otherwise the probe is reporting on the whole process rather than on
    // init, and every number it produces is someone else's allocation.
    {
        let span = tracing::info_span!("elsewhere.not_an_admission_phase");
        let _entered = span.enter();
        let noise = vec![0u8; DECOY];
        std::hint::black_box(&noise);
    }
    assert!(
        support::samples()
            .iter()
            .all(|sample| sample.phase != "elsewhere.not_an_admission_phase"),
        "the probe recorded a span outside `{}`, so it is not scoped to admission",
        support::PHASE_PREFIX
    );

    // The decoy has been freed, but the high-water mark still carries it, and
    // growth is measured against that mark. Drop it back to what is live so the
    // probe phases below are measured against themselves.
    support::reset_peak();

    // A phase that keeps what it allocates.
    let retained: Vec<u8>;
    {
        let span = tracing::info_span!("kin.init.probe_retains");
        let _entered = span.enter();
        retained = vec![0u8; HELD];
        std::hint::black_box(&retained);
    }

    // A phase that allocates strictly more and keeps none of it.
    {
        let span = tracing::info_span!("kin.init.probe_churns");
        let _entered = span.enter();
        let churn = vec![0u8; CHURNED];
        std::hint::black_box(&churn);
    }

    let growth = support::peak_growth_by_phase();
    let find = |phase: &str| {
        growth
            .iter()
            .find(|(name, _, _)| *name == phase)
            .unwrap_or_else(|| panic!("probe recorded no growth for {phase}: {growth:?}"))
    };

    let (_, retains_grew, retains_kept) = *find("kin.init.probe_retains");
    let (_, churns_grew, churns_kept) = *find("kin.init.probe_churns");

    assert!(
        retains_kept >= HELD,
        "the retaining phase held {HELD} bytes and the probe reported {retains_kept} \
         retained, so it cannot see retention"
    );
    assert!(
        retains_grew >= HELD,
        "the retaining phase allocated {HELD} bytes and the probe reported {retains_grew} \
         of peak growth"
    );

    assert!(
        churns_grew >= CHURNED,
        "the churning phase allocated {CHURNED} bytes and the probe reported {churns_grew} \
         of peak growth, so it cannot see transient allocation"
    );
    assert!(
        churns_kept < HELD,
        "the churning phase freed everything it allocated, but the probe reported \
         {churns_kept} bytes retained, so it cannot tell churn from retention"
    );

    // The load-bearing comparison: the churning phase allocates three times what
    // the retaining one does and keeps nothing, so a probe that only reported
    // peak would rank them the wrong way round for anyone deciding what to fix.
    assert!(
        churns_grew > retains_grew && churns_kept < retains_kept,
        "expected the churning phase to grow more and retain less than the retaining \
         phase; got grew {churns_grew} vs {retains_grew}, retained {churns_kept} vs \
         {retains_kept}"
    );

    drop(retained);
}

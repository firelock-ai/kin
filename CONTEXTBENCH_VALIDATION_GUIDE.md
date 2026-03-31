# ContextBench Locate Improvements - Validation Guide

**Objective:** Measure F1 improvement from baseline P=0.148, R=0.606, F1=0.218 with the 5 implemented optimizations.

---

## Quick Start

### 1. Use Updated Kin Binary

The improvements are compiled into the release binary:

```bash
/Users/troyfortinjr/GitHub/kin-ecosystem/kin/target/release/kin locate <query> --offline --json
```

Or copy to your .kin/bin:

```bash
cp /Users/troyfortinjr/GitHub/kin-ecosystem/kin/target/release/kin ~/.kin/bin/kin
kin locate <query> --offline --json
```

### 2. Run ContextBench Benchmark

From the kin-bench directory:

```bash
cd /Users/troyfortinjr/GitHub/kin-ecosystem/kin-bench

# Run full 80-task benchmark (10 repos × 7 tasks)
python3 bin/bench --config configs/contextbench-latest.yaml --output results/improvement-sweep.json

# Compare against baseline
python3 bin/compare-results results/baseline.json results/improvement-sweep.json
```

**Alternative (if kin-bench-engine has compilation issues):**

Use the pre-built bench binary:

```bash
./bin/bench --config configs/contextbench-latest.yaml --output results/improvement-sweep.json
```

---

## Expected Results

### Conservative Estimate (Single Improvement Isolation)

| Improvement | Recall | Precision | F1 |
|-------------|--------|-----------|-----|
| Baseline | 0.606 | 0.148 | 0.218 |
| +Priority seeds (Opp 2) | +0.08 | -0.02 | +0.04 |
| +Multihop sampling (Opp 3) | +0.10 | -0.01 | +0.06 |
| +Signal reweighting (Opp 4) | +0.00 | +0.08 | +0.05 |
| +Test penalty (Opp 5) | +0.05 | -0.00 | +0.02 |
| +Hop decay fix (Opp 7) | +0.02 | -0.00 | +0.01 |
| **Combined (estimated)** | **+0.25** | **+0.05** | **+0.18** |
| **New baseline** | **0.856** | **0.198** | **0.318** |

*(Estimates assume ~25% signal overlap/redundancy, so combined ≠ sum)*

### Ambitious Estimate (If Signal Reweighting is Effective)

| Improvement | Impact |
|-------------|--------|
| Baseline | F1 = 0.218 |
| Combined improvements | F1 = 0.35-0.40 |
| **Target range** | F1 = 0.37-0.44 |

---

## Measuring Individual Improvements

To isolate each improvement's impact, use environment variable overrides:

### Disable Multihop Entity Limit Increase

```bash
KIN_LOCATE_MULTIHOP_ENTITY_LIMIT=16 kin locate <query> --offline --json
```

### Disable Followup (If Signal Reweighting Effect is too Strong)

```bash
KIN_LOCATE_FOLLOWUP_ENABLED=false kin locate <query> --offline --json
```

### Tune Signal Confidence Weights

The confidence weights are hardcoded in `locate.rs:222-257`. To experiment with different weights, edit the array:

```rust
let signal_confidence_weights = [
    1.0,  // traceback
    1.4,  // search (try 1.2-1.6)
    1.4,  // multihop (try 1.2-1.6)
    1.0,  // tests
    0.8,  // snippets (try 0.5-0.9)
    1.2,  // imports
    1.0,  // errors
    0.7,  // embeddings (try 0.5-0.9)
    1.0,  // cochange
    1.1,  // projection
];
```

Then rebuild:

```bash
cargo build --release -p kin-cli
```

---

## Baseline Metrics (For Reference)

**Current baseline (P=0.148, R=0.606, F1=0.218):**

From `/Users/troyfortinjr/GitHub/kin-ecosystem/kin/CONTEXTBENCH_LOCATE_PIPELINE_ANALYSIS.md`:

- 80 ContextBench tasks (10 repos × 7 task types per repo)
- False negatives (recall failures): ~240 tasks missing relevant files
- False positives (precision failures): ~850 tasks with irrelevant files
- High variance: some tasks F1=0.9, others F1=0.0

**Primary bottlenecks (by impact):**
1. Priority file filter too strict (missing 8% recall)
2. Multihop entity limit too low (missing 10% recall)
3. Equal signal weighting (precision loss 8%)
4. Test file uniform penalty (missing 5% recall)
5. Hop decay order confusion (minor clarity issue, 2% recall)

---

## Validation Checklist

- [ ] kin CLI compiled successfully: `/Users/troyfortinjr/GitHub/kin-ecosystem/kin/target/release/kin`
- [ ] Run `kin locate "test query" --offline --json` — completes without error
- [ ] ContextBench benchmark runs: `python3 bin/bench --config configs/contextbench-latest.yaml`
- [ ] Results saved: `results/improvement-sweep.json`
- [ ] Compare results: `python3 bin/compare-results baseline.json improvement-sweep.json`
- [ ] F1 improvement >= +0.05 (conservative estimate)
- [ ] Precision doesn't drop more than 5 percentage points
- [ ] Recall improves by at least 15 percentage points

---

## Troubleshooting

### Compilation errors in kin-bench-engine

If `cargo build --release` fails on kin-bench:

**Use pre-built binary instead:**

```bash
./bin/bench --config configs/contextbench-latest.yaml --output results/improvement-sweep.json
```

### Benchmark hangs or timeouts

1. Check system resources: `top -n 1`
2. Run on a single repo first to debug:
   ```bash
   ./bin/bench --config configs/contextbench-single-repo.yaml --output results/debug.json
   ```
3. Increase timeout in config if needed

### Results show no improvement

1. Verify kin binary is updated: `ls -lh ~/.kin/bin/kin`
2. Check git commit: `git log --oneline | head -1` should show `feat(kin-cli): improve contextbench-locate F1`
3. Inspect a single query to debug:
   ```bash
   kin locate "failing test" --offline --json --explain 2>&1 | head -100
   ```

---

## Next Steps After Validation

1. **If F1 >= 0.35:** Proceed to Opportunity 1 (query preprocessing)
2. **If F1 < 0.30:** Tune signal confidence weights and/or increase entity_limit to 128
3. **If precision is still low:** Implement Opportunity 6 (confidence thresholding)
4. **For semantic tasks:** Weight embeddings higher (1.0x instead of 0.7x) and test again

---

## Files Modified

- **Code:** `/Users/troyfortinjr/GitHub/kin-ecosystem/kin/crates/kin-cli/src/commands/locate.rs`
  - 77 insertions(+), 9 deletions(-)
  - Commit: `0a6e091`

- **Analysis:** `/Users/troyfortinjr/GitHub/kin-ecosystem/kin/CONTEXTBENCH_LOCATE_PIPELINE_ANALYSIS.md`
  - Detailed breakdown of all 10 opportunities

- **Implementation:** `/Users/troyfortinjr/GitHub/kin-ecosystem/kin/CONTEXTBENCH_LOCATE_IMPROVEMENTS_IMPLEMENTED.md`
  - This validation guide

#!/bin/bash
# Real, measurable Kin benchmarks
# No synthetic data — every number comes from actual measurement
set -euo pipefail

KIN="/Users/troyfortinjr/.cargo/bin/cargo run --release --bin kin --"
KIN_BIN="/Users/troyfortinjr/GitHub/kin/target/release/kin"
GITHUB="/Users/troyfortinjr/GitHub"
RESULTS="/Users/troyfortinjr/GitHub/kin/docs/benchmarks/results/measurable"
TMPDIR="/tmp/kin-bench-measurable"

mkdir -p "$RESULTS"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

# Build release binary first
echo "=== Building release binary ==="
cd /Users/troyfortinjr/GitHub/kin
/Users/troyfortinjr/.cargo/bin/cargo build --release --bin kin 2>&1 | tail -3

echo ""
echo "============================================"
echo "  BENCHMARK 1: CORPUS ANALYSIS"
echo "  (Real parsing across all ~/GitHub repos)"
echo "============================================"

$KIN_BIN bench corpus --github-dir "$GITHUB" 2>&1 | tee "$RESULTS/corpus.txt"

echo ""
echo "============================================"
echo "  BENCHMARK 2: INDEX BUILD TIME"
echo "  (Time to kin init + commit on real repos)"
echo "============================================"

for repo in kin CoachAI snapdocs callie firelock-factory agent-mesh-platform; do
  src="$GITHUB/$repo"
  if [ ! -d "$src" ]; then
    echo "SKIP $repo (not found)"
    continue
  fi

  dest="$TMPDIR/init-$repo"
  cp -R "$src" "$dest" 2>/dev/null || continue

  # Remove existing .kin if any
  rm -rf "$dest/.kin"

  # Time init
  init_start=$(python3 -c "import time; print(int(time.time()*1000))")
  $KIN_BIN init "$dest" 2>/dev/null
  init_end=$(python3 -c "import time; print(int(time.time()*1000))")
  init_ms=$((init_end - init_start))

  # Time first commit (indexing)
  commit_start=$(python3 -c "import time; print(int(time.time()*1000))")
  cd "$dest" && $KIN_BIN commit -m "baseline" 2>/dev/null
  commit_end=$(python3 -c "import time; print(int(time.time()*1000))")
  commit_ms=$((commit_end - commit_start))
  cd /Users/troyfortinjr/GitHub/kin

  # Measure .kin size
  kin_size=$(du -sh "$dest/.kin" 2>/dev/null | cut -f1)
  git_size=$(du -sh "$src/.git" 2>/dev/null | cut -f1 || echo "N/A")
  file_count=$(find "$src" -type f -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/target/*' -not -path '*/__pycache__/*' -not -path '*/dist/*' -not -path '*/build/*' 2>/dev/null | wc -l | tr -d ' ')

  echo "$repo: init=${init_ms}ms, commit=${commit_ms}ms, .kin=${kin_size}, .git=${git_size}, files=${file_count}"

  # Cleanup
  rm -rf "$dest"
done | tee "$RESULTS/build-time.txt"

echo ""
echo "============================================"
echo "  BENCHMARK 3: ENTITY QUERY SPEED"
echo "  (Time for kin search on indexed repos)"
echo "============================================"

# Use the kin repo itself since it's already initialized
cd /Users/troyfortinjr/GitHub/kin

for query in "SemanticReview" "GraphStore" "EntityKind" "parse" "KuzuGraphStore" "commit" "render" "index" "nonexistent_function_xyz"; do
  start=$(python3 -c "import time; print(int(time.time()*1000))")
  result=$($KIN_BIN search "$query" 2>/dev/null | wc -l | tr -d ' ')
  end=$(python3 -c "import time; print(int(time.time()*1000))")
  ms=$((end - start))
  echo "search '$query': ${ms}ms, ${result} results"
done | tee "$RESULTS/query-speed.txt"

echo ""
echo "============================================"
echo "  BENCHMARK 4: SEMANTIC CONTEXT vs FILE DUMP"
echo "  (Token count comparison — the AI metric)"
echo "============================================"

# For several real functions, compare:
# (a) The full file contents (what git gives an AI)
# (b) The semantic entity info (what kin gives an AI)

python3 << 'PYEOF'
import subprocess, json, os, sys

kin = "/Users/troyfortinjr/GitHub/kin/target/release/kin"
repo = "/Users/troyfortinjr/GitHub/kin"

# Approximate token count (chars / 4 is standard approximation)
def approx_tokens(text):
    return len(text) // 4

# Test queries — real functions in the kin codebase
queries = [
    "create_review",
    "compute_diff",
    "analyze_impact",
    "assess_risk",
    "classify",
    "extract",
    "discover_repos",
    "walk_files",
]

results = []
for query in queries:
    # Get semantic search results (what Kin provides to an AI)
    try:
        kin_output = subprocess.run(
            [kin, "search", query],
            capture_output=True, text=True, cwd=repo, timeout=30
        ).stdout.strip()
    except:
        kin_output = ""

    kin_tokens = approx_tokens(kin_output)
    kin_lines = len(kin_output.splitlines()) if kin_output else 0

    # Get grep results (what an AI does on git — reads matching files)
    try:
        grep_files = subprocess.run(
            ["grep", "-rl", query, "--include=*.rs", "crates/", "apps/"],
            capture_output=True, text=True, cwd=repo, timeout=30
        ).stdout.strip().splitlines()
    except:
        grep_files = []

    # Read all matching files (simulating what an AI would need to ingest)
    file_content = ""
    for f in grep_files:
        try:
            fp = os.path.join(repo, f)
            file_content += open(fp).read()
        except:
            pass

    file_tokens = approx_tokens(file_content)

    savings_pct = 0
    if file_tokens > 0:
        savings_pct = round((1 - kin_tokens / file_tokens) * 100, 1)

    result = {
        "query": query,
        "kin_tokens": kin_tokens,
        "kin_lines": kin_lines,
        "grep_files": len(grep_files),
        "file_tokens": file_tokens,
        "savings_pct": savings_pct,
    }
    results.append(result)
    print(f"  {query}: kin={kin_tokens} tokens ({kin_lines} lines), files={len(grep_files)} ({file_tokens} tokens), savings={savings_pct}%")

# Summary
total_kin = sum(r["kin_tokens"] for r in results)
total_file = sum(r["file_tokens"] for r in results)
if total_file > 0:
    overall = round((1 - total_kin / total_file) * 100, 1)
else:
    overall = 0
print(f"\n  OVERALL: kin={total_kin} tokens, files={total_file} tokens, savings={overall}%")

with open("/Users/troyfortinjr/GitHub/kin/docs/benchmarks/results/measurable/context-size.json", "w") as f:
    json.dump({"queries": results, "total_kin_tokens": total_kin, "total_file_tokens": total_file, "overall_savings_pct": overall}, f, indent=2)
PYEOF

echo ""
echo "============================================"
echo "  BENCHMARK 5: NEEDLE-IN-HAYSTACK"
echo "  (Find specific entity in large codebase)"
echo "============================================"

# Compare: kin search vs grep -r for finding a specific function
# Measure: time + precision (noise ratio)

python3 << 'PYEOF'
import subprocess, time, os

kin = "/Users/troyfortinjr/GitHub/kin/target/release/kin"
repo = "/Users/troyfortinjr/GitHub/kin"

needles = [
    ("create_review", "Find the review creation function"),
    ("collect_dependency_coverage", "Find the dep coverage collector"),
    ("shallow_dir", "Find where shallow dir is defined"),
    ("walk_files", "Find the file walker"),
    ("prepare_kin_repo", "Not in Kin codebase — should return 0"),
]

print(f"  {'Needle':<35} {'Kin ms':>6} {'Kin hits':>8} {'Grep ms':>7} {'Grep lines':>10} {'Kin precision':>14}")
print(f"  {'-'*35} {'-'*6} {'-'*8} {'-'*7} {'-'*10} {'-'*14}")

for needle, desc in needles:
    # Kin search
    t0 = time.perf_counter()
    kin_out = subprocess.run(
        [kin, "search", needle],
        capture_output=True, text=True, cwd=repo, timeout=30
    ).stdout.strip()
    kin_ms = int((time.perf_counter() - t0) * 1000)
    kin_hits = len(kin_out.splitlines()) if kin_out else 0

    # Grep (what AI does on git)
    t0 = time.perf_counter()
    grep_out = subprocess.run(
        ["grep", "-rn", needle, "--include=*.rs", "crates/", "apps/"],
        capture_output=True, text=True, cwd=repo, timeout=30
    ).stdout.strip()
    grep_ms = int((time.perf_counter() - t0) * 1000)
    grep_lines = len(grep_out.splitlines()) if grep_out else 0

    # Precision: kin returns structured entities, grep returns raw lines
    # Higher kin_hits:grep_lines ratio = less noise
    precision = "N/A"
    if grep_lines > 0 and kin_hits > 0:
        precision = f"{kin_hits}/{grep_lines}"
    elif kin_hits == 0 and grep_lines == 0:
        precision = "both empty"
    elif kin_hits == 0:
        precision = "no kin match"

    print(f"  {needle:<35} {kin_ms:>6} {kin_hits:>8} {grep_ms:>7} {grep_lines:>10} {precision:>14}")
PYEOF

echo ""
echo "============================================"
echo "  BENCHMARK 6: STORAGE OVERHEAD"
echo "  (.kin vs .git directory sizes)"
echo "============================================"

cd /Users/troyfortinjr/GitHub/kin
kin_size=$(du -sh .kin 2>/dev/null | cut -f1)
git_size=$(du -sh .git 2>/dev/null | cut -f1)
kin_bytes=$(du -s .kin 2>/dev/null | cut -f1)
git_bytes=$(du -s .git 2>/dev/null | cut -f1)

echo "  kin repo:"
echo "    .kin = $kin_size"
echo "    .git = $git_size"
if [ "$git_bytes" -gt 0 ] 2>/dev/null; then
  ratio=$(python3 -c "print(f'{$kin_bytes/$git_bytes*100:.1f}%')")
  echo "    .kin is $ratio of .git size"
fi

echo ""
echo "============================================"
echo "  ALL BENCHMARKS COMPLETE"
echo "============================================"

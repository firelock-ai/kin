#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
check="${root}/scripts/check-actions-cache-policy.sh"
fixtures="$(mktemp -d)"
trap 'rm -rf "${fixtures}"' EXIT

make_case() {
  local name="$1"
  local case_root="${fixtures}/${name}"
  local workflow_root="${case_root}/.github/workflows"
  local action_root="${case_root}/.github/actions"
  mkdir -p "${workflow_root}" "${action_root}"
  cp "${root}"/.github/workflows/*.yml "${workflow_root}/"
  cp -R "${root}/.github/actions/." "${action_root}/"
  printf '%s\n' "${workflow_root}"
}

expect_rejection() {
  local name="$1"
  local workflow_root="$2"
  local expected="$3"
  local output
  if output="$("${check}" "${workflow_root}" 2>&1)"; then
    echo "FAIL: ${name} falsifier was accepted" >&2
    exit 1
  fi
  if ! grep -Fq "${expected}" <<<"${output}"; then
    echo "FAIL: ${name} failed for the wrong reason" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  echo "OK: ${name} rejected"
}

"${check}" "${root}/.github/workflows"

case_root="$(make_case target-output)"
perl -0pi -e 's#(~/.cargo/git\n)#$1            target\n#' "${case_root}/ci.yml"
expect_rejection target-output "${case_root}" "target output is forbidden"

case_root="$(make_case dynamic-key)"
perl -0pi -e 's/cargo-sources-v1/cargo-sources-\$\{\{ github.sha \}\}/' "${case_root}/ci.yml"
expect_rejection dynamic-key "${case_root}" "cache keys must not expand"

case_root="$(make_case non-main-save)"
perl -0pi -e "s/if: github.ref == 'refs\/heads\/main' && steps.cargo-sources.outputs.cache-hit != 'true'/if: always()/" "${case_root}/cache-seed.yml"
expect_rejection non-main-save "${case_root}" "cache save must be restricted to a main cache miss"

case_root="$(make_case writer-trigger)"
perl -0pi -e 's/(on:\n)/$1  pull_request:\n    branches: [main]\n/' "${case_root}/cache-seed.yml"
expect_rejection writer-trigger "${case_root}" "cache writer workflow must trigger only on pushes to main"

case_root="$(make_case monolithic-action)"
perl -0pi -e 's#actions/cache/restore\@v4#actions/cache\@v4#' "${case_root}/ci.yml"
expect_rejection monolithic-action "${case_root}" "use actions/cache/restore@v4 or actions/cache/save@v4"

case_root="$(make_case version-drift)"
perl -0pi -e 's#actions/cache/restore\@v4#actions/cache/restore\@v3#' "${case_root}/ci.yml"
expect_rejection version-drift "${case_root}" "use actions/cache/restore@v4 or actions/cache/save@v4"

case_root="$(make_case lookup-only-restore)"
perl -0pi -e 's/(            \$\{\{ runner\.os \}\}-cargo-sources-\n)/$1          lookup-only: true\n/' "${case_root}/ci.yml"
expect_rejection lookup-only-restore "${case_root}" "cache restore inputs must be exactly"

case_root="$(make_case softened-restore-action)"
perl -0pi -e 's/(      - name: Restore cargo sources\n)/$1        continue-on-error: true\n/' "${case_root}/ci.yml"
expect_rejection softened-restore-action "${case_root}" "cache restore step shape must be exact"

case_root="$(make_case poisoned-cache-action-env)"
perl -0pi -e 's/(      - name: Restore cargo sources\n)/$1        env:\n          ACTIONS_CACHE_URL: https:\/\/invalid.example\n/' "${case_root}/ci.yml"
expect_rejection poisoned-cache-action-env "${case_root}" "cache restore step shape must be exact"

case_root="$(make_case fail-on-cache-miss)"
perl -0pi -e 's/(            \$\{\{ runner\.os \}\}-cargo-sources-\n)/$1          fail-on-cache-miss: true\n/' "${case_root}/ci.yml"
expect_rejection fail-on-cache-miss "${case_root}" "cache restore inputs must be exactly"

case_root="$(make_case third-party-cache-action)"
perl -0pi -e 's#(      - name: Check formatting\n)#      - uses: Swatinem/rust-cache\@v2\n\n$1#' "${case_root}/ci.yml"
expect_rejection third-party-cache-action "${case_root}" "unaudited step action"

case_root="$(make_case checkout-ref-drift)"
perl -0pi -e 's/(      - uses: actions\/checkout\@v6\n)/$1        with:\n          ref: main\n/' "${case_root}/ci.yml"
expect_rejection checkout-ref-drift "${case_root}" "exact audited step topology"

case_root="$(make_case setup-cache-input)"
perl -0pi -e 's#(      - name: Check formatting\n)#      - uses: actions/setup-node\@v6\n        with:\n          cache: npm\n\n$1#' "${case_root}/ci.yml"
expect_rejection setup-cache-input "${case_root}" "cache-capable action inputs are forbidden"

case_root="$(make_case conditional-restore)"
perl -0pi -e "s/(      - name: Restore cargo sources\n)/\$1        if: github.event_name == 'pull_request'\n/" "${case_root}/ci.yml"
expect_rejection conditional-restore "${case_root}" "cache restore must run on every workflow ref"

case_root="$(make_case conditional-job)"
perl -0pi -e "s/(  check:\n)/\$1    if: github.event_name == 'workflow_dispatch'\n/" "${case_root}/ci.yml"
expect_rejection conditional-job "${case_root}" "check job must run unconditionally"

case_root="$(make_case softened-check-job)"
perl -0pi -e 's/(  check:\n)/$1    continue-on-error: true\n/' "${case_root}/ci.yml"
expect_rejection softened-check-job "${case_root}" "check job must run unconditionally"

case_root="$(make_case ci-workflow-shell-default)"
perl -0pi -e 's/(jobs:\n)/defaults:\n  run:\n    shell: bash {0} || true\n\n$1/' "${case_root}/ci.yml"
expect_rejection ci-workflow-shell-default "${case_root}" "custom run defaults could mask cache policy failures"

case_root="$(make_case ci-job-shell-default)"
perl -0pi -e 's/(  check:\n)/$1    defaults:\n      run:\n        shell: bash {0} || true\n/' "${case_root}/ci.yml"
expect_rejection ci-job-shell-default "${case_root}" "check job must run unconditionally"

case_root="$(make_case check-needs-prerequisite)"
perl -0pi -e 's/(  check:\n)/$1    needs: disabled-prerequisite\n/' "${case_root}/ci.yml"
expect_rejection check-needs-prerequisite "${case_root}" "check job must run unconditionally"

case_root="$(make_case missing-policy-step)"
perl -0pi -e 's#\n      - name: Check Actions cache policy\n        run: \|\n          \./scripts/check-actions-cache-policy\.sh\n          \./scripts/test-actions-cache-policy\.sh\n##' "${case_root}/ci.yml"
expect_rejection missing-policy-step "${case_root}" "policy enforcement step must run unconditionally"

case_root="$(make_case softened-policy-step)"
perl -0pi -e 's/(      - name: Check Actions cache policy\n)/$1        continue-on-error: true\n/' "${case_root}/ci.yml"
expect_rejection softened-policy-step "${case_root}" "policy enforcement step must run unconditionally"

case_root="$(make_case wrong-job-placement)"
perl -0pi -e 's/  check:\n    name: Check & Test/  decoy-cache:\n    name: Check & Test/' "${case_root}/ci.yml"
perl -0pi -e 's/jobs:\n/jobs:\n  check:\n    runs-on: \$\{\{ matrix.os \}\}\n    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-latest]\n    steps:\n      - run: echo cold\n\n/' "${case_root}/ci.yml"
expect_rejection wrong-job-placement "${case_root}" "cache restore must be declared in ci.yml job check"

case_root="$(make_case narrowed-matrix)"
perl -0pi -e 's/os: \[ubuntu-latest, macos-latest\]/os: [ubuntu-latest]/' "${case_root}/ci.yml"
expect_rejection narrowed-matrix "${case_root}" "exact Linux/macOS matrix"

case_root="$(make_case narrowed-trigger)"
perl -0pi -e 's/  merge_group:\n//' "${case_root}/ci.yml"
expect_rejection narrowed-trigger "${case_root}" "must run exactly on pull requests to main and merge groups"

case_root="$(make_case filtered-ci-trigger)"
perl -0pi -e 's/(  pull_request:\n    branches: \[main\]\n)/$1    paths: ["src\/**"]\n/' "${case_root}/ci.yml"
expect_rejection filtered-ci-trigger "${case_root}" "must run exactly on pull requests to main and merge groups"

case_root="$(make_case filtered-writer-trigger)"
perl -0pi -e 's/(  push:\n    branches: \[main\]\n)/$1    paths-ignore: ["**"]\n/' "${case_root}/cache-seed.yml"
expect_rejection filtered-writer-trigger "${case_root}" "cache writer workflow must trigger only on pushes to main"

case_root="$(make_case seed-timeout-narrowing)"
perl -0pi -e 's/timeout-minutes: 30/timeout-minutes: 1/' "${case_root}/cache-seed.yml"
expect_rejection seed-timeout-narrowing "${case_root}" "cache writer job must run unconditionally"

case_root="$(make_case seed-fail-fast-drift)"
perl -0pi -e 's/fail-fast: false/fail-fast: true/' "${case_root}/cache-seed.yml"
expect_rejection seed-fail-fast-drift "${case_root}" "cache writer job must run unconditionally"

case_root="$(make_case late-restore)"
perl -0pi -e 's#(      - name: Restore cargo sources\n)#      - name: Cargo work before restore\n        run: cargo fetch\n\n$1#' "${case_root}/ci.yml"
expect_rejection late-restore "${case_root}" "cache restore must precede every run step"

case_root="$(make_case late-save)"
perl -0pi -e 's#\z#\n      - name: Later step\n        run: echo later\n#' "${case_root}/cache-seed.yml"
expect_rejection late-save "${case_root}" "cache save must be the last declared job step"

case_root="$(make_case softened-save-action)"
perl -0pi -e 's/(      - name: Save cargo sources on main\n)/$1        continue-on-error: true\n/' "${case_root}/cache-seed.yml"
expect_rejection softened-save-action "${case_root}" "cache save step shape must be exact"

case_root="$(make_case hidden-build-output)"
perl -0pi -e 's/(      - name: Fetch Cargo dependencies\n)/      - name: Hidden build output\n        run: cargo build --target-dir ~\/\.cargo\/git\/target\n\n$1/' "${case_root}/cache-seed.yml"
expect_rejection hidden-build-output "${case_root}" "exact audited step topology"

case_root="$(make_case softened-fetch)"
perl -0pi -e 's/(      - name: Fetch Cargo dependencies\n)/$1        continue-on-error: true\n/' "${case_root}/cache-seed.yml"
expect_rejection softened-fetch "${case_root}" "strict cargo fetch with no failure softening"

case_root="$(make_case seed-workflow-shell-default)"
perl -0pi -e 's/(jobs:\n)/defaults:\n  run:\n    shell: bash {0} || true\n\n$1/' "${case_root}/cache-seed.yml"
expect_rejection seed-workflow-shell-default "${case_root}" "custom run defaults could mask cargo fetch failures"

case_root="$(make_case cargo-home-poison)"
perl -0pi -e 's/(  RUSTFLAGS: -Dwarnings\n)/$1  CARGO_HOME: \$\{\{ github.workspace \}\}\/isolated-cargo-home\n/' "${case_root}/cache-seed.yml"
expect_rejection cargo-home-poison "${case_root}" "exact Cargo home and shell invariants"

case_root="$(make_case masked-fetch-failure)"
perl -0pi -e 's/run: cargo fetch/run: cargo fetch || true/' "${case_root}/cache-seed.yml"
expect_rejection masked-fetch-failure "${case_root}" "strict cargo fetch with no failure softening"

case_root="$(make_case wrong-save-key)"
perl -0pi -e 's/steps\.cargo-sources\.outputs\.cache-primary-key/runner.os }}-cargo-sources-wrong/' "${case_root}/cache-seed.yml"
expect_rejection wrong-save-key "${case_root}" "save key must come from the restore primary key"

case_root="$(make_case duplicate-condition-key)"
perl -0pi -e "s/(      - name: Restore cargo sources\n)/\$1        if: true\n        if: false\n/" "${case_root}/ci.yml"
expect_rejection duplicate-condition-key "${case_root}" "duplicate YAML mapping key"

case_root="$(make_case composite-cache-action)"
perl -0pi -e 's!\z!\n    - name: Hidden target cache\n      uses: Actions/cache\@v4\n      with:\n        path: target\n        key: hidden-target\n!' "${case_root}/../actions/rust-toolchain/action.yml"
expect_rejection composite-cache-action "${case_root}" "repo-local composite actions must not invoke nested actions"

case_root="$(make_case local-action-drift)"
printf '%s\n' '# cache behavior requires re-audit' >>"${case_root}/../actions/rust-toolchain/action.yml"
expect_rejection local-action-drift "${case_root}" "local action digest changed"

case_root="$(make_case local-action-cache-write)"
# shellcheck disable=SC2016 # Fixture must preserve the runner-side HOME token.
printf '%s\n' \
  '    - name: Hidden build-output writer' \
  '      shell: bash' \
  '      run: cargo build --target-dir "$HOME/.cargo/git/target"' \
  >>"${case_root}/../actions/rust-toolchain/action.yml"
expect_rejection local-action-cache-write "${case_root}" "local action digest changed"

case_root="$(make_case unexpected-workflow)"
cp "${case_root}/ci.yml" "${case_root}/shadow.yml"
expect_rejection unexpected-workflow "${case_root}" "shadow.yml: unexpected cache action"

case_root="$(make_case reusable-pin-drift)"
perl -0pi -e 's/cargo-registry-release\.yml\@v0\.1\.32/cargo-registry-release.yml\@v0.1.99/' "${case_root}/registry-publish.yml"
expect_rejection reusable-pin-drift "${case_root}" "until its external cache behavior is re-audited"

case_root="$(make_case reusable-trigger-broadening)"
perl -0pi -e 's/(  push:\n    branches: )\[main\]/$1["**"]/' "${case_root}/registry-publish.yml"
expect_rejection reusable-trigger-broadening "${case_root}" "external cache-producing reusable must keep its exact triggers"

case_root="$(make_case reusable-caller-condition)"
perl -0pi -e 's/(  release:\n)/$1    if: always()\n/' "${case_root}/registry-publish.yml"
expect_rejection reusable-caller-condition "${case_root}" "external cache-producing reusable caller shape must be exact"

case_root="$(make_case reusable-input-drift)"
perl -0pi -e 's/test-command: cargo test/test-command: cargo test || true/' "${case_root}/registry-publish.yml"
expect_rejection reusable-input-drift "${case_root}" "external cache-producing reusable caller shape must be exact"

echo "OK: all Actions cache policy falsifiers were rejected."

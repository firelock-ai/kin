#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fail closed when Kin release authority drifts back onto main pushes."""

from __future__ import annotations

import copy
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Callable
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
README = ROOT / "README.md"
RELEASE = WORKFLOWS / "release.yml"
RELEASE_RECOVERY = WORKFLOWS / "release-recovery.yml"
RELEASE_TAG = WORKFLOWS / "release-tag.yml"
RELEASE_TRAIN = WORKFLOWS / "release-train.yml"
RELEASE_SENTINEL = WORKFLOWS / "release-sentinel.yml"
SAST = WORKFLOWS / "sast.yml"
ADVISORY_SWEEP = WORKFLOWS / "advisory-sweep.yml"
ADVISORY_SWEEP_SCRIPT = ROOT / "scripts" / "advisory-sweep.mjs"
HOLD_ALARM = ROOT / "scripts" / "release-hold-alarm.mjs"
HOLD_ALARM_POLICY = "scripts/release-hold-alarm.mjs"
PROOF_GATE = ROOT / "scripts" / "check-release-proof-artifacts.mjs"
PROOF_GATE_POLICY = "scripts/check-release-proof-artifacts.mjs"
INSTALL_PROOF_CANARY = WORKFLOWS / "install-proof-canary.yml"
RUST_TOOLCHAIN_ACTION = ROOT / ".github" / "actions" / "rust-toolchain" / "action.yml"
TOOLCHAIN_PRUNE = (
    ROOT / ".github" / "actions" / "rust-toolchain" / "prune-image-toolchains.sh"
)
CAPABILITY_CONTRACT = ROOT / "scripts" / "verify-capability-proof.mjs"
CAPABILITY_CONTRACT_POLICY = "scripts/verify-capability-proof.mjs"
RELEASE_BOT_DOC = ROOT / "docs" / "release-bot.md"
INSTALL_PROOF = WORKFLOWS / "install-proof.yml"
WINDOWS_INIT_CONTRACT = ROOT / "scripts" / "assert-windows-init-contract.sh"
WINDOWS_INIT_CONTRACT_POLICY = "scripts/assert-windows-init-contract.sh"
WINDOWS_WSL2_DOC = ROOT / "docs" / "windows-wsl2.md"
QUICKSTART_DOC = ROOT / "docs" / "quickstart.md"
MCP_TOOLS_DOC = ROOT / "docs" / "mcp-tools.md"
LLMS_DOC = ROOT / "llms.txt"
NPM_CANONICAL_README = ROOT / "packages" / "kin" / "README.md"
NPM_MCP_README = ROOT / "packages" / "kin-mcp" / "README.md"
WINDOWS_NPM_PROOF = ROOT / "scripts" / "prove-windows-npm-first-run.mjs"
CANONICAL_NPM_PROVISION = ROOT / "packages" / "kin" / "lib" / "provision.mjs"
CANONICAL_NPM_PROVISION_TEST = ROOT / "packages" / "kin" / "test" / "provision.test.mjs"
COMPAT_NPM_PROVISION = ROOT / "packages" / "kin-mcp" / "src" / "index.js"
COMPAT_NPM_PROVISION_TEST = ROOT / "packages" / "kin-mcp" / "test" / "index.test.js"
INSTALLER_CALLBACK = WORKFLOWS / "publish-release-installers.yml"
UPDATE_TRUST = ROOT / "docs" / "security" / "signing-and-update-trust.md"
PREPARE_RELEASE = ROOT / "scripts" / "prepare-release.mjs"
# A repo-relative file path as the release generator writes it.
GENERATED_PATH_LITERAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*\.[A-Za-z0-9]+$")
INSTALL_SH = ROOT / "scripts" / "install.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
INSTALL_PS1_POLICY = "scripts/install.ps1"
# The installer notice ends with autocrlf recovery advice for a shell that has
# already failed. Prose surfaces carry the capability claim before it, so this
# sentence opener is where the installer rendering and the doc rendering split.
WINDOWS_NOTICE_INSTALLER_TAIL = " If kin init reports"
ABANDONED_TAGS = ROOT / "scripts" / "abandoned-release-tags.json"
TAG_SELECTOR = ROOT / "scripts" / "select-admissible-release-tag.py"
ABANDONED_TAGS_POLICY = "scripts/abandoned-release-tags.json"
TAG_SELECTOR_POLICY = "scripts/select-admissible-release-tag.py"
ASSERTION_REACHABILITY = ROOT / "scripts" / "test-assertion-reachability.py"
RELEASE_TRAIN_BODY = ROOT / "scripts" / "release-train-body.mjs"
RELEASE_TRAIN_BODY_POLICY = "scripts/release-train-body.mjs"
RELEASE_TRAIN_BODY_BEGIN = "<!-- kin-release-train:begin -->"
RELEASE_TRAIN_BODY_END = "<!-- kin-release-train:end -->"
ASSERTION_REACHABILITY_POLICY = "scripts/test-assertion-reachability.py"
GLIBC_FLOOR_GUARD = ROOT / "scripts" / "check-glibc-floor.mjs"
GLIBC_FLOOR_GUARD_POLICY = "scripts/check-glibc-floor.mjs"
GLIBC_FLOOR_TEST = ROOT / "scripts" / "check-glibc-floor.test.mjs"
GLIBC_FLOOR_TEST_POLICY = "scripts/check-glibc-floor.test.mjs"
GLIBC_FLOOR_RELEASE_CHECK = (
    'run: node scripts/check-glibc-floor.mjs "$ARTIFACT/kin-vfs" "$ARTIFACT/$SHIM_NAME"'
)
GLIBC_FLOOR_BUILD_READ = (
    'floor="$(node "$GITHUB_WORKSPACE/scripts/check-glibc-floor.mjs" --print-floor)"'
)
KIN_VFS_COMPAT_GUARD = ROOT / "scripts" / "check-kin-vfs-compat.mjs"
KIN_VFS_COMPAT_GUARD_POLICY = "scripts/check-kin-vfs-compat.mjs"
KIN_VFS_COMPAT_TEST = ROOT / "scripts" / "check-kin-vfs-compat.test.mjs"
KIN_VFS_COMPAT_TEST_POLICY = "scripts/check-kin-vfs-compat.test.mjs"
INSTALLER_ASSET_GUARD = ROOT / "scripts" / "verify-installer-release-assets.py"
INSTALLER_ASSET_GUARD_POLICY = "scripts/verify-installer-release-assets.py"
INSTALLER_ASSET_FALSIFIER = ROOT / "scripts" / "falsify-installer-release-assets.py"
INSTALLER_ASSET_FALSIFIER_POLICY = "scripts/falsify-installer-release-assets.py"
INSTALLER_BINARY_GUARD = ROOT / "scripts" / "verify-installer-archive-binaries.py"
INSTALLER_BINARY_GUARD_POLICY = "scripts/verify-installer-archive-binaries.py"
INSTALLER_BINARY_FALSIFIER = ROOT / "scripts" / "falsify-installer-archive-binaries.py"
INSTALLER_BINARY_FALSIFIER_POLICY = "scripts/falsify-installer-archive-binaries.py"
RELEASE_VERSION_GUARD = ROOT / "scripts" / "check-release-version.mjs"
RELEASE_VERSION_GUARD_POLICY = "scripts/check-release-version.mjs"
RELEASE_VERSION_SUITE_POLICY = "scripts/check-release-version.test.mjs"
RELEASE_INTENT_SUITE_POLICY = "scripts/release-intent.test.mjs"
RELEASE_VERSION_FALSIFIER = ROOT / "scripts" / "falsify-release-version-guards.py"
RELEASE_VERSION_FALSIFIER_POLICY = "scripts/falsify-release-version-guards.py"
TRUSTED_POLICY_PREFIX = "refs/remotes/origin/main:"
TAG_LISTING_FORMAT = (
    "--format='%(refname:strip=2) "
    "%(if)%(*objectname)%(then)%(*objectname)%(else)%(objectname)%(end)'"
)
RELEASE_PR_STEP_ANCHOR = "      - name: Open the protected release PR"
RELEASE_APP_TOKEN = "${{ steps.app-token.outputs.token }}"
DEFAULT_WORKFLOW_TOKEN = "${{ github.token }}"
STEP_ENV_TOKEN_BINDING = re.compile(r"(?m)^\s+GH_TOKEN:\s*(?P<token>\S.*?)\s*$")
# Which tag each workflow declares it is about to create. Only the mint creates
# one, so only the mint names it. The train resolves drift from a base tag it
# never mints, and handing that base over as mint intent refuses exactly when a
# record covers it, which is always the moment a record is written: the mint
# only ever creates `v$(workspace version)`, so main's version equals the stuck
# tag until the train opens the bump the record exists to unblock. The empty
# argument is spelled as a literal rather than an expanded variable so that
# refilling it is a visible diff here and not a silent assignment upstream.
# Third-party actions inside the workflows that produce presence-required release
# contexts. A required context is release evidence, so whatever can write into it
# is release supply chain and has to be pinned to an immutable object rather than
# a tag anyone upstream can move. `actions/*` are first-party and governed
# separately, and `./`-prefixed actions are this repository's own tree, which
# moves only through a reviewed pull request here; these are the ones outside
# that trust boundary.
EXPECTED_REQUIRED_CONTEXT_ACTION_PINS = {
    ".github/workflows/sast.yml": {
        "taiki-e/install-action": "6a1bd70eaac3c8bdf093356838d7ee09fda951cf",
    },
}
EXPECTED_SELECTOR_INVOCATIONS = {
    "release-tag": ('"$abandoned"', '"$candidate_tags"', '"$TAG"', '"$admissible"'),
    "release-train": ('"$abandoned"', '"$candidate_tags"', '""', '"$admissible"'),
    # Recovery asks the same question about one tag, so its candidate listing is
    # the single pair the failed release ran rather than the whole tag listing,
    # and its mint intent is empty for a blunter reason than the train's: naming
    # the tag under reconcile as intent makes the selector refuse exactly the
    # recorded tag recovery is asking about, so recovery would read a waived tag
    # as unwaived and re-arm the alert the record exists to stand down.
    "release-recovery": ('"$RECORD"', '"$candidate"', '""', '"$admissible"'),
}
HEALTH = ROOT / "crates" / "kin-cli" / "src" / "commands" / "health.rs"
SETUP = ROOT / "crates" / "kin-cli" / "src" / "commands" / "setup.rs"
DOCKERFILE = ROOT / "Dockerfile"
CI_APT_INSTALL = ROOT / "scripts" / "ci-apt-install.sh"
BASE_IMAGE_REGISTRY = "docker.io"
BASE_IMAGE_MIRROR = 'mirrors = ["mirror.gcr.io"]'
BASE_IMAGE_MIRROR_INPUT = "buildkitd-config-inline:"
BASE_IMAGE_PIN = re.compile(r"(?m)^FROM\s+(?P<reference>\S+)")
SETUP_BUILDX_ACTION = "docker/setup-buildx-action@"
BASE_IMAGE_PINS = WORKFLOWS / "base-image-pins.yml"
RUST_CACHE_ACTION = "Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4"
MAIN_ONLY_CACHE_SAVE = "save-if: ${{ github.ref == 'refs/heads/main' }}"
MAIN_ONLY_CACHE_SAVE_VALUE = "${{ github.ref == 'refs/heads/main' }}"
# A job that reads the cache entry another job writes, and must never write it
# itself, saves on no ref at all. That is strictly narrower than the main-only
# scalar and never broader, so it cannot become the way an untrusted ref
# poisons a cache. These two values are the whole allowlist and anything else
# is still rejected. Nothing here has to re-prove that a saver still exists:
# the falsification below pins the check job's own main-only save by count.
RESTORE_ONLY_CACHE_SAVE_VALUE = "false"
CACHE_SAVE_VALUES = frozenset(
    {MAIN_ONLY_CACHE_SAVE_VALUE, RESTORE_ONLY_CACHE_SAVE_VALUE}
)
RUST_CACHE_REFERENCE = re.compile(r"Swatinem/rust-cache@", re.IGNORECASE)
CANONICAL_STEP_FIELDS = frozenset(
    {
        "continue-on-error",
        "env",
        "id",
        "if",
        "name",
        "run",
        "shell",
        "timeout-minutes",
        "uses",
        "with",
        "working-directory",
    }
)
CACHE_AUTHORITY_ADVERSARIAL_WORKFLOWS = (
    (
        "escaped action key and value",
        "canonical unquoted `key:` syntax",
        r"""
name: Escaped action
on: push
permissions:
  contents: read
jobs:
  adversarial:
    runs-on: ubuntu-latest
    steps:
      - name: Hidden moving cache action
        "u\u0073es": "Swatinem/rust-ca\u0063he@v2"
        with:
          save-if: ${{ true }}
""",
    ),
    (
        "aliased action value",
        "direct action scalar",
        r"""
name: Aliased action
on: push
permissions:
  contents: read
env:
  HIDDEN_CACHE: &hidden_cache "Swatinem/rust-ca\u0063he@v2"
jobs:
  adversarial:
    runs-on: ubuntu-latest
    steps:
      - name: Hidden alias cache action
        uses: *hidden_cache
        with:
          save-if: ${{ true }}
""",
    ),
    (
        "multiline escaped action value",
        "direct action scalar",
        r"""
name: Multiline escaped action
on: push
permissions:
  contents: read
jobs:
  adversarial:
    runs-on: ubuntu-latest
    steps:
      - name: Hidden multiline cache action
        uses: "Swatinem/rust-ca\
          che@v2"
        with:
          save-if: ${{ true }}
""",
    ),
    (
        "flow-mapping action step",
        "canonical block mapping",
        r"""
name: Flow action
on: push
permissions:
  contents: read
jobs:
  adversarial:
    runs-on: ubuntu-latest
    steps:
      - {name: Hidden flow cache action, "u\u0073es": "Swatinem/rust-ca\u0063he@v2", with: {save-if: "${{ true }}"}}
""",
    ),
    (
        "escaped save-if key",
        "canonical unquoted `key:` syntax",
        r"""
name: Escaped cache policy
on: push
permissions:
  contents: read
jobs:
  adversarial:
    runs-on: ubuntu-latest
    steps:
      - name: Hidden cache save policy
        uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4
        with:
          "save\u002dif": ${{ true }}
""",
    ),
    (
        "aliased save-if value",
        "must be the exact main-only scalar",
        r"""
name: Aliased cache policy
on: push
permissions:
  contents: read
env:
  HIDDEN_SAVE: &hidden_save "${{ true }}"
jobs:
  adversarial:
    runs-on: ubuntu-latest
    steps:
      - name: Hidden aliased save policy
        uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4
        with:
          save-if: *hidden_save
""",
    ),
    (
        "flow-mapping with policy",
        "with field must be a canonical block mapping",
        r"""
name: Flow cache policy
on: push
permissions:
  contents: read
jobs:
  adversarial:
    runs-on: ubuntu-latest
    steps:
      - name: Hidden flow save policy
        uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4
        with: {save-if: "${{ true }}"}
""",
    ),
)
REQUIRED_RELEASE_CHECKS = (
    "Check & Test (ubuntu-latest)",
    "Check & Test (macos-latest)",
    "Falsify guards",
    "Feature permutation tests (ubuntu-latest)",
    "Feature permutation tests (macos-latest)",
    "DCO Sign-off",
    "cargo-deny",
    "gitleaks (full history)",
    "Windows installer + vector release build",
)
DOCS_ONLY_WORKFLOW_HEADER = textwrap.dedent(
    """\
    name: CI
    on:
      push:
        branches: [main]
      pull_request:
        branches: [main]
        types: [opened, synchronize, reopened]
      merge_group:
      repository_dispatch:
        types: [dependency-updated]
    permissions:
      contents: read
    concurrency:
      group: ${{ github.workflow }}-${{ github.ref }}-${{ github.ref == 'refs/heads/main' && github.sha || '' }}
      cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
    env:
      CARGO_TERM_COLOR: always
      RUSTFLAGS: "-D warnings"
    """
).rstrip()
DOCS_ONLY_CLASSIFIER_SHELL = textwrap.dedent(
    """\
    set -euo pipefail
    docs_only=false
    if [ "$EVENT_NAME" = "pull_request" ]; then
      changed="$(
        /usr/bin/env -i \\
          HOME=/dev/null \\
          PATH=/usr/bin:/bin \\
          LC_ALL=C \\
          GIT_CONFIG_NOSYSTEM=1 \\
          GIT_CONFIG_SYSTEM=/dev/null \\
          GIT_CONFIG_GLOBAL=/dev/null \\
          GIT_CONFIG_COUNT=0 \\
          GIT_ATTR_NOSYSTEM=1 \\
          GIT_PAGER=cat \\
          GIT_TERMINAL_PROMPT=0 \\
          /usr/bin/git \\
            --no-pager \\
            --no-replace-objects \\
            --no-lazy-fetch \\
            --no-optional-locks \\
            --literal-pathspecs \\
            --git-dir="$WORKSPACE/.git" \\
            --work-tree="$WORKSPACE" \\
            -c core.attributesFile=/dev/null \\
            -c core.fsmonitor=false \\
            -c diff.external= \\
            -c diff.renames=false \\
            -c diff.ignoreSubmodules=none \\
            diff \\
            --no-ext-diff \\
            --no-textconv \\
            --no-renames \\
            --ignore-submodules=none \\
            --submodule=short \\
            --name-only \\
            "$BASE_SHA...$HEAD_SHA" \\
            --
      )"
      if [ -n "$changed" ]; then
        docs_only=true
        while IFS= read -r path; do
          case "$path" in
            .github/workflows/ci.yml) docs_only=false; break ;;
            *.md | docs/*) ;;
            .github/workflows/*) ;;
            *) docs_only=false; break ;;
          esac
        done <<< "$changed"
      fi
      printf '%s\\n' "$changed"
    fi
    echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"
    """
).rstrip()
DOCS_ONLY_CLASSIFIER_JOB = textwrap.dedent(
    """\
    changes:
      name: Classify diff scope
      runs-on: ubuntu-latest
      outputs:
        docs_only: ${{ steps.classify.outputs.docs_only }}
      steps:
        - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
          with:
            fetch-depth: 0
        - name: Classify changed paths
          id: classify
          shell: /usr/bin/bash --noprofile --norc -p -e -u -o pipefail {0}
          env:
            PATH: /usr/bin:/bin
            BASH_ENV: ""
            ENV: ""
            LD_AUDIT: ""
            LD_LIBRARY_PATH: /dev/null
            LD_PRELOAD: ""
            WORKSPACE: ${{ github.workspace }}
            EVENT_NAME: ${{ github.event_name }}
            BASE_SHA: ${{ github.event.pull_request.base.sha }}
            HEAD_SHA: ${{ github.event.pull_request.head.sha }}
          run: |
            set -euo pipefail
            docs_only=false
            if [ "$EVENT_NAME" = "pull_request" ]; then
              changed="$(
                /usr/bin/env -i \\
                  HOME=/dev/null \\
                  PATH=/usr/bin:/bin \\
                  LC_ALL=C \\
                  GIT_CONFIG_NOSYSTEM=1 \\
                  GIT_CONFIG_SYSTEM=/dev/null \\
                  GIT_CONFIG_GLOBAL=/dev/null \\
                  GIT_CONFIG_COUNT=0 \\
                  GIT_ATTR_NOSYSTEM=1 \\
                  GIT_PAGER=cat \\
                  GIT_TERMINAL_PROMPT=0 \\
                  /usr/bin/git \\
                    --no-pager \\
                    --no-replace-objects \\
                    --no-lazy-fetch \\
                    --no-optional-locks \\
                    --literal-pathspecs \\
                    --git-dir="$WORKSPACE/.git" \\
                    --work-tree="$WORKSPACE" \\
                    -c core.attributesFile=/dev/null \\
                    -c core.fsmonitor=false \\
                    -c diff.external= \\
                    -c diff.renames=false \\
                    -c diff.ignoreSubmodules=none \\
                    diff \\
                    --no-ext-diff \\
                    --no-textconv \\
                    --no-renames \\
                    --ignore-submodules=none \\
                    --submodule=short \\
                    --name-only \\
                    "$BASE_SHA...$HEAD_SHA" \\
                    --
              )"
              if [ -n "$changed" ]; then
                docs_only=true
                while IFS= read -r path; do
                  case "$path" in
                    .github/workflows/ci.yml) docs_only=false; break ;;
                    *.md | docs/*) ;;
                    .github/workflows/*) ;;
                    *) docs_only=false; break ;;
                  esac
                done <<< "$changed"
              fi
              printf '%s\\n' "$changed"
            fi
            echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"
    """
).rstrip()
# The inert pull-request producer of both expanded `Check & Test` names. It
# covered documentation-only diffs alone until FIR-2815 took the ubuntu and
# macOS suites off the pull-request path; it now covers every pull request, and
# it carries no `needs:` so it reports without waiting on the classifier. Its
# condition and the two aggregates' are mutually exclusive on every event, which
# is what keeps one required name from having two check runs behind it.
PULL_REQUEST_CHECK_STUB = textwrap.dedent(
    """\
    check-pr-fast-path:
      name: Check & Test
      if: ${{ !cancelled() && github.event_name == 'pull_request' }}
      runs-on: ubuntu-latest
      strategy:
        matrix:
          os: [ubuntu-latest, macos-latest]
      steps:
        - name: Report the pull-request fast path
          run: |
            echo "Check & Test runs in the merge queue and on every main commit."
            echo "Admission is the fast gate; see .github/workflows/ci.yml."
    """
).rstrip()
# The ubuntu shards publish `Check & Test ubuntu shard (1)` and `(2)`, which no
# ruleset requires, and `check-aggregate` is what publishes the required
# `Check & Test (ubuntu-latest)`. The job id stays `check` rather than becoming
# `check-ubuntu` for two reasons neither of which is visible from this file:
# `bin/kin-precheck` in the umbrella enumerates this job's gate list by that id,
# and `rust-cache` composes its key from the job id when no shared key is given,
# so `feature-tests` reaches this job's warm dependency graph by asking for
# `check`. Renaming it would cost the ubuntu permutations their cache exactly
# the way the macOS leg lost its own.
REAL_CHECK_JOB_AUTHORITY = textwrap.dedent(
    """\
    check:
      name: Check & Test ubuntu shard
      needs: changes
      if: >-
        ${{ !cancelled()
        && needs.changes.outputs.docs_only != 'true'
        && github.event_name != 'pull_request' }}
      runs-on: kin-16core
      timeout-minutes: 60
      env:
        CARGO_INCREMENTAL: "0"
        CARGO_PROFILE_DEV_DEBUG: "0"
        CARGO_PROFILE_TEST_DEBUG: "0"
      strategy:
        fail-fast: false
        matrix:
          shard: [1, 2]
      steps:
    """
).rstrip()
# The ubuntu counterpart of MACOS_SHARD_AGGREGATE_AUTHORITY, pinned for the same
# two reasons: the one-value matrix keeps a skipped aggregate from publishing the
# expanded required name beside the documentation-only stub's, and admitting only
# `success` from the shard roll-up keeps a skipped or cancelled shard from
# leaving half the ubuntu suite unrun behind a green required context.
UBUNTU_SHARD_AGGREGATE_AUTHORITY = textwrap.dedent(
    """\
    check-aggregate:
      name: Check & Test
      needs: [changes, check]
      if: >-
        ${{ !cancelled()
        && needs.changes.outputs.docs_only != 'true'
        && github.event_name != 'pull_request' }}
      runs-on: ubuntu-latest
      timeout-minutes: 5
      strategy:
        matrix:
          os: [ubuntu-latest]
      steps:
    """
).rstrip()
# Indented as `classifier_active_job_source` renders a dedented job block.
# The `check` job runner, pinned here as well as inside
# REAL_CHECK_JOB_AUTHORITY, because `shards` binds to blocks.get("check"),
# so one job is pinned in two places and both have to move together.
# Moved to the larger runner under the founder's 2026-08-26 ruling. The
# aggregate is deliberately NOT moved: it compiles nothing and runs in
# seconds, so it stays on ubuntu-latest.
UBUNTU_SHARD_RUNNER = "  runs-on: kin-16core"
UBUNTU_SHARD_INDEPENDENT_LEGS = "    fail-fast: false"
UBUNTU_SHARD_MATRIX = "      shard: [1, 2]"
UBUNTU_SHARD_PARTITION = (
    "      run: cargo nextest run --locked --partition count:${{ matrix.shard }}/2"
)
UBUNTU_SHARD_DOCTESTS = "      run: cargo test --doc --locked"
UBUNTU_SHARD_SUCCESS_GATE = 'if [ "$SHARDS" != "success" ]; then'
# The gates this job runs and the macOS shards deliberately do not. Each reads
# source and cannot answer differently on a second runner, so each is pinned to
# shard 1 by an explicit condition. They are named individually rather than
# counted: a bar set from a count is crossed by any twenty of them, and the one
# that goes missing is the one nobody named. This is the ladder-coverage lesson
# in docs/traps.md applied to a step list.
UBUNTU_SHARD_ONE_ONLY_GATES = (
    "Check the README language count against the adapter registry",
    "Install runtime guard tools",
    "Validate installer checksum fixtures",
    "Validate that every release gate assertion still runs",
    "Validate mandatory Homebrew release outcome gate",
    "Validate automatic release policy",
    "Check the RC build mirrors the release build",
    "Verify Kin/kin-vfs compatibility at the pinned release input",
    "Check formatting",
    "Check Zero File-Search Invariant",
    "Check Zero File-Search Invariant (answer modules)",
    "Check Hydration Replay Semantics",
    "Falsify Hydration Replay Semantics guard",
    "Falsify the release policy and Windows leg gates",
    "Clippy",
    "Check Runtime Boundaries",
    "Check Private Repo Coupling",
    "Test Private Repo Coupling Guard",
    "Check the Linux release target (musl)",
    "Check the aarch64 Linux release target (musl)",
    "Doc tests",
)
# What a partition consumes, and therefore what neither shard may skip. A
# partition that ran without one of these is not a partition of the suite.
UBUNTU_SHARD_BOTH_LEGS_STEPS = (
    "Install Rust toolchain",
    "Verify kin cargo registry config",
    "Cache cargo registry and build",
    "Build",
    "Install nextest",
    "Install language servers for the enrichment proof",
    "Test",
)
# The macOS shards publish `Check & Test macOS shard (1)` and `(2)`, which no
# ruleset requires, and the aggregate is what publishes the required
# `Check & Test (macos-latest)`. Two properties make that safe and both are
# pinned here, because neither is observable from the required context's name:
# the aggregate carries a one-value matrix, without which a SKIPPED aggregate
# would publish the expanded name beside the documentation-only stub's and put
# two check runs under one required name; and it admits only `success` from the
# shard roll-up, without which a skipped or cancelled shard would leave half the
# macOS suite unrun behind a green required context.
MACOS_SHARD_AGGREGATE_AUTHORITY = textwrap.dedent(
    """\
    check-macos-aggregate:
      name: Check & Test
      needs: [changes, check-macos]
      if: >-
        ${{ !cancelled()
        && needs.changes.outputs.docs_only != 'true'
        && github.event_name != 'pull_request' }}
      runs-on: ubuntu-latest
      timeout-minutes: 5
      strategy:
        matrix:
          os: [macos-latest]
      steps:
    """
).rstrip()
# Indented as `classifier_active_job_source` renders a dedented job block, which
# is the form these are matched against.
MACOS_SHARD_RUNNER = "  runs-on: macos-latest"
MACOS_SHARD_INDEPENDENT_LEGS = "    fail-fast: false"
MACOS_SHARD_MATRIX = "      shard: [1, 2]"
MACOS_SHARD_PARTITION = (
    "      run: cargo nextest run --locked --partition count:${{ matrix.shard }}/2"
)
MACOS_SHARD_DOCTESTS = "      run: cargo test --doc --locked"
MACOS_SHARD_SUCCESS_GATE = 'if [ "$SHARDS" != "success" ]; then'
CI_JOB_DISPLAY_NAMES = {
    "dco": "DCO Sign-off",
    "release-version": "Release version gate",
    "npm-launchers": "npm launcher tests",
    "windows-authority-tests": "Windows authority tests",
    "windows-authority-cli-tests": "Windows authority CLI tests",
    "windows-authority-runtime-tests": "Windows authority runtime tests",
    "windows-installer": "Windows installer + vector release build",
    "changes": "Classify diff scope",
    # The admission core (FIR-2815). Both run on every event and between them
    # they are the whole of what blocks a pull request. `fast-gate-tests`
    # publishes a shard name no ruleset requires; `fast-gate-tests-aggregate`
    # publishes the required name and is green only when every shard succeeded.
    "fast-gate-lint": "Fast gate lint and policy",
    "fast-gate-tests": "Fast gate test shard",
    "fast-gate-tests-aggregate": "Fast gate build and tests",
    # The inert pull-request producer of the two expanded `Check & Test` names.
    # It covered documentation-only diffs alone until FIR-2815 moved the ubuntu
    # and macOS suites off the pull-request path; it now covers every pull
    # request, which is why the id no longer says docs.
    "check-pr-fast-path": "Check & Test",
    # The ubuntu half of Check & Test, split so its 14.98-minute test step can
    # run as two nextest partitions. The shard job keeps the id `check`, which
    # bin/kin-precheck and rust-cache both key on, and publishes a name of its
    # own that is required by nothing; `check-aggregate` publishes
    # `Check & Test` with a one-value matrix, which expands to the
    # release-required `Check & Test (ubuntu-latest)` and is what the ruleset
    # names.
    "check": "Check & Test ubuntu shard",
    "check-aggregate": "Check & Test",
    # The macOS half of Check & Test, split so its 14.2-minute test step can run
    # as two nextest partitions. The shard job publishes a name of its own and
    # is required by nothing; the aggregate publishes `Check & Test` with a
    # one-value matrix, which expands to the release-required
    # `Check & Test (macos-latest)` and is what the ruleset names.
    "check-macos": "Check & Test macOS shard",
    "check-macos-aggregate": "Check & Test",
    # Both were steps inside `check` and are jobs so they stop sitting on the
    # merge queue's critical path. Neither is a required context until the
    # branch ruleset names it, so each is listed here to be reviewed as a
    # producer, and the ruleset is what makes it block.
    "falsify-guards": "Falsify guards",
    "feature-tests-pr-fast-path": "Feature permutation tests",
    "feature-tests": "Feature permutation tests",
    "coverage": "Code Coverage",
    "install-proof-pr-build": "Install Proof (PR) Build",
    "install-proof-pr": "Install Proof (PR)",
    "install-proof-pr-gate": "Install Proof (PR) Gate",
}
EXPECTED_WORKFLOW_JOB_DISPLAY_NAMES: dict[str, dict[str, str | None]] = {
    # The per-pull-request product acceptance job (FIR-2591). It publishes no
    # required context and claims none; it is registered here because this
    # census is what would otherwise let a new workflow's job NAME appear
    # unreviewed. The job id and display name are stable on purpose: renaming
    # either is what ejects unrelated queue entries.
    # The red-Acceptance alarm. It triggers only on `workflow_run` once
    # Acceptance concludes, so it runs on no pull-request or merge-group event and
    # can never claim a required context. Its only write is one tracking issue.
    ".github/workflows/acceptance-red-alarm.yml": {
        "alarm": "Report a red Acceptance on main",
    },
    ".github/workflows/acceptance.yml": {
        "acceptance": "Product Acceptance",
    },
    # The scheduled advisory sweep. It publishes no required context and runs on
    # no pull-request or merge-group event, so it can never claim one; it is
    # registered here because this census is what would otherwise let a new
    # job's NAME appear unreviewed.
    ".github/workflows/advisory-sweep.yml": {
        "sweep": "Sweep advisories",
    },
    ".github/workflows/approve-to-merge.yml": {
        "gate": None,
    },
    ".github/workflows/base-image-pins.yml": {
        "verify-pins": "Verify base image pins",
    },
    ".github/workflows/ci.yml": CI_JOB_DISPLAY_NAMES,
    ".github/workflows/claude.yml": {
        "preflight": "Resolve responder credential",
        "respond": "Respond to the mention",
    },
    ".github/workflows/daemon-smoke.yml": {
        "daemon-smoke": "Linux Daemon Smoke + MCP Headless",
    },
    ".github/workflows/dco.yml": {
        # This pull_request_target check is deliberately distinct from the
        # release-required CI job. GitHub check names are case-sensitive:
        # lowercase "sign-off" is extra PR evidence, never release evidence.
        "dco": "DCO sign-off",
    },
    ".github/workflows/docker.yml": {
        "build-image": "Docker Image Build (no push)",
    },
    ".github/workflows/fuzz.yml": {
        "fuzz": "cargo-fuzz (${{ matrix.target }})",
    },
    ".github/workflows/install-proof.yml": {
        "install-proof": "${{ matrix.os }}",
    },
    # The dependency receiver validates the exact payload, prepares and compiles
    # candidate registry bytes without a write credential, then admits only the
    # hash-bound manifest delta on a fresh App-authenticated runner. It publishes
    # no pull-request or merge-group context.
    ".github/workflows/kin-registry-release.yml": {
        "validate-dispatch": "Validate Kin registry release",
        "disarm-wave": "Disarm inherited Kin registry landing state",
        "prepare-wave": "Prepare and compile Kin registry pins",
        "mutate-wave": "Update the fixed Kin registry PR",
    },
    # This workflow_run consumer persists the exact App attestation only after
    # the receiver attempt is terminal-successful. It produces no required
    # context; the required CI gate reads and revalidates its server evidence.
    ".github/workflows/kin-registry-release-attest.yml": {
        "attest-completed-receiver": "Attest completed Kin registry receiver",
    },
    ".github/workflows/link-check.yml": {
        "link-check": "Check public documentation links",
    },
    # Manual fix-forward publisher for a release whose registry entry failed;
    # workflow_dispatch only, so it never produces a pull request check.
    ".github/workflows/mcp-registry-republish.yml": {
        "republish_mcp_registry": "Publish to the MCP Registry",
    },
    # Reports an ejection on the pull request the merge queue dropped. It runs
    # on workflow_run after the fact, produces no check on a pull request, and
    # so is never a required-context producer.
    ".github/workflows/merge-queue-ejection-notice.yml": {
        "notice": None,
    },
    ".github/workflows/notify-approver.yml": {
        "notify": None,
    },
    ".github/workflows/pr-text-hygiene.yml": {
        "pr_text": "PR text hygiene",
    },
    ".github/workflows/publish-release-installers.yml": {
        "dispatch": None,
    },
    # The release-candidate archive build. It is workflow_dispatch only, holds
    # no credential, and publishes nothing, so it produces no pull-request check
    # and can claim no required context. It is registered here because this
    # census is what would otherwise let a new job's NAME appear unreviewed.
    ".github/workflows/rc-build.yml": {
        "build": "RC Build (${{ matrix.artifact }})",
        "capability": "RC Capability (${{ matrix.os }})",
    },
    ".github/workflows/registry-index-migrate.yml": {
        "migrate": None,
    },
    ".github/workflows/release-recovery.yml": {
        "reconcile": "Reconcile failed release",
    },
    ".github/workflows/release-sentinel.yml": {
        "preflight": "Resolve sentinel credential",
        "patrol": "Patrol the release rail",
    },
    ".github/workflows/install-proof-canary.yml": {
        "capability-canary": "Capability Contract Canary",
    },
    ".github/workflows/release-tag.yml": {
        "mint-release-tag": "Mint release tag",
    },
    ".github/workflows/release-train.yml": {
        "reconcile": "Reconcile release PR",
        "hold-alarm": "Report a held rail",
    },
    ".github/workflows/release.yml": {
        "config": "Resolve release config",
        "build_daemon_image": "Build immutable daemon image",
        "attest_daemon_image": "Attest immutable daemon image",
        "build": "Build (${{ matrix.artifact }})",
        "notarize_linux": "Notarize macOS binaries (Linux / rcodesign)",
        "publish": "Publish Release",
        "install_proof": "Public Install Proof",
        "npm_publish_preflight": "Preflight Both npm Packages",
        "publish_npm_compatibility": (
            "Publish npm Compatibility Wrapper (@kinlab/kin-mcp)"
        ),
        "publish_npm_canonical": "Publish npm Canonical Package (@kinlab/kin)",
        "verify_npm_published": (
            "Verify Published npm Provenance (${{ matrix.package }})"
        ),
        "smoke_npm_published": (
            "Anonymous Published npm Smoke (${{ matrix.package }})"
        ),
        "publish_mcp_registry": "Publish to the MCP Registry",
        "finalize_release": "Promote Proven Release",
        "promote_ghcr_latest": "Promote stable ghcr latest",
        "publish_boundary_contracts": "Post-release boundary contracts publish",
        "version_tag_image": "Version-tag ghcr image",
        "seal_release_completion": "Seal completed stable release",
    },
    ".github/workflows/sast.yml": {
        "changes": "Classify diff scope",
        "cargo-deny": "cargo-deny",
    },
    ".github/workflows/secret-scan.yml": {
        "gitleaks": "gitleaks (full history)",
    },
    # workflow_dispatch only, so as written it publishes no check run on a pull
    # request or merge group. Registered here because this census is what would
    # otherwise let a new job's NAME appear unreviewed.
    #
    # It does not follow that the dispatch-only property is protected: this
    # census reads job names and never `on:` triggers, so adding
    # `pull_request:` to that workflow leaves the suite green. Verified by
    # injecting the trigger and re-running.
    ".github/workflows/windows-vector-proof.yml": {
        "windows-vector-proof": "Windows semantic vector search proof",
    },
}
EXPECTED_DYNAMIC_JOB_CONTEXT_SHA256 = {
    (
        ".github/workflows/fuzz.yml",
        "fuzz",
    ): "aa645addde738ea8f1fac9c70071ac0f603fd0030602f15d013535abf9a32443",
    (
        ".github/workflows/install-proof.yml",
        "install-proof",
    ): "3ab38cec398001873f4a29bb17ce14264b6eb54dbbe2b865ff109d1d4a74767d",
    (
        ".github/workflows/rc-build.yml",
        "build",
    ): "8dc0699fb69599edbca87492f3f3a895aefa3bea8384c86d8fc11fef99f9d52a",
    (
        ".github/workflows/rc-build.yml",
        "capability",
    ): "3e7512c3b44ab447531be464599f6237bff7efe798d54728c012676a7c3aed23",
    (
        ".github/workflows/release.yml",
        "build",
    ): "7375c7f0f82227e8695aea7fc290631a9d3667dc6674dca10830c53e0a0f4564",
    (
        ".github/workflows/release.yml",
        "verify_npm_published",
    ): "be398c786bc9f4a31e8a4196076f707a93b33b70c0ec9b4a0ea5e87f3e84c314",
    (
        ".github/workflows/release.yml",
        "smoke_npm_published",
    ): "495829aee07c97dfd59924fcac7ff3ddb57be574ffd0bf741adc93a37425b492",
}
REQUIRED_CHECK_JOB_PRODUCERS = {
    # Three producers, one per required expansion plus the documentation-only
    # stub. `check-aggregate` carries ubuntu-latest and is green only when every
    # `check` shard succeeded, `check-macos-aggregate` carries macos-latest on
    # the same terms, and `check-docs-only` publishes both names on a
    # documentation-only diff. `check` and `check-macos` publish names of their
    # own that no ruleset requires, which is what keeps a shard from being a
    # second check run under a required name. The real jobs and the stub stay
    # mutually exclusive by condition, so no two of them ever publish the same
    # expanded name on one event.
    "Check & Test": {
        (".github/workflows/ci.yml", "check-pr-fast-path"),
        (".github/workflows/ci.yml", "check-aggregate"),
        (".github/workflows/ci.yml", "check-macos-aggregate"),
    },
    "Falsify guards": {
        (".github/workflows/ci.yml", "falsify-guards"),
    },
    # The admission core (FIR-2815). Neither is required by a ruleset at the
    # moment this lands; the captain adds them, and the shape of that change is
    # in the report. They are registered here for the reason `Install Proof (PR)
    # Gate` is: this map is what stops a second job appearing under a name a
    # ruleset is about to block on, and a name is easiest to steal in the window
    # before anything requires it.
    "Fast gate lint and policy": {
        (".github/workflows/ci.yml", "fast-gate-lint"),
    },
    "Fast gate build and tests": {
        (".github/workflows/ci.yml", "fast-gate-tests-aggregate"),
    },
    "Fast gate test shard": {
        (".github/workflows/ci.yml", "fast-gate-tests"),
    },
    "Feature permutation tests": {
        (".github/workflows/ci.yml", "feature-tests-pr-fast-path"),
        (".github/workflows/ci.yml", "feature-tests"),
    },
    "DCO Sign-off": {
        (".github/workflows/ci.yml", "dco"),
    },
    "cargo-deny": {
        (".github/workflows/sast.yml", "cargo-deny"),
    },
    "gitleaks (full history)": {
        (".github/workflows/secret-scan.yml", "gitleaks"),
    },
    "Windows installer + vector release build": {
        (".github/workflows/ci.yml", "windows-installer"),
    },
    # The pull-request install proof's required context is this gate rather
    # than the reusable call's per-leg checks. A reusable-workflow call
    # publishes `<caller> / <leg>`, and a caller that skips publishes nothing
    # under that name at all, so requiring a leg would hang every
    # documentation-only pull request on a check that will never report.
    "Install Proof (PR) Gate": {
        (".github/workflows/ci.yml", "install-proof-pr-gate"),
    },
}
# Durable workflow IDs are GitHub's repository-scoped identity, while `path`
# makes that identity reviewable in source. These values are also exercised
# against the current REST response shape by the positive fixture below.
#
# The third element is the event the producer publishes under INSIDE the merge
# queue, which is not uniform: ci.yml and sast.yml carry a `merge_group:`
# trigger, while secret-scan.yml carries only `push: branches: ["**"]` and so
# publishes `gitleaks (full history)` from a push to the queue ref. That
# asymmetry is why the mint admits a tier by the ref the queue built rather
# than by the event name.
REQUIRED_RELEASE_CHECK_PROVENANCE = {
    "Check & Test (ubuntu-latest)": (
        245_803_170,
        ".github/workflows/ci.yml",
        "merge_group",
    ),
    "Check & Test (macos-latest)": (
        245_803_170,
        ".github/workflows/ci.yml",
        "merge_group",
    ),
    "Falsify guards": (245_803_170, ".github/workflows/ci.yml", "merge_group"),
    "Feature permutation tests (ubuntu-latest)": (
        245_803_170,
        ".github/workflows/ci.yml",
        "merge_group",
    ),
    "Feature permutation tests (macos-latest)": (
        245_803_170,
        ".github/workflows/ci.yml",
        "merge_group",
    ),
    "DCO Sign-off": (245_803_170, ".github/workflows/ci.yml", "merge_group"),
    "cargo-deny": (251_549_972, ".github/workflows/sast.yml", "merge_group"),
    "gitleaks (full history)": (
        293_452_372,
        ".github/workflows/secret-scan.yml",
        "push",
    ),
    "Windows installer + vector release build": (
        245_803_170,
        ".github/workflows/ci.yml",
        "merge_group",
    ),
}
# Ruleset 19746451 "Require status checks on main" gates the merge queue and is
# live GitHub configuration no test here can read. The mint carries a reviewed
# mirror of it; this is the part of that mirror the mint does not itself veto
# on, which it still requires an admitted build to have published.
RULESET_ONLY_RELEASE_CHECKS = {
    "PR text hygiene": (328_945_626, ".github/workflows/pr-text-hygiene.yml"),
}
GITHUB_ACTIONS_APP_ID = 15_368
RELEASE_TAG_WORKFLOW_ID = 318_521_292
RELEASE_GATE_FIXTURE_SHA = "1" * 40
# The landing commit's first parent, and the base sha the queue ref embeds.
# The mint requires these to be the same value, which is the assertion that
# binds "the tree the queue proved" to "the commit being released".
RELEASE_GATE_PARENT_SHA = "2" * 40
RELEASE_GATE_QUEUE_REF = f"gh-readonly-queue/main/pr-958-{RELEASE_GATE_PARENT_SHA}"
RELEASE_GATE_CURRENT_RUN_ID = 9000
EXTERNAL_REQUIRED_CONTEXT_SPOOF = textwrap.dedent(
    """\
    name: Required Context Spoof

    on:
      push:
        branches: [main]

    permissions:
      contents: read

    jobs:
      delay:
        name: Delay context creation
        runs-on: ubuntu-latest
        steps:
          - run: sleep 1
      spoof:
        name: Check & Test
        needs: delay
        runs-on: ubuntu-latest
        strategy:
          matrix:
            os: [ubuntu-latest, macos-latest]
        steps:
          - run: echo success
    """
)


def require(content: str, needle: str, context: str) -> None:
    if needle not in content:
        raise AssertionError(f"{context} is missing required policy: {needle}")


def expect_assertion(
    label: str,
    expected_error: str,
    check: Callable[[], None],
) -> None:
    try:
        check()
    except AssertionError as error:
        if expected_error not in str(error):
            raise AssertionError(
                f"falsification failed for the wrong reason: {label}: {error}"
            ) from error
        return
    raise AssertionError(f"falsification did not fail: {label}")


def workflow_paths(directory: Path = WORKFLOWS) -> list[Path]:
    """Return every workflow filename GitHub Actions recognizes."""

    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )


def classifier_shell_source(classifier: str) -> str:
    """Extract the classifier's complete active shell block."""

    lines = classifier.splitlines()
    run_lines = [index for index, line in enumerate(lines) if line.strip() == "run: |"]
    if len(run_lines) != 1:
        raise AssertionError(
            "diff classifier must contain exactly one closed-form shell run block"
        )
    run_line = run_lines[0]
    run_indent = len(lines[run_line]) - len(lines[run_line].lstrip())
    shell_lines: list[str] = []
    for index in range(run_line + 1, len(lines)):
        line = lines[index]
        if not line.strip():
            shell_lines.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= run_indent:
            break
        shell_lines.append(line)

    source = textwrap.dedent("\n".join(shell_lines)).strip()
    active_lines = [
        line.rstrip()
        for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return "\n".join(active_lines)


def classifier_active_job_source(classifier: str) -> str:
    """Return the complete active YAML contract for the classifier job."""

    source = textwrap.dedent(classifier).strip()
    active_lines = [
        line.rstrip()
        for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return "\n".join(active_lines)


def workflow_active_header_source(workflow: str) -> str:
    """Return the active workflow-level contract above the jobs mapping."""

    marker = "\njobs:\n"
    if workflow.count(marker) != 1:
        raise AssertionError(
            "docs_only authority requires exactly one canonical jobs mapping"
        )
    return classifier_active_job_source(workflow.split(marker, 1)[0])


# Block comment delimiters, longest opener first so `<!--` is tried before any
# prefix of it could match.
BLOCK_COMMENTS = (("<!--", "-->"), ("<#", "#>"), ("/*", "*/"))


def strip_block_comments(lines: list[str]) -> list[str]:
    """Drop block comments written as block comments, and nothing else.

    A block comment is recognized only where one is actually written: the
    opener begins a line, and the closer ends that line or a later one.

    This used to be three DOTALL regexes over the whole text, which cannot tell
    a comment from a pair of shell globs. In ci.yml the `docs/*)` pattern in a
    `case` arm opened one and `hashFiles('**/Cargo.lock')` closed it, and 46,138
    characters, 48% of the file, vanished from every assertion built on the
    result; release-train.yml lost 24% the same way. No workflow contains a real
    block comment at all, so that stripping has only ever produced silent false
    negatives, and an assertion that cannot see the line it names passes exactly
    like one that checked it.
    """

    kept: list[str] = []
    closer: str | None = None
    for line in lines:
        stripped = line.strip()
        if closer is not None:
            if stripped.endswith(closer):
                closer = None
            continue
        consumed = False
        for opener, end in BLOCK_COMMENTS:
            if not stripped.startswith(opener):
                continue
            # A complete one-line comment closes itself; anything else opens a
            # span that the next line ending in the closer will end.
            if not (
                stripped.endswith(end) and len(stripped) >= len(opener) + len(end)
            ):
                closer = end
            consumed = True
            break
        # Blank lines pass through. `active_lines` drops them, and counting them
        # here would make every file look like it had lost a comment.
        if not consumed:
            kept.append(line)
    return kept


def active_lines(source: str) -> list[str]:
    """Return a block's non-blank, non-comment lines, stripped of indentation.

    Shell/YAML line comments, JavaScript line/block comments, PowerShell block
    comments, and Markdown/HTML comments all count. Install-proof steps embed
    JavaScript in `node <<'NODE'` heredocs and the Windows installer is
    PowerShell, so stripping only `#`/`//` still lets an entire validator or
    user-facing warning become a valid no-op block while satisfying a guard.
    """

    return [
        line.strip()
        for line in strip_block_comments(source.splitlines())
        if line.strip()
        and not line.strip().startswith("#")
        and not line.strip().startswith("//")
    ]


def install_proof_step(install_proof: str, name: str) -> str:
    """Return one install-proof step, from its name to the next step's name."""

    anchor = f"      - name: {name}\n"
    if install_proof.count(anchor) != 1:
        raise AssertionError(f"install proof must declare one step named {name}")
    start = install_proof.index(anchor)
    return install_proof[
        start : install_proof.index("\n      - name: ", start + len(anchor))
    ]


def node_heredoc_body(step: str, label: str) -> str:
    """Extract one literal Node heredoc exactly as the Actions runner executes it."""

    start_marker = "          node <<'NODE'\n"
    end_marker = "          NODE\n"
    if step.count(start_marker) != 1:
        raise AssertionError(f"{label} must contain exactly one literal Node validator")
    start = step.index(start_marker) + len(start_marker)
    if step.count(end_marker, start) != 1:
        raise AssertionError(
            f"{label} must terminate exactly one literal Node validator"
        )
    body = step[start : step.index(end_marker, start)]
    yaml_indent = "          "
    lines: list[str] = []
    for line in body.splitlines():
        if line and not line.startswith(yaml_indent):
            raise AssertionError(
                f"{label} Node validator escaped the run-block indentation: {line!r}"
            )
        lines.append(line[len(yaml_indent) :] if line else "")
    return "\n".join(lines) + "\n"


def replace_exactly_once(
    source: str, original: str, replacement: str, label: str
) -> str:
    """Build one source mutation without letting a stale probe become a no-op."""

    matches = source.count(original)
    if matches != 1:
        raise AssertionError(
            f"{label} mutation expected one source anchor, found {matches}: "
            f"{original!r}"
        )
    return source.replace(original, replacement, 1)


def workflow_active_text(block: str) -> str:
    """Comment-stripped workflow text, safe for a job whose steps run shell.

    `active_lines` is the general helper, and it also strips C-style block
    comments so a JavaScript heredoc cannot hide a no-op validator. A shell
    glob opens one of those: `refs/tags/*` starts a match that runs to the next
    `*/`, which on release-train.yml is `${policy##*/` eleven thousand
    characters later, swallowing most of the reconcile job. A guard reading a
    workflow through that rule is structurally unable to see anything in the
    swallowed range, and an absence check reading it would report absence for a
    step that is right there. YAML and shell both comment with `#` alone, so
    that is all this strips.
    """

    return "\n".join(
        line.strip()
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def swap_release_tag_step_order(release_tag: str) -> str:
    """Move the release proof gate after the tag write it exists to gate.

    Both step names survive the swap, so the count check still passes and the
    ordering check is the only thing that can catch it. That is the point: a
    gate that runs after the ref is written reads exactly like a gate.
    """

    gate = "      - name: Require proof-loop artifacts for the release candidate\n"
    write = "      - name: Create release tag ref\n"
    placeholder = "      - name: kin-order-swap-placeholder\n"
    swapped = replace_exactly_once(
        release_tag, gate, placeholder, "proof gate order"
    )
    swapped = replace_exactly_once(swapped, write, gate, "proof gate order")
    return replace_exactly_once(swapped, placeholder, write, "proof gate order")


def swap_train_undraft_after_arm(release_train: str) -> str:
    """Arm the bump pull request before un-drafting it, instead of after.

    Both commands survive, so the presence checks still pass and the ordering
    check is the only thing that can catch it. Ordering is the whole point
    here: `gh pr merge --auto` registered against a draft pull request is not
    taken by the merge queue, so un-drafting afterwards leaves auto-merge armed
    on a pull request nothing will merge.
    """

    lines = release_train.splitlines(keepends=True)

    def find(predicate, start, label):
        for index in range(start, len(lines)):
            if predicate(lines[index]):
                return index
        raise AssertionError(f"release train un-draft order mutation found no {label}")

    undraft_start = find(
        lambda line: ".isDraft" in line and line.lstrip().startswith("if ["),
        0,
        "draft-state branch",
    )
    undraft_end = find(
        lambda line: line.strip() == "fi", undraft_start, "end of the draft-state branch"
    ) + 1
    arm_start = find(
        lambda line: 'gh pr merge "$PR"' in line, undraft_end, "arm command"
    )
    arm_end = find(
        lambda line: "--match-head-commit" in line, arm_start, "end of the arm command"
    ) + 1
    return "".join(
        lines[:undraft_start]
        + lines[undraft_end:arm_end]
        + lines[undraft_start:undraft_end]
        + lines[arm_end:]
    )


def write_node_validator_fixture_files(
    root: Path,
    files: dict[str, object],
    containment_root: Path,
    label: str,
) -> None:
    """Write one isolated validator fixture without allowing path escape."""

    for relative_path, value in files.items():
        target = (root / relative_path).resolve()
        try:
            target.relative_to(containment_root)
        except ValueError as error:
            raise AssertionError(
                f"{label} fixture path escapes its isolated root: {relative_path!r}"
            ) from error
        target.parent.mkdir(parents=True, exist_ok=True)
        content = value if isinstance(value, str) else json.dumps(value)
        content = content.replace(
            "__VALIDATOR_HOME__", str((containment_root / "home").resolve())
        ).replace(
            "__VALIDATOR_PROOF__", str((containment_root / "proof").resolve())
        )
        target.write_text(content, encoding="utf-8")


def run_node_validator_fixture(
    step: str,
    label: str,
    proof_files: dict[str, object],
    home_files: dict[str, object] | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the exact inline validator against one deterministic proof fixture."""

    script = node_heredoc_body(step, label)
    with tempfile.TemporaryDirectory(prefix="kin-proof-validator-fixture-") as temporary:
        temporary_root = Path(temporary).resolve()
        proof_dir = temporary_root / "proof"
        home_dir = temporary_root / "home"
        proof_dir.mkdir()
        home_dir.mkdir()
        write_node_validator_fixture_files(
            proof_dir, proof_files, temporary_root, label
        )
        write_node_validator_fixture_files(
            home_dir, home_files or {}, temporary_root, label
        )
        environment = {
            **os.environ,
            "HOME": str(home_dir),
            "USERPROFILE": str(home_dir),
            **(extra_env or {}),
        }
        try:
            return subprocess.run(
                ["node", "-"],
                input=script,
                cwd=proof_dir,
                env=environment,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AssertionError(
                f"{label} could not execute its deterministic fixture: {error}"
            ) from error


def assert_node_validator_accepts_fixture(
    step: str,
    label: str,
    proof_files: dict[str, object],
    home_files: dict[str, object] | None = None,
    extra_env: dict[str, str] | None = None,
) -> None:
    """Require the exact validator to accept a complete known-good fixture."""

    result = run_node_validator_fixture(
        step, label, proof_files, home_files, extra_env
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{label} rejected its known-good fixture with exit {result.returncode}: "
            f"{result.stderr.strip()}"
        )


def assert_node_validator_rejects_fixture(
    step: str,
    label: str,
    proof_files: dict[str, object],
    home_files: dict[str, object] | None = None,
    extra_env: dict[str, str] | None = None,
) -> None:
    """Require the exact validator to reject one behaviorally invalid fixture."""

    result = run_node_validator_fixture(
        step, label, proof_files, home_files, extra_env
    )
    if result.returncode == 0:
        raise AssertionError(f"{label} accepted a behaviorally invalid proof fixture")


VALIDATOR_FIXTURE_COMMIT = "a" * 40
VALIDATOR_FIXTURE_LOCK = "b" * 64
VALIDATOR_HOME = "__VALIDATOR_HOME__"
VALIDATOR_PROOF = "__VALIDATOR_PROOF__"


def validator_mcp_entry(
    executable: str,
    *,
    repo: str | None = None,
    cwd: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict[str, object]:
    args = ["mcp", "start"]
    if repo is not None:
        args.extend(["--repo", repo])
    entry: dict[str, object] = {
        "command": executable,
        "args": args,
        "env": {
            **(extra_env or {}),
            "KIN_MCP_TOOL_PROFILE": "agent-default",
        },
    }
    if cwd is not None:
        entry["cwd"] = cwd
    return entry


def validator_mcp_config(entry: dict[str, object]) -> dict[str, object]:
    return {"mcpServers": {"kin": entry}}


def validator_windows_mcp_home_fixture() -> dict[str, object]:
    """Return every repo-free Windows JSON MCP config."""

    executable = f"{VALIDATOR_HOME}/.kin/bin/kin.exe"
    config = validator_mcp_config(validator_mcp_entry(executable))
    return {
        ".claude.json": copy.deepcopy(config),
        ".cursor/mcp.json": copy.deepcopy(config),
        ".gemini/settings.json": copy.deepcopy(config),
        ".codeium/windsurf/mcp_config.json": copy.deepcopy(config),
    }


def validator_unix_mcp_home_fixture() -> dict[str, object]:
    """Return every main-HOME Unix JSON MCP config."""

    executable = f"{VALIDATOR_HOME}/.kin/bin/kin"
    ordinary = validator_mcp_config(validator_mcp_entry(executable))
    repository = validator_mcp_config(
        validator_mcp_entry(
            executable,
            repo=VALIDATOR_PROOF,
            cwd=VALIDATOR_PROOF,
        )
    )
    legacy = copy.deepcopy(repository)
    legacy["userPolicy"] = "preserve"
    legacy["mcpServers"]["kin"]["env"]["USER_POLICY"] = "preserve"
    return {
        ".claude.json": copy.deepcopy(ordinary),
        ".cursor/mcp.json": copy.deepcopy(ordinary),
        ".gemini/settings.json": copy.deepcopy(ordinary),
        ".codeium/windsurf/mcp_config.json": copy.deepcopy(ordinary),
        ".gemini/config/mcp_config.json": copy.deepcopy(repository),
        ".gemini/antigravity-ide/mcp_config.json": legacy,
    }


HEALTH_JOIN_BEGIN = "// --- BEGIN HEALTH JOIN ---"
HEALTH_JOIN_END = "// --- END HEALTH JOIN ---"
# Every file carrying a copy of the health join. install-proof.yml and
# rc-build.yml run with no checkout and cannot import the module, so they paste
# it; `assert_health_join_copies_agree` requires the copies equal.
HEALTH_JOIN_HOMES = (
    "scripts/verify-capability-proof.mjs",
    ".github/workflows/install-proof.yml",
    ".github/workflows/rc-build.yml",
)


def health_join_verdict(statuses: dict[str, str]) -> str:
    """The product's roll-up rule, in Python, for building honest fixtures.

    A fourth copy, and deliberately so: a fixture generator that took the
    aggregate as an argument is what let this harness carry `healthy=True`
    beside `embedding_model: pending` and pass while the real Windows leg threw
    on that exact pair (FIR-2919). `assert_health_join_copies_agree` pins the
    three JavaScript copies to each other; this one is pinned by the fixtures it
    builds having to survive the extracted validators.
    """

    if any(
        status in {"missing", "misconfigured"}
        or (check_id == "semantic_query_readiness" and status == "stale")
        for check_id, status in statuses.items()
    ):
        return "failing"
    if any(
        status not in {"healthy", "unsupported"} for status in statuses.values()
    ):
        return "needs_attention"
    return "ready"


def validator_health_report(
    statuses: dict[str, str],
    *,
    healthy: bool | None = None,
    verdict: str | None = None,
) -> dict[str, object]:
    """A health report whose aggregate is derived from its own checks.

    `healthy` and `verdict` stay overridable because several probes below have
    to build a report that disagrees with itself. Nothing else may pass them.
    """

    joined = health_join_verdict(statuses)
    return {
        "healthy": joined == "ready" if healthy is None else healthy,
        "verdict": joined if verdict is None else verdict,
        "checks": [
            {"id": check_id, "status": status}
            for check_id, status in statuses.items()
        ],
    }


WINDOWS_REQUIRED_VALIDATOR_CHECKS = {
    "kin_binary": "healthy",
    "kin_daemon_binary": "healthy",
    "shell_path": "healthy",
    "setup_ledger": "healthy",
    "registry_authority": "unsupported",
    "vfs_projection": "unsupported",
    "semantic_query_readiness": "unsupported",
    "daemon_running": "unsupported",
    "repo_init": "unsupported",
    # Nothing recorded and nothing in force on a fresh repo-free install, so
    # there is no configured projection for the row to report on. Required
    # rather than tolerated: `misconfigured` here is what failed the real leg
    # on every release from v0.5.44 through v0.5.47.
    "projection_mode": "unsupported",
    "mcp_client_claude": "healthy",
    "mcp_client_cursor": "healthy",
    "mcp_client_gemini": "healthy",
    "mcp_client_windsurf": "healthy",
}
# The repo-free report carries checks the required map does not name, and
# omitting them here is how this harness kept passing while the real Windows
# leg threw on one of them. `retrieval_profile` is the case that did it: a
# fresh install has selected no profile and fetched no reranker model, which is
# a first-run state rather than a degraded serving configuration, and the leg's
# tolerance accepts it only as `unsupported`.
WINDOWS_VALIDATOR_CHECKS = {
    **WINDOWS_REQUIRED_VALIDATOR_CHECKS,
    "retrieval_profile": "unsupported",
    # The two first-run statuses the leg tolerates beyond healthy and
    # not-applicable. A public runner has never fetched the embedding model, so
    # a correct install reports `pending` there; the runner has 4 GiB and Kin
    # has no host-memory probe for target_os windows, so `memory_floor` reports
    # `degraded`. The step names each check with the status it may hold rather
    # than accepting those statuses generally. Carried in the fixture for the
    # reason `retrieval_profile` is: a fixture that omits a check the real
    # report carries cannot fail the way the real leg does.
    #
    # `memory_floor` is the proof of that sentence. It was absent here, the real
    # v0.6.1 Windows report carried it as `degraded`, and this harness passed
    # while that leg threw (FIR-2919).
    "embedding_model": "pending",
    "memory_floor": "degraded",
}


def windows_node_validator_fixture() -> tuple[
    dict[str, object], dict[str, object], dict[str, str]
]:
    """Build a complete valid repository-free Windows proof fixture."""

    report = validator_health_report(WINDOWS_VALIDATOR_CHECKS)
    return (
        {
            "expected-commit.txt": VALIDATOR_FIXTURE_COMMIT,
            "expected-lock-sha.txt": VALIDATOR_FIXTURE_LOCK,
            "installed-kin-command.txt": f"{VALIDATOR_HOME}/.kin/bin/kin.exe",
            "kin-windows-bench-meta.json": {
                "kin_commit": VALIDATOR_FIXTURE_COMMIT,
                "kin_dirty": False,
                "kin_source_known": True,
                "dependency_provenance": VALIDATOR_FIXTURE_LOCK,
                "embeddings": {
                    "vector_enabled": True,
                    "embeddings_enabled": True,
                    # Metal is the macOS-only compiled backend, not the marker
                    # cargo feature, so it stays false on a correct Windows build.
                    "metal_enabled": False,
                },
            },
            "kin-windows-registry-authority.json": {
                "checks": [{"state": "unsupported"}]
            },
            "kin-windows-health.json": copy.deepcopy(report),
            "kin-windows-doctor.json": copy.deepcopy(report),
        },
        validator_windows_mcp_home_fixture(),
        {"RUNNER_OS": "Windows"},
    )


UNIX_REQUIRED_VALIDATOR_CHECKS = {
    "kin_binary": "healthy",
    "kin_daemon_binary": "healthy",
    "daemon_running": "healthy",
    "repo_init": "healthy",
    "shell_path": "healthy",
    "setup_ledger": "healthy",
    "registry_authority": "healthy",
    "vfs_projection": "healthy",
    "mcp_client_claude": "healthy",
    "mcp_client_cursor": "healthy",
    "mcp_client_codex": "healthy",
    "mcp_client_gemini": "healthy",
    "mcp_client_windsurf": "healthy",
    "mcp_client_antigravity": "healthy",
    "mcp_client_antigravity_workspace": "healthy",
}
UNIX_VALIDATOR_CHECKS = {
    **UNIX_REQUIRED_VALIDATOR_CHECKS,
    "semantic_query_readiness": "stale",
    # Carried for the same reason the Windows fixture carries it: the real
    # report has it, the pre-embed tolerance reads every check rather than only
    # the named ones, and a fixture that omits it cannot fail the way the real
    # leg does. A fresh install has selected no profile and fetched no reranker
    # model, which is a first-run state and reports unsupported.
    "retrieval_profile": "unsupported",
}


def unix_node_validator_fixture() -> tuple[
    dict[str, object], dict[str, object], dict[str, str]
]:
    """Build a complete valid Unix release-byte proof fixture."""

    pre_embed_report = validator_health_report(UNIX_VALIDATOR_CHECKS)
    # The post-embed capture names the rows a completed embed leaves behind on
    # this runner, so the fixture carries them: `unsupported` must not move the
    # aggregate, and `memory_floor` degraded must not fail the leg. Carrying
    # both here is what makes those tested claims instead of assumed ones.
    embedded_report = validator_health_report(
        {
            "semantic_query_readiness": "healthy",
            "retrieval_profile": "unsupported",
            "memory_floor": "degraded",
        }
    )
    fallback_report = validator_health_report({"mcp_client_claude": "healthy"})
    executable = f"{VALIDATOR_HOME}/.kin/bin/kin"
    ordinary_config = validator_mcp_config(validator_mcp_entry(executable))
    repository_config = validator_mcp_config(
        validator_mcp_entry(
            executable,
            repo=VALIDATOR_PROOF,
            cwd=VALIDATOR_PROOF,
        )
    )
    codex_config = validator_mcp_config(
        validator_mcp_entry(executable, repo=VALIDATOR_PROOF)
    )
    return (
        {
            "../expected-commit.txt": VALIDATOR_FIXTURE_COMMIT,
            "../expected-lock-sha.txt": VALIDATOR_FIXTURE_LOCK,
            "../installed-kin-command.txt": executable,
            "kin-status.json": {
                "schema": "kin.status.v3",
                "embedding_coverage": {
                    "state": "unobserved",
                    "reason": "no_running_daemon",
                },
            },
            "kin-build-meta.json": {
                "schema": "kin.bench-meta.v2",
                "kin_commit": VALIDATOR_FIXTURE_COMMIT,
                "kin_dirty": False,
                "kin_source_known": True,
                "dependency_provenance": VALIDATOR_FIXTURE_LOCK,
                "embeddings": {
                    "vector_enabled": True,
                    "embeddings_enabled": True,
                },
            },
            "kin-daemon-health.json": {
                "build": {
                    "sha": VALIDATOR_FIXTURE_COMMIT,
                    "dirty": False,
                    "source_known": True,
                    "dependency_provenance": VALIDATOR_FIXTURE_LOCK,
                }
            },
            "kin-health.json": copy.deepcopy(pre_embed_report),
            "kin-doctor.json": copy.deepcopy(pre_embed_report),
            "kin-claude-fallback-health.json": copy.deepcopy(fallback_report),
            "kin-claude-fallback-doctor.json": copy.deepcopy(fallback_report),
            "kin-claude-fallback-config.json": copy.deepcopy(ordinary_config),
            "kin-codex-config.json": copy.deepcopy(codex_config),
            ".agents/mcp_config.json": copy.deepcopy(repository_config),
            "kin-search.json": [
                {"name": "hello", "file": "probe.py"}
            ],
            "kin-locate.json": {"files": [{"path": "probe.py"}]},
            "kin-embed.json": {
                "pending_entities": 0,
                "pending_artifacts": 0,
                "time_limited": False,
            },
            "kin-embedded-status.json": {
                "schema": "kin.status.v3",
                "embedding_coverage": {
                    "state": "observed",
                    "source": "live_query_graph",
                    "indexed": 2,
                    "pending": 0,
                    "total": 2,
                },
            },
            "kin-embedded-health.json": copy.deepcopy(embedded_report),
            "kin-embedded-doctor.json": copy.deepcopy(embedded_report),
            "kin-semantic-search.json": [
                {"name": "hello", "file": "probe.py"}
            ],
            "kin-semantic-locate.json": {
                "semantic_coverage": {"supported": True, "complete": True},
                "files": [{"path": "probe.py"}],
            },
        },
        validator_unix_mcp_home_fixture(),
        {"RUNNER_OS": "Linux"},
    )


def fixture_with_json_value(
    fixture: dict[str, object],
    path: str,
    keys: tuple[str | int, ...],
    value: object,
) -> dict[str, object]:
    """Deep-copy a fixture and replace one nested JSON value."""

    mutated = copy.deepcopy(fixture)
    cursor: object = mutated[path]
    for key in keys[:-1]:
        cursor = cursor[key]  # type: ignore[index]
    cursor[keys[-1]] = value  # type: ignore[index]
    return mutated



def fixture_with_derived_aggregate(
    fixture: dict[str, object], path: str
) -> dict[str, object]:
    """Re-derive one report's aggregate from the checks it now carries.

    Every arm that mutates a check and still expects the fixture accepted has to
    call this. Setting `healthy` by hand beside a mutated check is how a probe
    builds a report the product could not emit, and a validator that rejects it
    is right for the wrong reason (FIR-2919).
    """

    mutated = copy.deepcopy(fixture)
    report = mutated[path]
    statuses = {
        check["id"]: check["status"]  # type: ignore[index]
        for check in report["checks"]  # type: ignore[index]
    }
    verdict = health_join_verdict(statuses)
    report["healthy"] = verdict == "ready"  # type: ignore[index]
    report["verdict"] = verdict  # type: ignore[index]
    return mutated


def fixture_without_file(
    fixture: dict[str, object], path: str
) -> dict[str, object]:
    mutated = copy.deepcopy(fixture)
    del mutated[path]
    return mutated


def fixture_without_json_key(
    fixture: dict[str, object],
    path: str,
    keys: tuple[str | int, ...],
) -> dict[str, object]:
    """Deep-copy a fixture and remove one nested JSON key."""

    mutated = copy.deepcopy(fixture)
    cursor: object = mutated[path]
    for key in keys[:-1]:
        cursor = cursor[key]  # type: ignore[index]
    del cursor[keys[-1]]  # type: ignore[index]
    return mutated


def fixture_with_check_status(
    fixture: dict[str, object],
    path: str,
    check_id: str,
    status: str,
) -> dict[str, object]:
    """Deep-copy a health fixture and change exactly one named check."""

    mutated = copy.deepcopy(fixture)
    report = mutated[path]
    checks = report["checks"]  # type: ignore[index]
    matches = [check for check in checks if check["id"] == check_id]
    if len(matches) != 1:
        raise AssertionError(
            f"validator fixture must contain one {check_id!r} check in {path}: "
            f"{matches}"
        )
    matches[0]["status"] = status
    return mutated


def fixture_with_extra_check(
    fixture: dict[str, object],
    path: str,
    check_id: str,
    status: str,
) -> dict[str, object]:
    """Deep-copy a health fixture and append one unexpected check."""

    mutated = copy.deepcopy(fixture)
    report = mutated[path]
    report["checks"].append(  # type: ignore[index,union-attr]
        {"id": check_id, "status": status}
    )
    return mutated


def fixture_with_duplicate_check(
    fixture: dict[str, object],
    path: str,
    check_id: str,
    status: str,
) -> dict[str, object]:
    """Insert a contradictory check before the authoritative fixture entry."""

    mutated = copy.deepcopy(fixture)
    report = mutated[path]
    checks = report["checks"]  # type: ignore[index]
    indexes = [index for index, check in enumerate(checks) if check["id"] == check_id]
    if len(indexes) != 1:
        raise AssertionError(
            f"validator fixture must contain one {check_id!r} check in {path}: "
            f"{indexes}"
        )
    checks.insert(indexes[0], {"id": check_id, "status": status})
    return mutated


def wrong_required_check_status(expected: str) -> str:
    """Choose a mismatch that preserves generic readiness/failure semantics."""

    if expected == "healthy":
        return "unsupported"
    if expected == "unsupported":
        return "healthy"
    if expected == "missing":
        return "misconfigured"
    raise AssertionError(f"no isolated required-check mutation for {expected!r}")


def assert_windows_node_validator_behavior(step: str) -> None:
    """Behaviorally pin every substantive Windows validator obligation."""

    proof, home, environment = windows_node_validator_fixture()
    label = "repo-free Windows install proof"
    assert_node_validator_accepts_fixture(step, label, proof, home, environment)

    def reject(
        case: str,
        invalid_proof: dict[str, object] | None = None,
        invalid_home: dict[str, object] | None = None,
    ) -> None:
        assert_node_validator_rejects_fixture(
            step,
            f"{label} ({case})",
            invalid_proof if invalid_proof is not None else proof,
            invalid_home if invalid_home is not None else home,
            environment,
        )

    # Every proof and home input is independently load-bearing on the valid path.
    for path in proof:
        reject(f"missing {path}", fixture_without_file(proof, path))
    for path in home:
        reject(f"missing home/{path}", invalid_home=fixture_without_file(home, path))

    for case, path, keys, value in (
        (
            "installed commit mismatch",
            "kin-windows-bench-meta.json",
            ("kin_commit",),
            "c" * 40,
        ),
        (
            "dirty installed build",
            "kin-windows-bench-meta.json",
            ("kin_dirty",),
            True,
        ),
        (
            "unknown installed source",
            "kin-windows-bench-meta.json",
            ("kin_source_known",),
            False,
        ),
        (
            "lock provenance mismatch",
            "kin-windows-bench-meta.json",
            ("dependency_provenance",),
            "d" * 64,
        ),
        (
            "vector feature disabled",
            "kin-windows-bench-meta.json",
            ("embeddings", "vector_enabled"),
            False,
        ),
        (
            "embedding feature disabled",
            "kin-windows-bench-meta.json",
            ("embeddings", "embeddings_enabled"),
            False,
        ),
        # Metal stays a negative control in the same direction: it is the
        # macOS-only compiled backend, so a Windows archive claiming it is
        # still the defect this rejects.
        (
            "Metal feature enabled",
            "kin-windows-bench-meta.json",
            ("embeddings", "metal_enabled"),
            True,
        ),
        (
            "registry authority falsely healthy",
            "kin-windows-registry-authority.json",
            ("checks", 0, "state"),
            "healthy",
        ),
    ):
        reject(case, fixture_with_json_value(proof, path, keys, value))

    reject(
        "registry authority reports more than one capability",
        fixture_with_json_value(
            proof,
            "kin-windows-registry-authority.json",
            ("checks",),
            [{"state": "unsupported"}, {"state": "unsupported"}],
        ),
    )

    # Every named repo-free posture is checked independently in both reports.
    # The wrong value deliberately preserves the generic aggregate and hard-
    # failure predicates, leaving only the required-map comparison able to
    # reject it.
    for report_path in ("kin-windows-health.json", "kin-windows-doctor.json"):
        for check_id, expected in WINDOWS_REQUIRED_VALIDATOR_CHECKS.items():
            wrong = wrong_required_check_status(expected)
            reject(
                f"{report_path} required {check_id}={wrong}",
                fixture_with_check_status(proof, report_path, check_id, wrong),
            )
        # A retrieval profile that is genuinely degraded, meaning levers off on
        # a configuration this install chose rather than levers it has never
        # had, is not tolerated by the repo-free posture. This is the arm that
        # keeps the accepted `unsupported` above from being a blanket pass on
        # anything this check reports.
        reject(
            f"{report_path} degraded retrieval profile",
            fixture_with_check_status(proof, report_path, "retrieval_profile", "stale"),
        )
        # The first-run pending tolerance is one check and one status, not a
        # standing pass for `pending`. These two arms are what say so: the
        # named check may not drift to another non-healthy status, and no other
        # check may borrow the tolerance by going pending itself. Both preserve
        # the aggregate and hard-failure predicates, so only the tolerance
        # sweep can reject them.
        reject(
            f"{report_path} embedding model drifts off pending",
            fixture_with_check_status(proof, report_path, "embedding_model", "stale"),
        )
        reject(
            f"{report_path} a second check borrows the pending tolerance",
            fixture_with_check_status(
                proof, report_path, "retrieval_profile", "pending"
            ),
        )
        reject(
            f"{report_path} contradictory duplicate check",
            fixture_with_duplicate_check(
                proof, report_path, "kin_binary", "unsupported"
            ),
        )
        # The overclaim itself, in the shape it shipped. A fresh repo-free
        # install carries a pending row and a degraded row, so its honest
        # aggregate is `healthy: false` with `verdict: needs_attention`. The
        # v0.6.1 Windows binary emitted `true` over exactly those rows; the
        # first arm is that report and it must be refused. The second is the
        # aggregate agreeing while the verdict does not, which no build should
        # be able to emit and which the validator must catch on its own rather
        # than by inference from the boolean.
        reject(
            f"{report_path} inconsistent healthy aggregate",
            fixture_with_json_value(proof, report_path, ("healthy",), True),
        )
        reject(
            f"{report_path} inconsistent verdict",
            fixture_with_json_value(proof, report_path, ("verdict",), "ready"),
        )
        reject(
            f"{report_path} verdict absent, as pre-FIR-2919 bytes emit",
            fixture_without_json_key(proof, report_path, ("verdict",)),
        )
        reject(
            f"{report_path} unexpected hard failure",
            fixture_with_extra_check(proof, report_path, "unexpected", "missing"),
        )
        for repo_bound_id in (
            "mcp_client_codex",
            "mcp_client_antigravity",
            "mcp_client_antigravity_workspace",
        ):
            reject(
                f"{report_path} repo-bound {repo_bound_id} writer appears",
                fixture_with_extra_check(
                    proof, report_path, repo_bound_id, "healthy"
                ),
            )

    for config_path in home:
        reject(
            f"{config_path} MCP command missing",
            invalid_home=fixture_without_json_key(
                home, config_path, ("mcpServers", "kin", "command")
            ),
        )
        reject(
            f"{config_path} MCP command drift",
            invalid_home=fixture_with_json_value(
                home,
                config_path,
                ("mcpServers", "kin", "command"),
                "/wrong/kin",
            ),
        )
        # FIR-2293, named as its own class rather than left to the drift case
        # above. `kin setup` recorded the MCP command by joining onto whatever
        # `KIN_HOME` held, and MSYS bash hands it a forward-slashed `$HOME`, so
        # a Windows install wrote `C:/Users/u/.kin\bin\kin.exe` against an
        # installed launcher of `C:\Users\u\.kin\bin\kin.exe`. Windows opens
        # both, so only a byte comparison against the installed launcher can
        # tell them apart, and this arm is what keeps that able to fail.
        reject(
            f"{config_path} MCP command mixes path separators",
            invalid_home=fixture_with_json_value(
                home,
                config_path,
                ("mcpServers", "kin", "command"),
                f"{VALIDATOR_HOME}/.kin\\bin\\kin.exe",
            ),
        )
        reject(
            f"{config_path} MCP args drift",
            invalid_home=fixture_with_json_value(
                home,
                config_path,
                ("mcpServers", "kin", "args"),
                ["mcp", "start", "--repo", "."],
            ),
        )
        reject(
            f"{config_path} MCP profile drift",
            invalid_home=fixture_with_json_value(
                home,
                config_path,
                ("mcpServers", "kin", "env", "KIN_MCP_TOOL_PROFILE"),
                "full",
            ),
        )

    for forbidden_path in (
        ".gemini/config/mcp_config.json",
        ".gemini/antigravity-ide/mcp_config.json",
    ):
        unexpected_home = copy.deepcopy(home)
        unexpected_home[forbidden_path] = validator_mcp_config(
            validator_mcp_entry(f"{VALIDATOR_HOME}/.kin/bin/kin.exe")
        )
        reject(
            f"repo-free Windows wrote {forbidden_path}",
            invalid_home=unexpected_home,
        )


def assert_unix_node_validator_behavior(step: str) -> None:
    """Behaviorally pin every substantive Unix validator obligation."""

    proof, home, environment = unix_node_validator_fixture()
    label = "released-byte Unix install proof"
    assert_node_validator_accepts_fixture(step, label, proof, home, environment)

    def reject(
        case: str,
        invalid_proof: dict[str, object] | None = None,
        invalid_home: dict[str, object] | None = None,
    ) -> None:
        assert_node_validator_rejects_fixture(
            step,
            f"{label} ({case})",
            invalid_proof if invalid_proof is not None else proof,
            invalid_home if invalid_home is not None else home,
            environment,
        )

    # Removing each input independently proves the complete success path reads it.
    for path in proof:
        reject(f"missing {path}", fixture_without_file(proof, path))
    for path in home:
        reject(f"missing home/{path}", invalid_home=fixture_without_file(home, path))

    malformed_commit = copy.deepcopy(proof)
    malformed_commit["../expected-commit.txt"] = "bad"
    malformed_commit = fixture_with_json_value(
        malformed_commit, "kin-build-meta.json", ("kin_commit",), "bad"
    )
    malformed_commit = fixture_with_json_value(
        malformed_commit, "kin-daemon-health.json", ("build", "sha"), "bad"
    )
    reject("matching but malformed build commits", malformed_commit)

    malformed_lock = copy.deepcopy(proof)
    malformed_lock["../expected-lock-sha.txt"] = "bad"
    malformed_lock = fixture_with_json_value(
        malformed_lock, "kin-build-meta.json", ("dependency_provenance",), "bad"
    )
    malformed_lock = fixture_with_json_value(
        malformed_lock,
        "kin-daemon-health.json",
        ("build", "dependency_provenance"),
        "bad",
    )
    reject("matching but malformed lock provenance", malformed_lock)

    for case, path, keys, value in (
        (
            "CLI schema drift",
            "kin-build-meta.json",
            ("schema",),
            "kin.bench-meta.v1",
        ),
        (
            "CLI commit mismatch",
            "kin-build-meta.json",
            ("kin_commit",),
            "c" * 40,
        ),
        (
            "CLI dirty build",
            "kin-build-meta.json",
            ("kin_dirty",),
            True,
        ),
        (
            "CLI unknown source",
            "kin-build-meta.json",
            ("kin_source_known",),
            False,
        ),
        (
            "CLI lock mismatch",
            "kin-build-meta.json",
            ("dependency_provenance",),
            "d" * 64,
        ),
        (
            "daemon commit mismatch",
            "kin-daemon-health.json",
            ("build", "sha"),
            "c" * 40,
        ),
        (
            "daemon dirty build",
            "kin-daemon-health.json",
            ("build", "dirty"),
            True,
        ),
        (
            "daemon unknown source",
            "kin-daemon-health.json",
            ("build", "source_known"),
            False,
        ),
        (
            "daemon lock mismatch",
            "kin-daemon-health.json",
            ("build", "dependency_provenance"),
            "d" * 64,
        ),
        (
            "status schema drift",
            "kin-status.json",
            ("schema",),
            "kin.status.v2",
        ),
        (
            "vector feature absent",
            "kin-build-meta.json",
            ("embeddings", "vector_enabled"),
            False,
        ),
        (
            "embedding feature absent",
            "kin-build-meta.json",
            ("embeddings", "embeddings_enabled"),
            False,
        ),
        (
            "lexical search misses entity",
            "kin-search.json",
            (0, "name"),
            "other",
        ),
        (
            "locate misses artifact",
            "kin-locate.json",
            ("files", 0, "path"),
            "other.py",
        ),
        (
            "pending entities remain",
            "kin-embed.json",
            ("pending_entities",),
            1,
        ),
        (
            "pending artifacts remain",
            "kin-embed.json",
            ("pending_artifacts",),
            1,
        ),
        (
            "embedding is time limited",
            "kin-embed.json",
            ("time_limited",),
            True,
        ),
        (
            "embedded status schema drift",
            "kin-embedded-status.json",
            ("schema",),
            "kin.status.v2",
        ),
        (
            "embedded coverage unobserved",
            "kin-embedded-status.json",
            ("embedding_coverage",),
            {"state": "unobserved", "reason": "missing"},
        ),
        (
            "embedded coverage has wrong source",
            "kin-embedded-status.json",
            ("embedding_coverage", "source"),
            "snapshot",
        ),
        (
            "embedded coverage has zero total",
            "kin-embedded-status.json",
            ("embedding_coverage", "total"),
            0,
        ),
        (
            "embedded coverage incomplete",
            "kin-embedded-status.json",
            ("embedding_coverage",),
            {
                "state": "observed",
                "source": "live_query_graph",
                "indexed": 1,
                "pending": 1,
                "total": 2,
            },
        ),
        (
            "embedded coverage still pending",
            "kin-embedded-status.json",
            ("embedding_coverage", "pending"),
            1,
        ),
        (
            "semantic search misses entity",
            "kin-semantic-search.json",
            (0, "name"),
            "other",
        ),
        (
            "semantic locate unsupported",
            "kin-semantic-locate.json",
            ("semantic_coverage", "supported"),
            False,
        ),
        (
            "semantic locate incomplete",
            "kin-semantic-locate.json",
            ("semantic_coverage", "complete"),
            False,
        ),
        (
            "semantic locate misses artifact",
            "kin-semantic-locate.json",
            ("files", 0, "path"),
            "other.py",
        ),
    ):
        reject(case, fixture_with_json_value(proof, path, keys, value))

    reject(
        "pre-embed coverage missing",
        fixture_without_json_key(
            proof, "kin-status.json", ("embedding_coverage",)
        ),
    )
    reject(
        "pre-embed coverage malformed",
        fixture_with_json_value(
            proof, "kin-status.json", ("embedding_coverage",), []
        ),
    )
    reject(
        "pre-embed coverage has unknown state",
        fixture_with_json_value(
            proof,
            "kin-status.json",
            ("embedding_coverage", "state"),
            "unknown",
        ),
    )
    reject(
        "unobserved coverage has no reason",
        fixture_with_json_value(
            proof,
            "kin-status.json",
            ("embedding_coverage", "reason"),
            "",
        ),
    )
    reject(
        "unobserved coverage leaks counts",
        fixture_with_json_value(
            proof,
            "kin-status.json",
            ("embedding_coverage", "indexed"),
            0,
        ),
    )
    reject(
        "unobserved coverage leaks source",
        fixture_with_json_value(
            proof,
            "kin-status.json",
            ("embedding_coverage", "source"),
            "live_query_graph",
        ),
    )
    observed_pre_embed = fixture_with_json_value(
        proof,
        "kin-status.json",
        ("embedding_coverage",),
        {
            "state": "observed",
            "source": "live_query_graph",
            "indexed": 0,
            "pending": 2,
            "total": 2,
        },
    )
    assert_node_validator_accepts_fixture(
        step,
        f"{label} (observed pre-embed coverage)",
        observed_pre_embed,
        home,
        environment,
    )
    for case, keys, value in (
        ("observed coverage wrong source", ("source",), "snapshot"),
        ("observed coverage negative count", ("indexed",), -1),
        ("observed coverage carries reason", ("reason",), "stale"),
        ("observed coverage indexed exceeds total", ("indexed",), 3),
        ("observed coverage pending undercounts gap", ("pending",), 1),
    ):
        reject(
            case,
            fixture_with_json_value(
                observed_pre_embed,
                "kin-status.json",
                ("embedding_coverage", *keys),
                value,
            ),
        )

    for report_path in ("kin-health.json", "kin-doctor.json"):
        for check_id, expected in UNIX_REQUIRED_VALIDATOR_CHECKS.items():
            wrong = wrong_required_check_status(expected)
            reject(
                f"{report_path} required {check_id}={wrong}",
                fixture_with_check_status(proof, report_path, check_id, wrong),
            )
        # The pre-embed tolerance accepts an aggregate held false by pending
        # embeddings only while every OTHER check is healthy or unsupported, so
        # a genuinely degraded retrieval profile still closes it. That is what
        # refused v0.5.7 on this leg, and it is why the accepted `unsupported`
        # above is a real answer rather than a hole in the fixture.
        reject(
            f"{report_path} degraded retrieval profile",
            fixture_with_check_status(proof, report_path, "retrieval_profile", "stale"),
        )
        reject(
            f"{report_path} contradictory duplicate check",
            fixture_with_duplicate_check(
                proof, report_path, "kin_binary", "unsupported"
            ),
        )
        reject(
            f"{report_path} inconsistent healthy aggregate",
            fixture_with_json_value(proof, report_path, ("healthy",), True),
        )

        reject(
            f"{report_path} inconsistent verdict",
            fixture_with_json_value(proof, report_path, ("verdict",), "ready"),
        )
        reject(
            f"{report_path} verdict absent, as pre-FIR-2919 bytes emit",
            fixture_without_json_key(proof, report_path, ("verdict",)),
        )
        # A row that needs attention and is not one this posture named. The
        # aggregate is re-derived, so the fixture is a report the product could
        # actually emit and only the tolerance sweep can refuse it.
        reject(
            f"{report_path} an unnamed row needs attention",
            fixture_with_derived_aggregate(
                fixture_with_extra_check(
                    proof, report_path, "kinlab_connect", "degraded"
                ),
                report_path,
            ),
        )

        healthy_readiness = fixture_with_derived_aggregate(
            fixture_with_check_status(
                proof, report_path, "semantic_query_readiness", "healthy"
            ),
            report_path,
        )
        assert_node_validator_accepts_fixture(
            step,
            f"{label} ({report_path} already semantically ready)",
            healthy_readiness,
            home,
            environment,
        )

        unsupported_readiness = fixture_with_derived_aggregate(
            fixture_with_check_status(
                proof, report_path, "semantic_query_readiness", "unsupported"
            ),
            report_path,
        )
        reject(
            f"{report_path} semantic readiness unsupported",
            unsupported_readiness,
        )

    for report_path in ("kin-embedded-health.json", "kin-embedded-doctor.json"):
        # The post-embed capture carries `memory_floor: degraded`, so its honest
        # aggregate is already false. The overclaim is the true one.
        reject(
            f"{report_path} inconsistent healthy aggregate",
            fixture_with_json_value(proof, report_path, ("healthy",), True),
        )
        reject(
            f"{report_path} verdict absent, as pre-FIR-2919 bytes emit",
            fixture_without_json_key(proof, report_path, ("verdict",)),
        )
        reject(
            f"{report_path} an unnamed row needs attention after the embed",
            fixture_with_derived_aggregate(
                fixture_with_extra_check(
                    proof, report_path, "kinlab_connect", "pending"
                ),
                report_path,
            ),
        )
        reject(
            f"{report_path} contradictory duplicate check",
            fixture_with_duplicate_check(
                proof, report_path, "semantic_query_readiness", "unsupported"
            ),
        )
        unsupported_readiness = fixture_with_check_status(
            proof, report_path, "semantic_query_readiness", "unsupported"
        )
        reject(
            f"{report_path} semantic readiness unsupported",
            unsupported_readiness,
        )

    for report_path in (
        "kin-claude-fallback-health.json",
        "kin-claude-fallback-doctor.json",
    ):
        reject(
            f"{report_path} Claude fallback not healthy",
            fixture_with_check_status(
                proof, report_path, "mcp_client_claude", "unsupported"
            ),
        )
        reject(
            f"{report_path} contradictory duplicate check",
            fixture_with_duplicate_check(
                proof, report_path, "mcp_client_claude", "misconfigured"
            ),
        )
        reject(
            f"{report_path} inconsistent healthy aggregate",
            fixture_with_json_value(proof, report_path, ("healthy",), False),
        )
        reject(
            f"{report_path} leaks a non-Claude global client",
            fixture_with_extra_check(
                proof, report_path, "mcp_client_cursor", "healthy"
            ),
        )

    for config_path in home:
        reject(
            f"{config_path} MCP command missing",
            invalid_home=fixture_without_json_key(
                home, config_path, ("mcpServers", "kin", "command")
            ),
        )
        reject(
            f"{config_path} MCP command drift",
            invalid_home=fixture_with_json_value(
                home,
                config_path,
                ("mcpServers", "kin", "command"),
                "/wrong/kin",
            ),
        )
        reject(
            f"{config_path} MCP args drift",
            invalid_home=fixture_with_json_value(
                home,
                config_path,
                ("mcpServers", "kin", "args"),
                ["mcp", "start", "--repo", "."],
            ),
        )
        reject(
            f"{config_path} MCP profile drift",
            invalid_home=fixture_with_json_value(
                home,
                config_path,
                ("mcpServers", "kin", "env", "KIN_MCP_TOOL_PROFILE"),
                "full",
            ),
        )
        entry = home[config_path]["mcpServers"]["kin"]  # type: ignore[index]
        if "cwd" in entry:
            reject(
                f"{config_path} MCP cwd drift",
                invalid_home=fixture_with_json_value(
                    home,
                    config_path,
                    ("mcpServers", "kin", "cwd"),
                    "/wrong/repo",
                ),
            )

    for config_path in (
        "kin-claude-fallback-config.json",
        "kin-codex-config.json",
        ".agents/mcp_config.json",
    ):
        reject(
            f"{config_path} MCP command missing",
            fixture_without_json_key(
                proof, config_path, ("mcpServers", "kin", "command")
            ),
        )
        reject(
            f"{config_path} MCP command drift",
            fixture_with_json_value(
                proof,
                config_path,
                ("mcpServers", "kin", "command"),
                "/wrong/kin",
            ),
        )
        reject(
            f"{config_path} MCP args drift",
            fixture_with_json_value(
                proof,
                config_path,
                ("mcpServers", "kin", "args"),
                ["mcp", "start", "--repo", "/wrong/repo"],
            ),
        )
        reject(
            f"{config_path} MCP profile drift",
            fixture_with_json_value(
                proof,
                config_path,
                ("mcpServers", "kin", "env", "KIN_MCP_TOOL_PROFILE"),
                "full",
            ),
        )
        entry = proof[config_path]["mcpServers"]["kin"]  # type: ignore[index]
        if "cwd" in entry:
            reject(
                f"{config_path} MCP cwd drift",
                fixture_with_json_value(
                    proof,
                    config_path,
                    ("mcpServers", "kin", "cwd"),
                    "/wrong/repo",
                ),
            )

    reject(
        "Antigravity legacy top-level policy drift",
        invalid_home=fixture_with_json_value(
            home,
            ".gemini/antigravity-ide/mcp_config.json",
            ("userPolicy",),
            "lost",
        ),
    )
    reject(
        "Antigravity legacy entry policy drift",
        invalid_home=fixture_with_json_value(
            home,
            ".gemini/antigravity-ide/mcp_config.json",
            ("mcpServers", "kin", "env", "USER_POLICY"),
            "lost",
        ),
    )


def assert_node_validator_rejects_missing_proof(step: str, label: str) -> None:
    """Execute the shipped validator and require incomplete proof trees to fail.

    Token checks explain which contract drifted, but cannot prove those tokens
    remain reachable. Running the extracted program against a deliberately
    absent evidence tree catches whole-validator no-ops. Running it again after
    seeding only the first expected-commit input gets beyond that first read and
    catches a false branch or early exit around every substantive validation.
    Both controls fail for runtime behavior rather than one enumerated syntax.
    """

    script = node_heredoc_body(step, label)
    try:
        syntax = subprocess.run(
            ["node", "--check", "-"],
            input=script,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AssertionError(f"{label} could not parse under Node: {error}") from error
    if syntax.returncode != 0:
        raise AssertionError(
            f"{label} is not valid Node source: {syntax.stderr.strip()}"
        )
    expected_commit_reads = re.findall(
        r'const expectedCommit = fs\.readFileSync\("([^"]+)", "utf8"\)\.trim\(\);',
        script,
    )
    if len(expected_commit_reads) != 1:
        raise AssertionError(
            f"{label} must read exactly one expected-commit proof input: "
            f"{expected_commit_reads}"
        )

    with tempfile.TemporaryDirectory(prefix="kin-proof-validator-") as temporary:
        temporary_root = Path(temporary).resolve()
        proof_dir = temporary_root / "proof"
        proof_dir.mkdir()

        def require_runtime_rejection(scenario: str) -> None:
            try:
                result = subprocess.run(
                    ["node", "-"],
                    input=script,
                    cwd=proof_dir,
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise AssertionError(
                    f"{label} could not execute under Node for {scenario}: {error}"
                ) from error
            if result.returncode == 0:
                raise AssertionError(
                    f"{label} accepted {scenario}; the validator is not "
                    "runtime-falsifiable"
                )

        require_runtime_rejection("an empty proof tree")

        expected_commit_path = (proof_dir / expected_commit_reads[0]).resolve()
        try:
            expected_commit_path.relative_to(temporary_root)
        except ValueError as error:
            raise AssertionError(
                f"{label} expected-commit input escapes its isolated proof tree: "
                f"{expected_commit_reads[0]!r}"
            ) from error
        expected_commit_path.parent.mkdir(parents=True, exist_ok=True)
        expected_commit_path.write_text("0" * 40 + "\n", encoding="utf-8")
        require_runtime_rejection("an expected-commit-only proof tree")


def windows_init_contract_strings() -> dict[str, str]:
    """Return wording shared by both Windows admission proofs.

    The install proof installs a public release anonymously and has no
    checkout, so it cannot run the contract script and retypes these instead.
    Reading the script here is the only thing that keeps the two statements of
    one contract from drifting apart.
    """

    source = WINDOWS_INIT_CONTRACT.read_text(encoding="utf-8")
    strings: dict[str, str] = {}
    for name in ("NON_EMPTY_REFUSAL",):
        bindings = re.findall(rf'(?m)^{name}="([^"]+)"$', source)
        if len(bindings) != 1:
            raise AssertionError(
                f"{WINDOWS_INIT_CONTRACT_POLICY} must bind {name} exactly once: "
                f"{bindings}"
            )
        strings[name] = bindings[0]
    return strings


def windows_public_support_notice(install_ps1: str) -> str:
    """Read the one public capability statement every Windows surface repeats.

    `scripts/assert-windows-init-contract.sh` used to bind this notice, back
    when the whole subject of that contract was that native Windows refused
    every repository. The contract now proves the opposite: both admission
    boundaries `require_admitted`, and only a non-empty native directory is
    refused. It binds no notice at all any more, so the installer's single
    `$NativeWindowsSupportNotice` literal is the owner. That is the copy a
    Windows user reads before anything is downloaded, and the copy that went
    stale in public.
    """

    bindings = re.findall(
        r'(?m)^\$NativeWindowsSupportNotice = "([^"]+)"$', install_ps1
    )
    if len(bindings) != 1:
        raise AssertionError(
            f"{INSTALL_PS1_POLICY} must bind $NativeWindowsSupportNotice "
            f"exactly once: {bindings}"
        )
    notice = bindings[0]
    for truth in (
        "Native Windows x86_64 support is early",
        "Repository admission works",
        "kin init imports a Git repository and publishes graph authority",
        "Transparent filesystem projection is not shipped on Windows",
        "does not yet cover MCP or review workflows",
        "WSL2 remains the recommended path",
    ):
        if truth not in notice:
            raise AssertionError(
                "Windows public support notice no longer states the executable "
                f"admission contract: missing {truth!r}"
            )
    return notice


def windows_public_support_doc_notice(notice: str) -> str:
    """Render the installer's notice the way prose surfaces carry it.

    Markdown and `llms.txt` copies code-format the command and drop the
    installer-only autocrlf recovery sentence, which is advice for a command
    that already failed rather than a capability claim. Deriving both
    renderings from the one binding is what keeps a single owner: editing
    either rendering alone still fails the exactly-once rule below.
    """

    doc = notice.split(WINDOWS_NOTICE_INSTALLER_TAIL)[0]
    if doc == notice:
        raise AssertionError(
            f"{INSTALL_PS1_POLICY} notice must keep its autocrlf recovery "
            "sentence, which marks where the prose rendering ends: "
            f"missing {WINDOWS_NOTICE_INSTALLER_TAIL!r}"
        )
    return doc.replace("kin init", "`kin init`")


def assert_windows_public_support_contract(
    contract_source: str,
    install_ps1: str,
    public_surfaces: dict[Path, str],
    compatibility_mcp_readme: str,
) -> None:
    """Keep every install surface inside the native-Windows admission boundary.

    The required Windows jobs prove what native Windows actually admits. This
    public notice is therefore owned by one binding rather than by independent
    prose on each surface. Each shipped installer/doc/package copy must be
    exact, and capability claims the contract disproves are forbidden even
    where the exact notice survives elsewhere in the same file.
    """

    notice = windows_public_support_notice(install_ps1)
    doc_notice = windows_public_support_doc_notice(notice)
    contract_active = "\n".join(active_lines(contract_source))
    for admission in (
        'require_admitted "Windows exact-Git admission"',
        'require_admitted "Windows native-unborn bootstrap"',
        "require_non_empty_refused",
        '"Windows non-empty native boundary"',
        'fail "$label unexpectedly succeeded" "$log"',
    ):
        require(
            contract_active,
            admission,
            "public Windows support notice tied to executable admission",
        )

    install_active = "\n".join(active_lines(install_ps1))
    installer_count = install_active.count(notice)
    if installer_count != 1:
        raise AssertionError(
            f"{INSTALL_PS1_POLICY} must carry the Windows support notice "
            f"exactly once; found {installer_count}"
        )
    for path, source in public_surfaces.items():
        count = "\n".join(active_lines(source)).count(doc_notice)
        if count != 1:
            raise AssertionError(
                f"{path.relative_to(ROOT)} must repeat the Windows support notice "
                f"from {INSTALL_PS1_POLICY} exactly once; found {count}"
            )

    all_surfaces = {INSTALL_PS1: install_ps1, **public_surfaces}
    normalized = " ".join(
        "\n".join([*all_surfaces.values(), compatibility_mcp_readme]).lower().split()
    )
    for stale_claim in (
        # Refusal-era claims. Native Windows admits repositories now, so each
        # of these understates the shipped product; the first three are the
        # v0.5.3 installer wording that stayed live on the public endpoint
        # after the notice itself was corrected.
        "repository admission is currently unavailable",
        "kin init fails closed",
        "graph, lexical, daemon, repository setup, mcp, and review workflows are unsupported",
        "use wsl2 for usable kin repositories",
        "native windows cannot admit a kin repository",
        "native windows cannot currently admit a repository",
        "while admission is unsupported",
        # Overclaims in the other direction. Projection is not shipped on
        # Windows and the install proof still does not cover MCP or review
        # there, so these remain forbidden.
        "native windows is a supported vector-free subset",
        "native windows build is a supported vector-free runtime",
        "native windows supports graph + lexical workflows",
        "supported for graph, lexical retrieval, daemon, setup, mcp",
        "it ships the supported vector-free runtime",
        "the graph, lexical, daemon, setup, and mcp surfaces are release-tested",
    ):
        if stale_claim in normalized:
            raise AssertionError(
                "public native-Windows surface contradicts the executable "
                f"admission contract: found stale claim {stale_claim!r}"
            )

    if re.search(r'(?m)^\s*"ARM64"\s*\{\s*return\b', install_ps1):
        raise AssertionError(
            "PowerShell installer must never resolve native ARM64 to a release "
            "archive; only windows-x86_64 is published"
        )
    for policy in (
        '$NativeWindowsSupportNotice = "' + notice + '"',
        'Write-Host "  ! $NativeWindowsSupportNotice"',
        "function Resolve-KinWindowsArchiveArchitecture",
        '"AMD64" { return "x86_64" }',
        '"ARM64" { throw "No native Windows ARM64 archive is published.',
        "Not running repository setup: MCP and review workflows are not yet "
        "covered on native Windows.",
    ):
        require(install_active, policy, "truthful native-Windows installer")
    if "windows-aarch64" in install_ps1:
        raise AssertionError(
            "PowerShell installer fabricates the nonexistent windows-aarch64 archive"
        )
    if "& $KinExe setup" in install_active:
        raise AssertionError(
            "native-Windows installer must not configure MCP/review workflows "
            "the install proof does not yet cover there"
        )

    for policy in (
        "- macOS, Linux, or native Windows x64",
        "Use WSL2 when you need projection.",
    ):
        require(
            compatibility_mcp_readme,
            policy,
            "compatibility MCP package native-Windows boundary",
        )

    quickstart_active = "\n".join(active_lines(public_surfaces[QUICKSTART_DOC]))
    for policy in (
        "on macOS and Linux, skip the `kin setup` wizard",
        "Native Windows always skips repository setup because the install proof "
        "does not yet cover MCP or review workflows there",
        "`KIN_NO_SETUP` is accepted there only for CI compatibility",
        "On macOS and Linux, `kin setup` is the guided wizard the installer launches",
        "Native Windows does not launch repository setup",
    ):
        require(
            quickstart_active,
            policy,
            "quickstart platform-specific setup contract",
        )


def assert_windows_contract_stage_check_is_reachable(contract_source: str) -> None:
    """Keep the shipped contract's stage-residue check able to fail at all.

    Both admission paths stage into the PARENT of the directory they admit:
    `crates/kin-core/src/git_init.rs` derives the stage from the source's
    parent and `crates/kin-core/src/init.rs` from the working directory's. A
    stage count taken inside the admitted directory therefore reports zero for
    every input and passes whether or not admission cleaned up after itself.
    This script is a required Windows check on every pull request, so a form
    that cannot fail is worse here than no check at all: it reads as proof.
    """

    active = "\n".join(active_lines(contract_source))
    for policy in (
        'parent="$(dirname "$dir")"',
        "staged=\"$(count_matching \"$parent\" '.kin.init-*')\"",
        'if [ "$staged" != "0" ]; then',
    ):
        require(active, policy, "reachable Windows stage-leak check")


PROOF_CAPTURE_DIRECTORY = 'captures="$RUNNER_TEMP/kin-proof-captures"'
PROOF_CAPTURE_DIRECTORY_CREATE = 'mkdir -p "$captures"'


def assert_install_proof_init_log_authority(first_run: str) -> None:
    """Keep the install proof's own report files out of the worktree kin init admits.

    kin init proves the Git worktree exactly, repeats that proof immediately
    before publication, and repeats it again afterwards, refusing when the two
    differ. A report file written into that worktree therefore breaks admission
    twice over: it is an untracked non-ignored path, and an ignored one would
    still change size between the repeats. The same worktree stays under a
    watcher that admits new non-ignored files for the rest of the job, so the
    constraint outlives init and every later capture is held to it by
    `assert_install_proof_captures_stay_out_of_the_admitted_tree`.

    Pinning the capture lines is not enough on its own, because the property is
    about the whole span between entering that worktree and admitting it. Two
    mutations leave every pinned line in place and still break admission: an
    unrelated write into the worktree before init, and a second init that an
    exact-prefix count cannot see. So the span is closed-form and an `init` this
    function does not recognize is refused by name.
    """

    active = active_lines(first_run)
    admission = 'kin init > "$captures/kin-init.txt" 2>&1 || init_status=$?'
    bootstrap = (
        "git init -q && git config user.email ci@firelock.ai && git config user.name ci"
    )
    entry = "mkdir -p kin-install-proof && cd kin-install-proof"
    propagate = 'if [ "$init_status" -ne 0 ]; then exit "$init_status"; fi'
    # An `init` token anywhere in an active line, not a prefix of one:
    # `(cd sub && kin init)`, `eval kin init`, and `"$KIN" init` all admit a
    # worktree and none of them starts with `kin init`.
    init_token = re.compile(r"(?<![\w./-])init(?![\w-])")
    admissions = [
        line for line in active if init_token.search(line) and line != bootstrap
    ]
    if len(admissions) != 1:
        raise AssertionError(
            "install proof must invoke kin init exactly once in the first-run "
            f"step: {admissions}"
        )
    if admissions[0] != admission:
        raise AssertionError(
            "kin init must write its log outside the worktree it admits rather "
            f"than through a relative redirect or pipe: {admissions[0]}"
        )
    for policy in (
        entry,
        PROOF_CAPTURE_DIRECTORY,
        PROOF_CAPTURE_DIRECTORY_CREATE,
        propagate,
    ):
        if policy not in active:
            raise AssertionError(
                f"install-proof init log capture lost an active line: {policy}"
            )
    # kin's own exit status is propagated after admission. Reordering the
    # propagation above init leaves every pinned line present and reports the
    # status of whatever ran before it instead.
    order = [active.index(step) for step in (admission, propagate)]
    if order != sorted(order):
        raise AssertionError(
            "install-proof init log capture must admit, then propagate kin's "
            f"own exit status; found line order {order}"
        )
    # Nothing may write into the worktree between entering it and admitting it.
    # A line-presence check cannot see an inserted write, and an inserted write
    # is byte-for-byte the class that broke the v0.4.5 release proof.
    prelude = active[active.index(entry) + 1 : order[0]]
    committed_prelude = [
        bootstrap,
        "printf 'def hello():\\n    return 42\\n' > probe.py",
        'git add -A && git commit -qm "probe"',
        PROOF_CAPTURE_DIRECTORY,
        PROOF_CAPTURE_DIRECTORY_CREATE,
        "init_status=0",
    ]
    if prelude != committed_prelude:
        raise AssertionError(
            "only the committed Git bootstrap may run between entering the "
            f"worktree kin init admits and admitting it; found {prelude}"
        )


def assert_install_proof_captures_stay_out_of_the_admitted_tree(
    proof_steps: dict[str, str], restore: str, restore_position: tuple[int, int, int]
) -> None:
    """Keep every proof report out of the admitted tree until nothing measures it.

    The worktree the proof admits stays under a watcher for the rest of the job,
    so a report written into it becomes semantic corpus and the store the
    assertions read grows while they read it. That is not a hypothesis: a leg
    read complete coverage in health and 13 of 18 in locate one second later,
    and it fenced a release.

    A report is therefore captured under RUNNER_TEMP and restored afterwards. A
    presence check on the restore step cannot see the mutation that matters,
    which is one capture reverting to a relative path, so every report-shaped
    redirect, tee, and Node write in these steps is examined instead and a
    relative target is refused by name. The restore itself has to run after the
    last step that reads the store, before the validator that reads the files,
    and on failure as well, or a leg that dies early hands over no evidence at
    all.
    """

    # A bare filename with a report extension and no directory part: exactly
    # the shape a write into the admitted tree takes, and one no capture under
    # `"$captures/..."` can wear, so a match is the defect rather than a
    # candidate for it.
    in_tree_report = re.compile(r"[\w.\-]+\.(?:json|jsonl|txt|log)")
    writes = (
        re.compile(r"(?:^|\s)\d?>>?\s*(\S+)"),
        re.compile(r"\|\s*tee\s+(\S+)"),
        re.compile(r"(?:write|append)FileSync\(\s*\"([^\"]+)\""),
    )
    for step_name, step_source in proof_steps.items():
        for line in active_lines(step_source):
            for pattern in writes:
                for raw in pattern.findall(line):
                    if in_tree_report.fullmatch(raw.strip('"')):
                        raise AssertionError(
                            f"{step_name} writes a proof report into the "
                            f"admitted tree rather than the capture "
                            f"directory: {line}"
                        )

    restore_active = active_lines(restore)
    for policy in (
        PROOF_CAPTURE_DIRECTORY,
        'destination="$PWD/kin-install-proof"',
        'cp "$captures/$capture" "$destination/$capture"',
        'done < <(ls -1 "$captures")',
    ):
        if policy not in restore_active:
            raise AssertionError(
                f"install-proof capture restore lost an active line: {policy}"
            )
    if "if: always()" not in restore_active:
        raise AssertionError(
            "install-proof capture restore must run on failure too, or a leg "
            "that dies early uploads no captured evidence"
        )
    last_store_read, restore_start, validation_start = restore_position
    if not last_store_read < restore_start < validation_start:
        raise AssertionError(
            "install-proof captures must be restored after the last step that "
            "reads the store and before the step that reads the files; found "
            f"positions {restore_position}"
        )


def assert_install_proof_embedding_settles_before_measurement(embedding: str) -> None:
    """Require a bounded, counter-driven settle between the embed and its captures.

    An embedding pass reports on the work it took, and content that belongs in
    the corpus is admitted asynchronously around it, so coverage read straight
    afterwards can be a sample of a store still taking work on. Waiting is
    therefore mandatory, but only in the form that can fail: a sleep asserts a
    duration nobody measured, while a poll asserts the counters themselves and
    says which one never settled when its budget runs out.
    """

    active = active_lines(embedding)
    embed = 'kin embed --max-seconds 300 --json | tee "$captures/kin-embed.json"'
    settle = 'PROOF_CAPTURES="$captures" node <<\'NODE\''
    capture = (
        'kin status --json --wait-quiesce 60 | tee "$captures/kin-embedded-status.json"'
    )
    for policy in (embed, settle, capture):
        if policy not in active:
            raise AssertionError(
                f"install-proof embedding settle lost an active line: {policy}"
            )
    settle_body = "\n".join(active)
    for policy in (
        'coverage.state === "observed" &&',
        "coverage.total > 0 &&",
        "coverage.pending === 0 &&",
        "coverage.indexed === coverage.total",
        "drained && current === previous",
        "process.exit(1);",
    ):
        if policy not in settle_body:
            raise AssertionError(
                "install-proof embedding settle must poll the counters to "
                f"quiescence and fail on expiry: {policy}"
            )
    order = [active.index(step) for step in (embed, settle, capture)]
    if order != sorted(order):
        raise AssertionError(
            "install-proof must embed, then settle, then capture the status it "
            f"asserts on; found line order {order}"
        )
    for line in active:
        if re.fullmatch(r"sleep [\d.]+", line):
            raise AssertionError(
                "install-proof must settle on the counters rather than on a "
                f"duration nobody measured: {line}"
            )


INSTALL_PROOF_MATRIX_PATTERN = re.compile(
    r"^include: \$\{\{ fromJSON\(inputs\.local_artifact "
    r"&& '(?P<pull_request>\[.*?\])' \|\| '(?P<release>\[.*?\])'\) \}\}$"
)


def install_proof_matrix_rows(install_job: str) -> tuple[
    list[dict[str, object]], list[dict[str, object]]
]:
    """Decode both reviewed install-proof matrices from their one expression.

    The release matrix is the default and the pull-request matrix is the
    override, and the job carries exactly one line that can produce either.
    Decoding it here is what lets the posture assertions below judge rows
    rather than YAML text, so neither list can gain a platform, lose one, or
    grow a second tolerated leg without this failing. A matrix built any other
    way (a second expression, a literal include, a computed list) is refused
    outright rather than read past.
    """

    strategy_lines = active_lines(dynamic_job_context_source(install_job))
    includes = [line for line in strategy_lines if line.startswith("include:")]
    if len(includes) != 1:
        raise AssertionError(
            "install-proof must declare exactly one matrix include line; "
            f"found {includes}"
        )
    match = INSTALL_PROOF_MATRIX_PATTERN.fullmatch(includes[0])
    if match is None:
        raise AssertionError(
            "install-proof matrix must be the reviewed release-or-pull-request "
            f"expression; found `{includes[0]}`"
        )
    try:
        release = json.loads(match.group("release"))
        pull_request = json.loads(match.group("pull_request"))
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"install-proof matrix does not decode as JSON: {error}"
        ) from error
    return release, pull_request


INSTALL_PROOF_PULL_REQUEST_ARTIFACT = "install-proof-pr-binaries"
INSTALL_PROOF_PULL_REQUEST_JOBS = (
    "install-proof-pr-build",
    "install-proof-pr",
    "install-proof-pr-gate",
)


# The only event filters the pull-request install proof jobs may carry, matched
# on the whole stripped line. A set rather than a substring test, because
# `event_name != 'pull_request'` is a substring of every filter that also
# excludes something else, and the thing this assertion exists to catch is a
# heavy leg quietly leaving the merge queue. `install-proof-pr-gate` carries no
# job-level filter at all: it always reports, and decides inside its own step.
INSTALL_PROOF_ADMITTED_EVENT_FILTERS = frozenset(
    {"&& github.event_name != 'pull_request'"}
)
# The gate is exempt from even that. It always reports, under one stable name,
# and decides inside its own step, so any job-level event filter here publishes
# no check rather than a skipped one.
INSTALL_PROOF_PULL_REQUEST_GATE = "install-proof-pr-gate"


def assert_install_proof_runs_on_pull_requests(ci: str, install_proof: str) -> None:
    """Require the release install proof to run before a tag exists.

    v0.5.38 was versioned, built, published, and only then refused, on an
    assertion no pull-request check ran: `kin locate` had to report complete
    semantic coverage over a freshly installed probe repository, and the only
    place that ran was the public install proof, which the release workflow
    calls after publishing. The remedy is not a second copy of that assertion,
    which would drift from the one the release enforces. It is the same
    reusable proof, called from CI against binaries the pull request built.

    So this pins the three properties that make that true and keeps each one
    falsifiable. The proof must reach the reviewed reusable workflow rather
    than a lookalike; the binaries it installs must be the ones the pull
    request compiled and packaged in the release archive layout; and none of
    the three jobs may exclude the MERGE QUEUE, which is what the release mint
    reads. The semantic-coverage assertion itself is pinned last: the step
    producing its capture stays on the ordinary Unix path, so a run reaches it
    rather than skipping it as an optional extra.

    The pull-request exclusion used to be barred too, and FIR-2815 admits
    exactly one form of it and no other. The reason it was barred has not
    changed and is not weakened: a heavy leg quietly moved back to main is how
    this class of break returns. What changed is where "before a tag" is paid.
    The proof measured 9.4 minutes on a pull request against a ten-minute
    open-to-merge bar, and it now runs in the merge queue and on every commit
    that reaches main, both of which are before any tag. `release-tag.yml`
    still refuses to mint a sha whose required checks are not green.

    The admitted form is the exact expression below and nothing else, so an
    event filter that excluded the merge queue, or excluded a push, or was
    written differently enough to mean something else, still fails here.
    """

    jobs = workflow_job_blocks(ci)
    missing = [job for job in INSTALL_PROOF_PULL_REQUEST_JOBS if job not in jobs]
    if missing:
        raise AssertionError(
            "the install proof must run at pull-request time; CI lost "
            f"{missing}"
        )
    build, call, gate = (jobs[job] for job in INSTALL_PROOF_PULL_REQUEST_JOBS)

    call_lines = active_lines(call)
    for policy in (
        "uses: ./.github/workflows/install-proof.yml",
        f"local_artifact: {INSTALL_PROOF_PULL_REQUEST_ARTIFACT}",
    ):
        if policy not in call_lines:
            raise AssertionError(
                "the pull-request install proof must call the reviewed reusable "
                f"proof with the built artifact; missing `{policy}`"
            )
    build_lines = active_lines(build)
    for policy in (
        f"name: {INSTALL_PROOF_PULL_REQUEST_ARTIFACT}",
        "--target x86_64-unknown-linux-musl -p kin-cli -p kin-daemon",
        'tar czf "$stage/$artifact.tar.gz" -C "$stage" "$artifact"',
        "assertReleaseArchiveMemberPaths(listing, {",
        'cp scripts/install.sh "$stage/install.sh"',
    ):
        if policy not in build_lines:
            raise AssertionError(
                "the pull-request install proof must install release-layout "
                f"binaries built by this pull request; missing `{policy}`"
            )

    for job_id, job in zip(INSTALL_PROOF_PULL_REQUEST_JOBS, (build, call, gate)):
        for line in active_lines(job):
            clause = line.strip()
            is_condition = clause.startswith(("&&", "||", "if:"))
            if not is_condition or "event_name" not in clause:
                continue
            # A folded `if:` puts the closing `}}` on whichever clause happens
            # to be last, so one reviewed filter reads two ways depending on
            # clause order. Normalise that and nothing else.
            clause = clause.removesuffix("}}").strip()
            if job_id == INSTALL_PROOF_PULL_REQUEST_GATE:
                raise AssertionError(
                    f"{job_id} must not exclude an event. It is the job that "
                    "always reports, under one stable name, and is the context "
                    "to require; a filter here publishes no check at all rather "
                    f"than a skipped one: {line}"
                )
            if clause not in INSTALL_PROOF_ADMITTED_EVENT_FILTERS:
                raise AssertionError(
                    f"{job_id} carries an event filter that is not the one "
                    "reviewed under FIR-2815. The install proof runs in the "
                    "merge queue and on every main commit, and a filter written "
                    f"any other way silently returns it to the tag: {line}"
                )
            if "merge_group" in line or "push" in line:
                raise AssertionError(
                    f"{job_id} must run inside the merge queue and on main: "
                    "the release mint keys off the queue-proven sha and "
                    f"refuses a build that skipped this proof: {line}"
                )

    gate_lines = active_lines(gate)
    for policy in (
        'if [ "$BUILD_RESULT" != "success" ]; then',
        'if [ "$PROOF_RESULT" != "success" ]; then',
        "exit 1",
    ):
        if policy not in gate_lines:
            raise AssertionError(
                "the pull-request install proof gate must fail closed on a "
                f"proof that did not pass; missing `{policy}`"
            )

    embedding = install_proof_step(
        install_proof, "Unix embedding and semantic retrieval proof"
    )
    embedding_lines = active_lines(embedding)
    conditioned = [line for line in embedding_lines if line.startswith("if:")]
    if conditioned != ["if: runner.os != 'Windows'"]:
        raise AssertionError(
            "the semantic retrieval proof admits exactly the Unix condition, so "
            "a pull-request run reaches the assertion that refused v0.5.38; "
            f"found {conditioned}"
        )
    if (
        'kin locate hello --json --explain --max-files 5 | tee "$captures/kin-semantic-locate.json"'
        not in embedding_lines
    ):
        raise AssertionError(
            "the semantic retrieval proof lost the locate capture the "
            "capability validator reads"
        )


def assert_install_proof_every_leg_gates_the_release(install_proof: str) -> None:
    """Require every install-proof matrix row to gate the release.

    The windows-latest row carried ``experimental: true`` and the job carried
    the matching ``continue-on-error`` guard, so the one platform most likely
    to break shipped without a verdict. Two defects held that waiver open and
    both are fixed on released bytes: kin#811's inherited-pipe read of
    ``.kin/daemon.port``, then a projection chooser that named
    ``projection_mode=misconfigured`` on a host where nothing was recorded,
    which killed every release from v0.5.44 through v0.5.47. v0.5.49's run
    concluded ``Public Install Proof / windows-latest`` SUCCESS against its
    own published archives, which is the condition the waiver itself named
    for its removal, so the waiver is spent.

    Tolerance is therefore rejected in every spelling it could return in: a
    job-level ``continue-on-error`` of any value, a step-level one, which
    would spare every leg rather than one, and an ``experimental`` key on any
    row of either decoded matrix, since that key is the half of the waiver a
    reader would restore first. The reviewed platform set stays pinned here
    too, so a row cannot be dropped in the same edit that would have
    tolerated it.
    """

    jobs = workflow_job_blocks(install_proof)
    install_job = jobs.get("install-proof")
    if install_job is None:
        raise AssertionError(
            "install-proof gating posture lost the install-proof job"
        )
    job_fields = job_top_level_mapping_fields(install_job)
    tolerance = [
        value.strip() for key, value in job_fields if key == "continue-on-error"
    ]
    if tolerance:
        raise AssertionError(
            "install-proof admits no job-level continue-on-error; every "
            f"matrix row gates the release; found {tolerance}"
        )
    tolerance_mentions = [
        line for line in active_lines(install_job) if "continue-on-error" in line
    ]
    if tolerance_mentions:
        raise AssertionError(
            "install-proof admits no continue-on-error at all; a step-level "
            "tolerance would spare every leg, not one; found "
            f"{tolerance_mentions}"
        )
    release_rows, pull_request_rows = install_proof_matrix_rows(install_job)
    for label, rows in (("release", release_rows), ("pull request", pull_request_rows)):
        tolerated = [row.get("os") for row in rows if "experimental" in row]
        if tolerated:
            raise AssertionError(
                f"install-proof {label} matrix rows admit no experimental "
                f"key; the Windows waiver is spent; found it under {tolerated}"
            )
    release_platforms = [row.get("os") for row in release_rows]
    expected_platforms = [
        "ubuntu-latest",
        "ubuntu-24.04-arm",
        "macos-latest",
        "macos-15-intel",
        "windows-latest",
    ]
    if release_platforms != expected_platforms:
        raise AssertionError(
            "install-proof release matrix must gate exactly "
            f"{expected_platforms}; found {release_platforms}"
        )


def assert_install_proof_first_run_never_pipes_the_daemon_spawner(
    first_run: str,
) -> None:
    """Keep every daemon-spawning command in the first-run step unpiped.

    A pipeline outlives the command that wrote to it whenever a child
    inherits the descriptor. On Windows that child holds the write end until
    it idles out, so the reader blocks while the step looks like it is
    working. v0.5.49's Windows leg spent 3672 s of a 3684 s step in exactly
    two such waits, 1805 s and 1868 s, which is the 1800 s daemon idle window
    plus slack; both were a ``kin setup --intent agent`` piped into ``tee``,
    and that step was 62 of the 63.5 minutes between the published tag and
    npm.

    `kin status` and the graph queries already carry that rule in prose. This
    is the executable half: the first-run step captures by redirect and
    prints with `cat`, never by pipe, and a setup that fails still reaches
    the job log rather than aborting the step before the `cat`.
    """

    # The pipe scan runs first, so a capture that reverts to `tee` is named as
    # the pipe it is rather than as a missing redirect line.
    piped = [line for line in active_lines(first_run) if "| tee" in line]
    if piped:
        raise AssertionError(
            "the first-run install proof captures by redirect, never by pipe: "
            "a child that inherits the pipe holds it for its whole idle "
            f"window and the step waits on it; found {piped}"
        )
    for policy in (
        'kin setup --no-interactive --intent agent --shell "$PROOF_SHELL" \\',
        '> "$captures/kin-setup.txt" 2>&1 || setup_status=$?',
        'cat "$captures/kin-setup.txt"',
        'if [ "$setup_status" -ne 0 ]; then exit "$setup_status"; fi',
        '> "$captures/kin-claude-fallback-setup.txt" 2>&1 || fallback_setup_status=$?',
        'cat "$captures/kin-claude-fallback-setup.txt"',
        'if [ "$fallback_setup_status" -ne 0 ]; then exit "$fallback_setup_status"; fi',
    ):
        require(first_run, policy, "unpiped first-run setup capture")


def assert_install_proof_repo_steps_cover_windows(install_proof: str) -> None:
    """Require native Windows released bytes to prove repo, daemon, and MCP.

    This is deliberately a positive execution proof. Merely rejecting one
    spelling of ``runner.os != 'Windows'`` lets an equivalent Linux-only
    expression, a job-level guard, a matrix exclusion, or a fixed non-Windows
    runner silently remove the Windows leg while the policy test stays green.
    The three release-critical steps are therefore unconditional inside one
    canonical matrix job whose runner is the matrix OS and whose include list
    contains an unexcluded ``windows-latest`` row.
    """

    jobs = workflow_job_blocks(install_proof)
    install_job = jobs.get("install-proof")
    if install_job is None:
        raise AssertionError("native Windows release proof lost the install-proof job")

    job_fields = job_top_level_mapping_fields(install_job)
    if any(key == "if" for key, _ in job_fields):
        raise AssertionError(
            "native Windows release proof lost repository coverage: install-proof "
            "must not carry a job-level condition"
        )
    runs_on = [value.strip() for key, value in job_fields if key == "runs-on"]
    if runs_on != ["${{ matrix.os }}"]:
        raise AssertionError(
            "native Windows release proof must run on the reviewed OS matrix; "
            f"found runs-on={runs_on}"
        )

    strategy_lines = active_lines(dynamic_job_context_source(install_job))
    if any(
        line == "exclude:" or line.startswith("exclude:")
        for line in strategy_lines
    ):
        raise AssertionError(
            "native Windows release proof matrix must not exclude a reviewed OS row"
        )
    release_rows, _ = install_proof_matrix_rows(install_job)
    windows_rows = [row for row in release_rows if row.get("os") == "windows-latest"]
    if len(windows_rows) != 1:
        raise AssertionError(
            "native Windows release proof matrix must contain exactly one "
            f"windows-latest row; found {len(windows_rows)}"
        )

    for step in (
        "First-run repository, daemon, and setup proof",
        "Graph query and MCP tool-call proof",
        "Validate installed capability proof",
    ):
        step_source = textwrap.dedent(
            install_proof_step(install_proof, step)
        ).strip()
        top_level_fields: list[str] = []
        for line in classifier_active_job_source(step_source).splitlines()[1:]:
            indent = len(line) - len(line.lstrip())
            if indent != 2:
                continue
            match = re.fullmatch(r"  (?P<key>[A-Za-z0-9_-]+):(?:[ \t].*)?", line)
            if match is None:
                raise AssertionError(
                    "install-proof step fields must use canonical unquoted `key:` "
                    f"syntax: {line.strip()}"
                )
            top_level_fields.append(match.group("key"))
        if "if" in top_level_fields:
            raise AssertionError(
                f"native Windows release proof lost repository coverage: {step} "
                "must run unconditionally for every reviewed matrix row"
            )


def assert_install_proof_windows_admission_contract(
    windows_admission: str, contract: dict[str, str]
) -> None:
    """Require released Windows bytes to assert the native admission contract."""

    active = "\n".join(active_lines(windows_admission))
    for name, wording in contract.items():
        binding = f'{name}="{wording}"'
        if binding not in active:
            raise AssertionError(
                "install proof must assert the shipped Windows admission contract "
                f"verbatim; {name} drifted from {WINDOWS_INIT_CONTRACT_POLICY}: "
                f"expected {binding}"
            )
    for policy in (
        'require_admitted "Windows exact-Git admission" "$git_boundary" "$git_log"',
        'require_admitted "Windows native-unborn bootstrap" "$native_boundary" "$native_log"',
        'require_refused "Windows non-empty native boundary" "$populated_boundary" "$populated_log"',
        'require_text "$1" "$NON_EMPTY_REFUSAL" "$3"',
        'fail "$1 failed" "$3"',
        'fail "$1 unexpectedly succeeded" "$3"',
        'if [ ! -d "$2/.kin" ]; then',
        'if [ -e "$2/.kin" ]; then',
        'parent="$(dirname "$2")"',
        "staged=\"$(count_matching \"$parent\" '.kin.init-*')\"",
        'if [ "$staged" != "0" ]; then',
    ):
        require(active, policy, "shipped Windows admission contract proof")


def assert_install_proof_repo_free_windows_proof(repo_free: str) -> None:
    """Keep the pre-repository Windows setup/provenance checkpoint falsifiable.

    The later first-run steps prove the admitted repo, daemon, all five client
    writers, and MCP. This earlier checkpoint separately proves the CLI's
    public provenance, unsupported capability posture, and the four client
    writers that do not require an exact repository binding.
    """

    active = "\n".join(active_lines(repo_free))
    for policy in (
        "kin bench-meta --json > kin-windows-bench-meta.json",
        "kin registry authority --json > kin-windows-registry-authority.json",
        "if kin registry authority --fix > kin-windows-registry-fix.txt 2>&1; then",
        'kin setup --no-interactive --intent agent --shell "$PROOF_SHELL"',
        "kin setup status --json | tee kin-windows-health.json",
        "kin doctor --json | tee kin-windows-doctor.json",
        "for agent in claude cursor codex gemini windsurf agy; do",
        'fs.readFileSync("expected-commit.txt", "utf8").trim()',
        'fs.readFileSync("expected-lock-sha.txt", "utf8").trim()',
        'fs.readFileSync("installed-kin-command.txt", "utf8").trim()',
        "installedKin !== expectedInstalledKin",
        "meta.kin_commit !== expectedCommit",
        "meta.kin_dirty !== false",
        "meta.kin_source_known !== true",
        "meta.dependency_provenance !== expectedLock",
        "meta.embeddings?.vector_enabled !== true",
        "meta.embeddings?.embeddings_enabled !== true",
        "meta.embeddings?.metal_enabled !== false",
        'authority.checks[0]?.state !== "unsupported"',
        '["repo_init", "unsupported"]',
        '["daemon_running", "unsupported"]',
        '["registry_authority", "unsupported"]',
        '["vfs_projection", "unsupported"]',
        '["semantic_query_readiness", "unsupported"]',
        '["shell_path", "healthy"]',
        '["setup_ledger", "healthy"]',
        '["mcp_client_claude", "healthy"]',
        '["mcp_client_cursor", "healthy"]',
        '"mcp_client_codex", "mcp_client_antigravity", "mcp_client_antigravity_workspace"',
        '["mcp_client_gemini", "healthy"]',
        '["mcp_client_windsurf", "healthy"]',
        "entry.command !== installedKin",
        'path.join(home, ".gemini", "config", "mcp_config.json")',
    ):
        require(active, policy, "repo-free Windows install proof")


def assert_install_proof_status_contract(
    first_run: str, graph_query: str, embedding: str, validation: str
) -> None:
    """Pin install proof to fields the released binaries actually emit.

    `kin status --json` is the repository status report, not the daemon command
    envelope. Build provenance therefore comes from the CLI's bench metadata
    and the daemon's public health response, while embedding progress comes
    from the required `kin.status.v3` coverage sum type. Keeping these sources
    separate prevents a plausible-looking proof from reading fields that no
    shipped command produces.
    """

    first_run_active = "\n".join(active_lines(first_run))
    embedding_active = "\n".join(active_lines(embedding))
    validation_active = "\n".join(active_lines(validation))

    require(
        first_run_active,
        'kin bench-meta --json > "$captures/kin-build-meta.json"',
        "installed CLI provenance capture",
    )
    require(
        first_run_active,
        "printf '%s\\n' \"$fake_agent_bin\" >> \"$GITHUB_PATH\"",
        "cross-step agent-client proof PATH",
    )
    for policy in (
        "for agent in claude cursor codex gemini windsurf agy; do",
        'antigravity_legacy="$HOME/.gemini/antigravity-ide/mcp_config.json"',
        'command: "/stale/kin"',
        'CODEX_CONFIG="$HOME/.codex/config.toml" PROOF_CAPTURES="$captures" python3',
        'tomllib.load(handle)["mcp_servers"]["kin"]',
        'claude_fallback_home="$RUNNER_TEMP/kin-proof-claude-fallback-home"',
        'printf \'{}\\n\' > "$claude_fallback_home/.claude/config.json"',
        'if [ -e "$claude_fallback_home/.claude.json" ]; then',
        "kin-claude-fallback-health.json",
        "kin-claude-fallback-doctor.json",
    ):
        require(first_run_active, policy, "complete MCP writer state/path matrix")

    graph_active_lines = active_lines(graph_query)
    graph_active = "\n".join(graph_active_lines)
    # A query that starts the daemon must be redirected, never piped. Windows
    # hands a spawned daemon every handle its caller was given, so a piped query
    # leaves the reader on the far side waiting for the daemon rather than for
    # the CLI. The step then resumes only once the daemon has idled out and
    # retired the endpoint the next line reads, so it reports a missing
    # `.kin/daemon.port`. That reads as a daemon which never published one, and
    # for two releases it was recorded as exactly that.
    for line in graph_active_lines:
        if line.startswith(("kin search ", "kin locate ")) and "|" in line:
            raise AssertionError(
                "install proof must redirect a daemon-starting query rather than "
                "pipe it: a daemon that inherits the pipe holds it until idle "
                "shutdown and retires the endpoint this step reads before the "
                f"read happens: {line}"
            )

    for policy in (
        'kin search hello --json > "$captures/kin-search.json"',
        'kin locate hello --json --explain --max-files 5 > "$captures/kin-locate.json"',
        "daemon_port=\"$(tr -d '[:space:]' < .kin/daemon.port)\"",
        'DAEMON_PORT="$daemon_port" node',
        "http://127.0.0.1:${process.env.DAEMON_PORT}/health",
        "kin-daemon-health.json",
        'kin setup status --json | tee "$captures/kin-health.json"',
        'kin doctor --json | tee "$captures/kin-doctor.json"',
        'path.join(process.cwd(), ".agents", "mcp_config.json")',
        "spawn(entry.command, entry.args",
        'const stripVerbatim = (p) => (typeof p === "string" && p.startsWith("\\\\\\\\?\\\\") ? p.slice(4) : p);',
        "cwd: stripVerbatim(entry.cwd),",
        "env: { ...proofEnv, ...(entry.env ?? {}) }",
    ):
        require(graph_active, policy, "installed daemon startup and health capture")

    daemon_start = 'kin search hello --json > "$captures/kin-search.json"'
    endpoint_capture = "daemon_port=\"$(tr -d '[:space:]' < .kin/daemon.port)\""
    setup_health = 'kin setup status --json | tee "$captures/kin-health.json"'
    doctor_health = 'kin doctor --json | tee "$captures/kin-doctor.json"'
    daemon_start_index = graph_active_lines.index(daemon_start)
    if any(
        daemon_start_index >= graph_active_lines.index(capture)
        for capture in (endpoint_capture, setup_health, doctor_health)
    ):
        raise AssertionError(
            "install proof must start the daemon through a graph query before "
            "reading its endpoint or capturing setup health"
        )

    for stale_capture in (setup_health, doctor_health):
        if stale_capture in "\n".join(active_lines(first_run)):
            raise AssertionError(
                "install proof must capture setup health after the daemon-starting "
                f"graph query, not in the first-run step: {stale_capture}"
            )

    for stale in (
        "status.build",
        "status.semantic_coverage",
        "embeddedStatus.semantic_coverage",
    ):
        if stale in validation_active:
            raise AssertionError(
                "install proof reads a field the released status report does not "
                f"emit: {stale}"
            )

    for policy in (
        'const cliMeta = JSON.parse(fs.readFileSync("kin-build-meta.json", "utf8"))',
        'const daemonHealth = JSON.parse(fs.readFileSync("kin-daemon-health.json", "utf8"))',
        "sha: cliMeta.kin_commit",
        "sha: daemonHealth.build?.sha",
        'status.schema !== "kin.status.v3"',
        "validateEmbeddingCoverage(status.embedding_coverage",
        "cliMeta.embeddings?.vector_enabled !== true",
        "cliMeta.embeddings?.embeddings_enabled !== true",
        'embeddedStatus.schema !== "kin.status.v3"',
        "validateEmbeddingCoverage(embeddedStatus.embedding_coverage",
        "embeddedCoverage.indexed !== embeddedCoverage.total",
        "embeddedCoverage.pending !== 0",
        'fs.readFileSync("../installed-kin-command.txt", "utf8").trim()',
        "installedKin !== expectedInstalledKin",
        '["mcp_client_antigravity", "healthy"]',
        '["mcp_client_antigravity_workspace", "healthy"]',
        '"kin-claude-fallback-config.json"',
        '"kin-codex-config.json"',
        'path.join(repoRoot, ".agents", "mcp_config.json")',
        "entry.command !== installedKin",
        'legacy.userPolicy !== "preserve"',
    ):
        require(
            validation_active,
            policy,
            "released-byte status and build proof contract",
        )

    require(
        embedding_active,
        'kin status --json | tee "$captures/kin-embedded-status.json"',
        "post-embedding repository status capture",
    )


def assert_toolchain_prune_is_wired(action: str) -> None:
    """Keep the cache key a function of this repository, not of the runner image.

    `Swatinem/rust-cache` hashes every entry of `rustup toolchain list` into half its key.
    Two ubuntu-latest jobs sixty-five seconds apart drew images carrying 1.97.1 and 1.98.0,
    hashed to 8374e8ea and 6ea01539 against one `Cargo.lock`, and could not restore each
    other's cache. Nothing in this repository chose either version.

    The obvious fix is the wrong one and has its own arm below: turning off
    `add-rust-environment-hash-key` gates BOTH halves of the key in that action's source,
    so the key freezes at its bare prefix and stops varying on `Cargo.lock` at all.

    Order is the load-bearing part here. The image's set has to be recorded BEFORE the
    install, because afterwards nothing can tell an image toolchain from the one this action
    added, and a prune that reads the list after the install would remove the toolchain it
    just installed or nothing at all.
    """

    for step in (
        "Record the toolchains the runner image shipped",
        "Prune toolchains this repository never named",
    ):
        if action.count(f"- name: {step}\n") != 1:
            raise AssertionError(
                f"the rust-toolchain action must declare exactly one step named {step!r}; "
                "without it the cargo cache key carries whatever toolchain the runner "
                "image happened to ship"
            )
    record = action.index("- name: Record the toolchains the runner image shipped")
    install = action.index("- name: Install the toolchain")
    prune = action.index("- name: Prune toolchains this repository never named")
    if not record < install < prune:
        raise AssertionError(
            "the image toolchain set must be recorded before the install and pruned after "
            "it; recorded after the install it cannot tell the image's toolchains from ours"
        )
    # The needle is the INVOCATION, never the name. The step's own comment names the
    # script, so a needle of `prune-image-toolchains.sh` matches a step that calls nothing
    # and this assertion could not fail. That is how it read on the first run of the
    # mutation below, which is the only reason it is written this way.
    if 'bash "$GITHUB_ACTION_PATH/prune-image-toolchains.sh"' not in action:
        raise AssertionError(
            "the prune step must call prune-image-toolchains.sh, which is the copy the "
            "behavioral cases below drive"
        )
    if "repo_pin=$repo_pin" not in action and 'repo_pin=$repo_pin' not in action:
        raise AssertionError(
            "the resolve step must publish repo_pin, because the prune keeps the channel "
            "rust-toolchain.toml names as well as the toolchain the caller asked for"
        )


def run_prune(
    tmp: Path,
    resolved: str,
    preinstalled: list[str],
    repo_pin: str = "",
    uninstall_fails: str = "",
    uninstall_fails_after: str = "",
    after: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Drive the prune script against a stub rustup, so its logic is testable off CI.

    The stub is the whole point. Asserting the script's TEXT would pass on a script that
    removes the wrong toolchain, and a check that cannot fail is not evidence. `after` lets
    a case model a rustup that reports something the prune did not achieve, which is the
    straggler the assertion exists to catch.
    """

    bindir = tmp / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    state = tmp / "installed.txt"
    state.write_text("\n".join(preinstalled) + "\n", encoding="utf-8")
    forced = tmp / "forced-after.txt"
    if after is not None:
        forced.write_text("\n".join(after) + "\n", encoding="utf-8")
    stub = bindir / "rustup"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'STATE="{state}"\n'
        f'FORCED="{forced}"\n'
        f'FAILS="{uninstall_fails}"\n'
        f'FAILS_AFTER="{uninstall_fails_after}"\n'
        'if [ "$1" = "toolchain" ] && [ "$2" = "list" ]; then\n'
        '  if [ -f "$FORCED" ]; then cat "$FORCED"; else cat "$STATE"; fi\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = "toolchain" ] && [ "$2" = "uninstall" ]; then\n'
        '  if [ -n "$FAILS" ] && [ "$3" = "$FAILS" ]; then echo "stub refuses $3" >&2; exit 1; fi\n'
        '  grep -v "^$3\\( \\|$\\)" "$STATE" > "$STATE.new" || true\n'
        '  mv "$STATE.new" "$STATE"\n'
        '  if [ -n "$FAILS_AFTER" ] && [ "$3" = "$FAILS_AFTER" ]; then echo "stub errored after removing $3" >&2; exit 1; fi\n'
        "  exit 0\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    before = tmp / "before.txt"
    before.write_text("\n".join(preinstalled) + "\n", encoding="utf-8")
    env = dict(os.environ)
    env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
    return subprocess.run(
        ["bash", str(TOOLCHAIN_PRUNE), resolved, str(before), repo_pin],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def assert_toolchain_prune_behavior() -> None:
    """The prune keeps what this repository names and removes what the image shipped."""

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)

        # The measured case: the image shipped a second stable nobody here chose.
        run = run_prune(
            tmp / "image-extra",
            "1.96.0",
            [
                "1.96.0-x86_64-unknown-linux-gnu (default)",
                "1.98.0-x86_64-unknown-linux-gnu",
            ],
            repo_pin="1.96.0",
        )
        if run.returncode != 0:
            raise AssertionError(f"the prune refused an ordinary image: {run.stderr}")
        if "removing 1.98.0-x86_64-unknown-linux-gnu" not in run.stdout:
            raise AssertionError(
                f"the prune left the image's own toolchain installed: {run.stdout}"
            )
        if "keeping 1.96.0-x86_64-unknown-linux-gnu" not in run.stdout:
            raise AssertionError(
                f"the prune removed the toolchain this repository pins: {run.stdout}"
            )

        # fuzz.yml's shape: a caller-supplied nightly, and a bare `cargo` that
        # rust-toolchain.toml resolves to the stable pin. Both survive.
        run = run_prune(
            tmp / "two-named",
            "nightly-2026-06-17",
            [
                "1.96.0-x86_64-unknown-linux-gnu",
                "1.98.0-x86_64-unknown-linux-gnu",
                "nightly-2026-06-17-x86_64-unknown-linux-gnu",
            ],
            repo_pin="1.96.0",
        )
        if run.returncode != 0:
            raise AssertionError(f"the prune refused the fuzz shape: {run.stderr}")
        for kept in ("1.96.0-x86_64", "nightly-2026-06-17-x86_64"):
            if f"keeping {kept}" not in run.stdout:
                raise AssertionError(
                    f"the prune removed {kept}, which this repository names: {run.stdout}"
                )
        if "removing 1.98.0-x86_64-unknown-linux-gnu" not in run.stdout:
            raise AssertionError(
                f"the prune kept a toolchain nobody named: {run.stdout}"
            )

        # A prefix must not be read as a match in either direction.
        run = run_prune(
            tmp / "prefix",
            "1.9",
            ["1.96.0-x86_64-unknown-linux-gnu"],
        )
        if run.returncode == 0:
            raise AssertionError(
                "channel 1.9 matched toolchain 1.96.0, so a prefix is being read as a "
                "match and the wrong toolchain can be kept"
            )

        # A refused uninstall must stop the job. Swallowed, it leaves a third toolchain in
        # the list under a green run, which is exactly the defect being fixed.
        run = run_prune(
            tmp / "refused",
            "1.96.0",
            [
                "1.96.0-x86_64-unknown-linux-gnu",
                "1.98.0-x86_64-unknown-linux-gnu",
            ],
            repo_pin="1.96.0",
            uninstall_fails="1.98.0-x86_64-unknown-linux-gnu",
        )
        if run.returncode == 0:
            raise AssertionError(
                "a refused uninstall exited zero, so a toolchain this repository never "
                "chose survives into the cache key under a green run"
            )
        if "could not uninstall" not in run.stderr:
            raise AssertionError(
                f"a refused uninstall did not name itself: {run.stderr}"
            )

        # The same refusal from a rustup that removed the toolchain and THEN errored. It
        # leaves no straggler, so the assertion below cannot shield it, and the loud
        # failure is the only thing that can stop the job. Without this case the
        # "could not uninstall" assertion is unreachable: every refusal the other stub mode
        # produces is caught by the straggler check first, and an assertion nothing can
        # reach is not evidence.
        run = run_prune(
            tmp / "refused-after",
            "1.96.0",
            [
                "1.96.0-x86_64-unknown-linux-gnu",
                "1.98.0-x86_64-unknown-linux-gnu",
            ],
            repo_pin="1.96.0",
            uninstall_fails_after="1.98.0-x86_64-unknown-linux-gnu",
        )
        if run.returncode == 0:
            raise AssertionError(
                "an uninstall that errored after doing the work exited zero, so nothing "
                "stops a job whose toolchain removal is only half trustworthy"
            )
        if "could not uninstall" not in run.stderr:
            raise AssertionError(
                f"a refusal that left no straggler was not named: {run.stderr}"
            )

        # And the straggler assertion, which is what turns this from a hope into a check:
        # a rustup that reports an unnamed toolchain still installed must fail the step,
        # however it got there.
        run = run_prune(
            tmp / "straggler",
            "1.96.0",
            ["1.96.0-x86_64-unknown-linux-gnu"],
            repo_pin="1.96.0",
            after=[
                "1.96.0-x86_64-unknown-linux-gnu",
                "1.99.0-x86_64-unknown-linux-gnu",
            ],
        )
        if run.returncode == 0:
            raise AssertionError(
                "a toolchain this repository never named survived the prune and the step "
                "still passed, so the invariant is asserted nowhere"
            )
        if "survived the prune" not in run.stderr:
            raise AssertionError(f"the straggler was not named: {run.stderr}")


def assert_docs_only_classifier_guard(workflow: str) -> None:
    """Require the exact workflow header, classifier job, and classifier shell."""

    if workflow_active_header_source(workflow) != DOCS_ONLY_WORKFLOW_HEADER:
        raise AssertionError(
            "diff classifier workflow header must exactly match the closed-form "
            "process environment authority contract"
        )
    classifier = workflow_job_blocks(workflow).get("changes")
    if classifier is None:
        raise AssertionError("diff classifier workflow must contain the changes job")
    job_source = classifier_active_job_source(classifier)
    if job_source != DOCS_ONLY_CLASSIFIER_JOB:
        raise AssertionError(
            "diff classifier active job must exactly match the closed-form "
            "docs_only authority contract"
        )
    if classifier_shell_source(classifier) != DOCS_ONLY_CLASSIFIER_SHELL:
        raise AssertionError("diff classifier shell extraction disagrees with its job")


def workflow_job_blocks(workflow: str) -> dict[str, str]:
    """Return every job block from a workflow, preserving declaration order."""

    marker = "jobs:\n"
    if workflow.count(marker) != 1:
        raise AssertionError("workflow must contain exactly one jobs mapping")
    jobs = workflow.split(marker, 1)[1]
    top_level_job_lines = [
        line
        for line in jobs.splitlines()
        if line.startswith("  ")
        and not line.startswith(("   ", "\t"))
        and line.strip()
        and not line.lstrip().startswith("#")
    ]
    for line in top_level_job_lines:
        if re.fullmatch(r"  [A-Za-z0-9_-]+:[ \t]*", line) is None:
            raise AssertionError(
                "workflow job ids must use one canonical unquoted scalar line: "
                f"{line.strip()}"
            )
    matches = list(
        re.finditer(r"^  (?P<job>[A-Za-z0-9_-]+):[ \t]*$", jobs, re.MULTILINE)
    )
    if len(matches) != len(top_level_job_lines):
        raise AssertionError("workflow job census did not account for every job key")
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        job = match.group("job")
        if job in blocks:
            raise AssertionError(f"workflow declares duplicate job id: {job}")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(jobs)
        blocks[job] = jobs[match.start() : end].rstrip()
    return blocks


# The full cargo-deny check set, spelled once. A merge group that ran a subset
# of this would stop reading the advisory database on the one event that reads
# the merged tree, which is the fix that was tried and refused: see the step's
# own comment in sast.yml.
CARGO_DENY_FULL_CHECK = (
    "cargo deny --log-level warn --manifest-path ./Cargo.toml --all-features check"
)


def workflow_step_shell(job: str, name: str) -> str:
    """Return one named step's active shell body, dedented and comment-free.

    Unlike workflow_step_source this resolves a step that is the last one in
    its job, which is where the cargo-deny gate sits.
    """

    anchor = f"      - name: {name}\n"
    if job.count(anchor) != 1:
        raise AssertionError(f"job must declare exactly one step named {name}")
    lines = job[job.index(anchor) :].splitlines()
    try:
        run_block = lines.index("        run: |")
    except ValueError as error:
        raise AssertionError(
            f"step {name} must carry one literal shell run block"
        ) from error
    body: list[str] = []
    for line in lines[run_block + 1 :]:
        if not line.strip():
            continue
        if len(line) - len(line.lstrip()) <= 8:
            break
        body.append(line.rstrip())
    source = textwrap.dedent("\n".join(body))
    return "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )


def assert_cargo_deny_reads_every_advisory(sast: str) -> None:
    """Keep advisories in every cargo-deny run, and make a merge group say why.

    Skipping `advisories` inside `merge_group` stops a freshly published
    advisory from ejecting an innocent pull request, and it also stops the one
    gate that reads the merged tree from reading the advisory database at all.
    The sweep closes that window by landing the bump on a schedule instead, so
    this check stays whole and only its failure message changes.
    """

    job = workflow_job_blocks(sast).get("cargo-deny")
    if job is None:
        raise AssertionError("SAST must declare the cargo-deny job")
    shell = workflow_step_shell(job, "Run cargo-deny")
    # Continuations joined first, so a wrapped invocation is judged whole, and
    # the shell grammar around it stripped, so `if cargo deny ...; then` reads
    # as the invocation it is.
    joined = re.sub(r"\\\n\s*", " ", shell)
    gating = []
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.startswith("if "):
            stripped = stripped[3:]
        if stripped.endswith("; then"):
            stripped = stripped[: -len("; then")]
        if stripped.startswith("cargo deny"):
            gating.append(re.sub(r"\s+", " ", stripped).strip())
    if not gating or gating[0] != CARGO_DENY_FULL_CHECK:
        raise AssertionError(
            "the cargo-deny gate must run the whole default check set, advisories "
            f"included, on every event (first invocation: {gating[0] if gating else 'none'})"
        )
    narrowed = f"{CARGO_DENY_FULL_CHECK} bans licenses sources"
    if narrowed in re.sub(r"\s+", " ", joined):
        raise AssertionError(
            "the cargo-deny gate must not narrow its check set: dropping advisories "
            "inside a merge group stops the one run that reads the merged tree from "
            "reading the advisory database"
        )
    if "--annotate-merge-group" not in shell:
        raise AssertionError(
            "a merge-group cargo-deny failure must name the advisory and its bump "
            "command, or the queue ejects an entry with no cause recorded anywhere"
        )
    if not shell.rstrip().endswith("exit 1"):
        raise AssertionError(
            "a merge-group cargo-deny failure must still fail: the advisory is real "
            "and only its message changes"
        )


def assert_advisory_sweep_authority(sweep: str, release_train: str) -> None:
    """Pin what lets the sweep write to the repository unattended."""

    header = sweep.split("\njobs:", maxsplit=1)[0]
    if "\n  schedule:\n" not in header:
        raise AssertionError("the advisory sweep must run on a schedule, not on demand only")
    if "types: [advisory-sweep]" not in header:
        raise AssertionError(
            "the advisory sweep's manual path must be a repository dispatch pinned to "
            "one action, which always resolves this workflow file from the default branch"
        )
    if "ALLOWED_ACTORS: |" not in sweep:
        raise AssertionError(
            "the advisory sweep's manual path must be gated to the reviewed actor set"
        )
    for pin, label in (
        (
            "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
            "release App token minter",
        ),
        (
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            "checkout",
        ),
    ):
        if pin not in sweep:
            raise AssertionError(
                f"the advisory sweep must pin its {label} to the reviewed object"
            )
        if pin not in release_train:
            raise AssertionError(
                f"the advisory sweep's {label} pin no longer matches release-train.yml"
            )
    if "environment: release-tag" not in sweep:
        raise AssertionError(
            "the advisory sweep must declare the environment its App credentials are "
            "scoped to, or it silently falls back to repository-scoped copies"
        )
    for needle, label in (
        ("cargo metadata --locked", "prove the hand-written lock is one cargo would produce"),
        (
            "cargo deny --log-level warn --manifest-path ./Cargo.toml --all-features check advisories",
            "prove the advisory the bump exists for is actually gone",
        ),
        ('if [ "$changed" != "Cargo.lock" ]', "refuse a bump that touched anything but the lock"),
        ("git diff --numstat -- Cargo.lock", "refuse a bump that moved more lock lines than it named"),
    ):
        if needle not in sweep:
            raise AssertionError(
                f"the advisory sweep must {label} before it opens a pull request"
            )
    for job_step, gate in (
        ("Open or update the bump pull request", "steps.plan.outputs.bumps != '0'"),
        ("Arm protected auto-merge", "steps.plan.outputs.bumps != '0'"),
        ("Open or update the unfixable-advisory issue", "steps.plan.outputs.unfixable != '0'"),
    ):
        anchor = f"      - name: {job_step}\n"
        if anchor not in sweep:
            raise AssertionError(f"the advisory sweep must declare the {job_step} step")
        block = sweep[sweep.index(anchor) : sweep.index(anchor) + 400]
        if f"if: {gate}" not in block:
            raise AssertionError(
                f"the advisory sweep's {job_step} step must be gated on {gate}, so a "
                "clean sweep opens nothing"
            )


WINDOWS_DAEMON_SIBLING_BUILD = (
    "- name: Build the sibling Windows daemon the authority tests drive"
)
WINDOWS_DAEMON_COMPILE_STEP = (
    "- name: Compile and run native Windows runtime authority tests"
)
WINDOWS_DAEMON_LIFECYCLE_TEST = '"daemon_status_and_stop_lifecycle"'


def assert_windows_daemon_sibling_build(ci_job: str) -> None:
    """Require the Windows leg to build the daemon its lifecycle test drives.

    The lifecycle test runs a real daemon, and the harness takes it from the
    `kin-daemon` beside the `kin` binary the test was built with. Every other
    `kin-daemon` invocation in the leg compiles `--lib`, which produces no
    binary, so without an explicit build nothing writes one for that target
    before the test reads it.

    The harness does cover a missing daemon by rebuilding one, but a rebuild
    lands beside the test only when it repeats the same `--target`, so a leg
    that leaves the build to the harness is asserting a harness behavior rather
    than supplying its own input. Ordering is pinned as well as presence: this
    build sitting after the tests is how the leg failed for days while reporting
    a daemon missing from a directory the job did eventually populate.

    Judged on active lines and scoped to the step's own block: the `--target`
    that decides where the binary lands must appear inside the sibling build
    step itself, and ordering compares step-name positions, so a comment
    quoting the test name can neither satisfy a policy nor invert the order.
    """

    active_job = "\n".join(active_lines(ci_job))
    for step in (WINDOWS_DAEMON_SIBLING_BUILD, WINDOWS_DAEMON_COMPILE_STEP):
        require(active_job, step, "native Windows daemon lifecycle prerequisite")
    build_start = active_job.index(WINDOWS_DAEMON_SIBLING_BUILD)
    compile_start = active_job.index(WINDOWS_DAEMON_COMPILE_STEP)
    if build_start > compile_start:
        raise AssertionError(
            "native Windows daemon lifecycle prerequisite must build the msvc "
            "kin-daemon binary before the lifecycle test reads it"
        )
    sibling_build_block = active_job[build_start:compile_start]
    for policy in (
        "-p kin-daemon --no-default-features --bin kin-daemon",
        "--target x86_64-pc-windows-msvc",
    ):
        require(
            sibling_build_block,
            policy,
            "native Windows daemon lifecycle prerequisite",
        )
    require(
        active_job[compile_start:],
        WINDOWS_DAEMON_LIFECYCLE_TEST,
        "native Windows daemon lifecycle prerequisite",
    )


WINDOWS_AUTHORITY_JOBS = (
    "windows-authority-tests",
    "windows-authority-cli-tests",
    "windows-authority-runtime-tests",
)
WINDOWS_AUTHORITY_LEG_HELPERS = "source ./scripts/windows-authority-legs.sh"
# The one job-level condition these three may carry, matched whole. Whole rather
# than by substring, because `github.event_name != 'pull_request'` is a
# substring of every condition that also excludes the merge queue or the push,
# and that is the thing this rule exists to catch.
WINDOWS_AUTHORITY_ADMITTED_IF = "${{ github.event_name != 'pull_request' }}"
# Every native Windows leg, wherever it runs. The set is what the three jobs
# owe between them, so splitting or rebalancing them stays a free choice while
# dropping one does not: a leg that leaves this file has to leave it visibly.
WINDOWS_AUTHORITY_LEGS = (
    "kin-registry library",
    "kin-core registry authority",
    "kin-core capability-owned config replacement",
    "retained config capability exclusion",
    "kin-git library",
    "MCP Windows sibling daemon discovery",
    "kin-core repository initialization",
    "managed-install spawn fence",
    "daemon shutdown identity",
    "kin-cli Windows modules",
    "full managed uninstall safety",
    "native full managed uninstall lifecycle",
    "native managed-daemon ownership scan",
    "native install authority contention and crash recovery",
    "native managed-daemon spawn admission",
    "bounded CLI test subprocesses",
    "bounded daemon probe subprocesses",
    "daemon status and stop lifecycle",
    "spawned-child Windows authority ordering",
    "isolated runtime process-tree containment",
    "direct daemon-child containment",
    "late daemon-descendant containment",
    "daemon isolation support",
    "durable merge resolution containment compile",
)


# The admission core, FIR-2815. Two jobs decide whether a pull request may land
# and a third publishes the required name for the sharded one. Everything about
# that arrangement is invisible from the context name, which is why it is pinned
# here the way the Check & Test aggregates are: a required context that goes
# green on a shard that never ran is worse than no context at all, and an
# admission gate is the one place where that is cheapest to introduce and
# hardest to notice.
FAST_GATE_LINT_STEPS = (
    "run: cargo fmt -- --check",
    "run: python3 scripts/check-quarantine.py",
    "cargo clippy --all-targets --all-features -- $allows",
    "bash scripts/release-policy-gate.sh <<'RELEASE_POLICY'",
)
# What the sharded half owes. The listing assertion is the load-bearing one: the
# scope selector narrows the run to the packages a diff can have broken, and a
# nextest filter matching nothing grades nothing and exits 0, printing the same
# summary a clean pass prints. Without a listing count the whole job is a check
# that cannot fail.
FAST_GATE_SHARD_STEPS = (
    "python3 scripts/changed-crate-scope.py",
    "cargo nextest list --locked",
    'print("::error title=Empty test selection::the scope lists zero tests")',
    "cargo nextest run --locked",
    "run: python3 scripts/check-quarantine.py --report-junit",
)
FAST_GATE_SHARD_MATRIX = "shard: [1, 2, 3]"
FAST_GATE_SHARD_INDEPENDENT_LEGS = "fail-fast: false"
FAST_GATE_AGGREGATE_ALWAYS_RUNS = "if: ${{ !cancelled() }}"
FAST_GATE_AGGREGATE_NEEDS = "needs: [changes, fast-gate-tests]"
FAST_GATE_AGGREGATE_SUCCESS_GATE = 'if [ "$SHARDS" != "success" ]; then'


def assert_fast_gate_authority(workflow: str) -> None:
    """Pin the admission core so it cannot go green having graded nothing.

    Three properties, none of them observable from the required context's name.

    The aggregate ALWAYS runs. It is the only producer of the required name, and
    a required context nobody reports blocks a merge forever with every visible
    check green, which is a silent hang rather than a failure. So its condition
    is `!cancelled()` and nothing narrower, and it decides inside its own step.

    The aggregate admits `success` from the shards and nothing else. `skipped`
    and `cancelled` mean part of the selection never ran, and a required context
    green on that is worse than no context at all. The documentation-only case
    is the one exemption and it is spelled out in the step rather than inferred
    from a job condition, so a reader can see which case is being passed.

    The shards assert their LISTING before they run. The scope selector narrows
    to the packages a diff can have broken, and a nextest filter matching
    nothing grades nothing and exits 0 with the same summary a clean pass
    prints. The count is what separates the two, and it is the only thing that
    can, so it is required here rather than left to a reviewer to notice.
    """

    jobs = workflow_job_blocks(workflow)
    for job_id in ("fast-gate-lint", "fast-gate-tests", "fast-gate-tests-aggregate"):
        if job_id not in jobs:
            raise AssertionError(
                f"the admission core lost {job_id}; what blocks a pull request "
                "from landing is not something to remove quietly"
            )

    lint = active_lines(jobs["fast-gate-lint"])
    for policy in FAST_GATE_LINT_STEPS:
        if not any(policy in line for line in lint):
            raise AssertionError(
                "the admission core's lint and policy half must keep running "
                f"`{policy}`: 31 of 64 measured pull-request failures were "
                "formatting, clippy or a policy script"
            )

    shard = jobs["fast-gate-tests"]
    shard_lines = active_lines(shard)
    for policy in FAST_GATE_SHARD_STEPS:
        if not any(policy in line for line in shard_lines):
            raise AssertionError(
                f"the admission core's sharded half must keep running `{policy}`"
            )
    for policy in (FAST_GATE_SHARD_MATRIX, FAST_GATE_SHARD_INDEPENDENT_LEGS):
        if policy not in shard_lines:
            raise AssertionError(
                f"the admission core's shards must keep `{policy}`: one red "
                "shard cancelling its siblings makes the aggregate report one "
                "cause where there may be three"
            )

    aggregate = jobs["fast-gate-tests-aggregate"]
    aggregate_lines = active_lines(aggregate)
    conditions = [line for line in aggregate_lines if line.startswith("if:")]
    if conditions != [FAST_GATE_AGGREGATE_ALWAYS_RUNS]:
        raise AssertionError(
            "the admission core's aggregate publishes the required name and "
            f"must run on every event, with `{FAST_GATE_AGGREGATE_ALWAYS_RUNS}` "
            f"and nothing narrower; it carries {conditions}. A required context "
            "nobody reports is a silent hang, not a failure"
        )
    if FAST_GATE_AGGREGATE_NEEDS not in aggregate_lines:
        raise AssertionError(
            "the admission core's aggregate must wait on the shards it grades; "
            f"missing `{FAST_GATE_AGGREGATE_NEEDS}`"
        )
    if FAST_GATE_AGGREGATE_SUCCESS_GATE not in aggregate_lines:
        raise AssertionError(
            "the admission core's aggregate must admit only `success` from the "
            "shards: `skipped` and `cancelled` mean part of the selection never "
            "ran, and a required context green on that is worse than none"
        )


def assert_windows_authority_split(ci_jobs: dict[str, str]) -> None:
    """Hold the three native Windows jobs to what one job used to owe.

    The legs were split across three jobs because one job could not finish
    inside any cap worth setting: across 119 sampled runs, 32 of the 106 allowed
    to finish were destroyed by the 60-minute limit, and the 70 survivors
    averaged 52.6 minutes against it. Three things have to stay true for the
    split to be an improvement rather than a way to lose coverage quietly.

    Every leg still runs exactly once. A split is the cheapest possible place to
    drop a test, because the leg simply is not in the job you are reading and
    the other job looks complete on its own.

    No job takes a job-level `if:` other than the one reviewed under FIR-2815,
    which takes them off pull requests and leaves them on the merge queue and on
    every commit that reaches main. These jobs are the merge group's only proof
    of the native Windows admission contract, and that reasoning did not change
    when one job became three, nor when the pull-request half of CI was thinned:
    a filter excluding the queue or the push is still what would quietly move
    this proof to the tag, and is still refused. The longest of the three
    measured 11.7 minutes, which no admission gate carries against a ten-minute
    open-to-merge bar, and `merge_pr_ready` refuses while any check is pending,
    so leaving them on pull requests set the lane's clock whether or not any
    ruleset named them.

    The step budgets sum to less than the job cap. GitHub CANCELS a job that
    hits its own timeout, and a cancelled job is silent on a check no ruleset
    requires and skips its cache save, so the next run starts colder than the
    one that timed out. A step that overruns its own budget FAILS instead, which
    is loud and still runs the save. Keeping the sum under the cap is what makes
    the loud failure arrive first, whichever step is the slow one.
    """

    combined = "\n".join(
        "\n".join(active_lines(ci_jobs[job])) for job in WINDOWS_AUTHORITY_JOBS
    )
    for leg in WINDOWS_AUTHORITY_LEGS:
        occurrences = combined.count(f'"{leg}"')
        if occurrences != 1:
            raise AssertionError(
                "the native Windows authority jobs must run every reviewed leg "
                f"exactly once; '{leg}' appears {occurrences} times across "
                + ", ".join(WINDOWS_AUTHORITY_JOBS)
            )

    for job_id in WINDOWS_AUTHORITY_JOBS:
        block = ci_jobs[job_id]
        conditions = re.findall(r"(?m)^    if: (.*)$", block)
        if conditions != [] and conditions != [WINDOWS_AUTHORITY_ADMITTED_IF]:
            raise AssertionError(
                "the Windows authority jobs must stay on the merge queue and "
                "on every main commit, so admission behavior is asserted "
                "before a release commit can carry it. The only reviewed "
                f"condition is `{WINDOWS_AUTHORITY_ADMITTED_IF}`, and "
                f"{job_id} carries {conditions}"
            )
        require(block, WINDOWS_AUTHORITY_LEG_HELPERS, f"shared leg helpers in {job_id}")
        job_cap = re.search(r"(?m)^    timeout-minutes: (?P<cap>\d+)$", block)
        if job_cap is None:
            raise AssertionError(f"{job_id} must declare one job timeout")
        step_budgets = [
            int(budget)
            for budget in re.findall(r"(?m)^        timeout-minutes: (\d+)$", block)
        ]
        if not step_budgets:
            raise AssertionError(
                f"{job_id} must budget its long steps, or a slow step can only "
                "be reported by cancelling the job"
            )
        if sum(step_budgets) >= int(job_cap.group("cap")):
            raise AssertionError(
                f"{job_id} step budgets sum to {sum(step_budgets)} against a job "
                f"cap of {job_cap.group('cap')}: an overrun there is cancelled "
                "silently instead of failing loudly"
            )


def assert_windows_npm_first_run_proof(ci_job: str, proof_source: str) -> None:
    """Require both public npm surfaces to pass a real native Windows first run.

    Unit tests on Linux can prove package policy, but not Windows executable
    names or sibling-daemon discovery. Keep the canonical package, compatibility
    wrapper, built binary pair, and PATH-free runtime exercise in one required
    Windows job so none can be inferred from the others.
    """

    active_job_lines = active_lines(ci_job)
    active_job = "\n".join(active_job_lines)
    for command in (
        "npm test --prefix ./packages/kin",
        "npm run lint --prefix ./packages/kin",
        "npm test --prefix ./packages/kin-mcp",
        "npm run lint --prefix ./packages/kin-mcp",
    ):
        if command not in active_job_lines:
            raise AssertionError(
                "native Windows npm first-run CI proof is missing exact command: "
                f"{command}"
            )
    for policy in (
        "actions/setup-node@v7",
        "node-version: 20",
        "Test both public npm surfaces on native Windows",
        "node --check ./scripts/prove-windows-npm-first-run.mjs",
        "MCP Windows sibling daemon discovery",
        "daemon_delegate::tests::windows_daemon_discovery_finds_platform_sibling_without_path",
        "-p kin-mcp --no-default-features --lib",
        "Build the Windows binaries the admission and npm assertions drive",
        "-p kin-cli -p kin-daemon --no-default-features",
        "--bin kin --bin kin-daemon",
        "Prove both npm surfaces from built Windows binaries",
        "KIN_NPM_PROOF_KIN_BIN: ${{ github.workspace }}/target/x86_64-pc-windows-msvc/debug/kin.exe",
        "KIN_NPM_PROOF_DAEMON_BIN: ${{ github.workspace }}/target/x86_64-pc-windows-msvc/debug/kin-daemon.exe",
        "node ./scripts/prove-windows-npm-first-run.mjs",
    ):
        require(active_job, policy, "native Windows npm first-run CI proof")

    npm_tests = active_job.index("npm test --prefix ./packages/kin")
    binary_build = active_job.index(
        "Build the Windows binaries the admission and npm assertions drive"
    )
    runtime_proof = active_job.index(
        "Prove both npm surfaces from built Windows binaries"
    )
    if not npm_tests < binary_build < runtime_proof:
        raise AssertionError(
            "native Windows npm proof must run package tests before building the "
            "exact binaries its first-run integration drives"
        )

    active_proof = "\n".join(active_lines(proof_source))
    for policy in (
        "if (process.platform !== 'win32' && !hostOverride) {",
        "requireBuiltBinary('KIN_NPM_PROOF_KIN_BIN', expectedKinName)",
        "requireBuiltBinary('KIN_NPM_PROOF_DAEMON_BIN', expectedDaemonName)",
        "await copyExecutable(builtKin, managedKin)",
        "await copyExecutable(builtDaemon, managedDaemon)",
        "writeLauncherStamp(targetKinVersion(), { KIN_HOME: kinHome })",
        "setEnv(env, 'KIN_NO_PROVISION', '1')",
        "deleteEnv(env, 'KIN_DAEMON_BIN')",
        "assertPathExcludes(env, path.dirname(managedKin), '@kinlab/kin')",
        "assert.ok(path.isAbsolute(managedKin), '@kinlab/kin managed binary must be absolute')",
        "[canonicalKinLauncher, 'status', '--json']",
        "[canonicalKinLauncher, 'search', 'greet', '--json']",
        "launcher: canonicalMcpLauncher",
        "setEnv(env, 'KIN_MCP_AUTO_INIT', '1')",
        "launcher: compatibilityMcpLauncher",
        "name: 'semantic_search'",
        "assert.match(rendered, /greet/i",
        "assert.match(rendered, /main\\.rs/i",
        "['daemon', 'stop', '--all', '--json']",
    ):
        require(active_proof, policy, "native Windows npm first-run harness")

    canonical_start = proof_source.index("async function proveCanonical(")
    compatibility_start = proof_source.index(
        "async function proveCompatibility(", canonical_start
    )
    canonical = "\n".join(
        active_lines(proof_source[canonical_start:compatibility_start])
    )
    if re.search(r"setEnv\(env, ['\"]KIN_DAEMON_BIN['\"]", canonical):
        raise AssertionError(
            "canonical Windows npm proof must not inject KIN_DAEMON_BIN; the "
            "absolute managed kin.exe must discover its sibling daemon"
        )
    for policy in (
        "const hostilePath = [managedBinDir, readEnv(process.env, 'PATH') || '']",
        "setEnv(env, 'PATH', pathWithoutDirectory(hostilePath, managedBinDir))",
    ):
        require(active_proof, policy, "non-vacuous PATH-free Windows npm proof")


def assert_windows_npm_archive_authority(
    canonical_source: str,
    canonical_test: str,
    compatibility_source: str,
    compatibility_test: str,
) -> None:
    """Pin real-ZIP extraction to Windows system authority in both packages."""

    for label, source, end_marker in (
        (
            "canonical npm provisioner",
            canonical_source,
            "/**\n * Download, verify, and install the pinned Kin release.",
        ),
        (
            "compatibility npm provisioner",
            compatibility_source,
            "async function installFromArchive(",
        ),
    ):
        start = source.index("function archiveExtraction(")
        end = source.index(end_marker, start)
        extraction = "\n".join(active_lines(source[start:end]))
        require(
            "\n".join(active_lines(source)),
            "path.win32.join(systemRoot, 'System32', 'tar.exe')",
            f"{label} absolute System32 extraction authority",
        )
        for policy in (
            "if (platform === 'win32') {",
            "if (process.platform === 'win32') {",
            "executable: windowsSystemTarPath(env)",
            "executable: '/usr/bin/unzip'",
        ):
            require(extraction, policy, f"{label} Windows ZIP extraction authority")

    for label, test_source, test_name in (
        (
            "canonical npm provisioner",
            canonical_test,
            "provision uses deterministic Windows ZIP extraction under a hostile PATH",
        ),
        (
            "compatibility npm provisioner",
            compatibility_test,
            "ensureKinBinary installs the flat native Windows zip and .exe pair",
        ),
    ):
        active_test = "\n".join(active_lines(test_source))
        for policy in (
            test_name,
            "environmentWithHostileTar",
            "process.platform === 'win32' ? 'tar.exe' : 'tar'",
            "env.PATH = [hostileBin, originalPath]",
            "windowsSystemTarPath()",
            "'/usr/bin/zip'",
            "subarray(0, 4).toString('hex')",
            "'504b0304'",
        ):
            require(active_test, policy, f"{label} genuine Windows ZIP regression")


def job_top_level_mapping_fields(job: str) -> list[tuple[str, str]]:
    """Return canonical job-level fields, rejecting YAML key aliases."""

    active_lines = classifier_active_job_source(job).splitlines()
    child_indents = [
        len(line) - len(line.lstrip()) for line in active_lines[1:] if line.strip()
    ]
    if not child_indents:
        return []
    if min(child_indents) != 2:
        raise AssertionError(
            "workflow job top-level fields must use canonical two-space "
            "child indentation"
        )

    fields: list[tuple[str, str]] = []
    for line in active_lines[1:]:
        indent = len(line) - len(line.lstrip())
        if indent != 2:
            continue
        match = re.fullmatch(
            r"  (?P<key>[A-Za-z0-9_-]+):(?:[ \t]*(?P<value>.*))?",
            line,
        )
        if match is None:
            raise AssertionError(
                "workflow job top-level keys must use canonical unquoted "
                f"`key:` syntax: {line.strip()}"
            )
        fields.append((match.group("key"), match.group("value") or ""))
    return fields


def optional_job_display_name(job: str) -> str | None:
    """Return a job's exact top-level display name, if it declares one."""

    names = [
        value.strip()
        for key, value in job_top_level_mapping_fields(job)
        if key == "name"
    ]
    if len(names) > 1:
        raise AssertionError(
            "workflow jobs may carry at most one one-line display name"
        )
    if names and (not names[0] or names[0] in {"|", "|-", ">", ">-"}):
        raise AssertionError(
            "workflow job display names must be non-empty one-line scalars"
        )
    return names[0] if names else None


def job_display_name(job: str) -> str:
    """Return the required exact one-line display name for a CI job block."""

    name = optional_job_display_name(job)
    if name is None:
        raise AssertionError(
            "every CI job must carry exactly one one-line display name"
        )
    return name


def dynamic_job_context_source(job: str) -> str:
    """Return the name-bearing matrix contract for a dynamic job display name."""

    active_lines = classifier_active_job_source(job).splitlines()
    try:
        strategy_start = active_lines.index("  strategy:")
    except ValueError as error:
        raise AssertionError(
            "a matrix-derived workflow job name requires an explicit strategy"
        ) from error
    strategy_end = len(active_lines)
    for index in range(strategy_start + 1, len(active_lines)):
        line = active_lines[index]
        if len(line) - len(line.lstrip()) <= 2:
            strategy_end = index
            break
    return "\n".join(active_lines[strategy_start:strategy_end])


def assert_workflow_job_census(workflows: dict[Path, str]) -> None:
    """Pin every workflow job so no second required-context producer can appear."""

    actual: dict[str, dict[str, str | None]] = {}
    dynamic_contexts: dict[tuple[str, str], str] = {}
    for workflow, content in sorted(workflows.items()):
        path = workflow.relative_to(ROOT).as_posix()
        actual[path] = {}
        for job_id, block in workflow_job_blocks(content).items():
            display_name = optional_job_display_name(block)
            actual[path][job_id] = display_name
            if display_name is None or "${{" not in display_name:
                continue
            if "${{ matrix." not in display_name:
                raise AssertionError(
                    "dynamic workflow job display names must derive only from "
                    f"their reviewed matrix contract: {path}:{job_id}"
                )
            authority = (
                f"{display_name}\n{dynamic_job_context_source(block)}"
            ).encode()
            dynamic_contexts[(path, job_id)] = hashlib.sha256(authority).hexdigest()

    if actual != EXPECTED_WORKFLOW_JOB_DISPLAY_NAMES:
        raise AssertionError(
            "workflow-wide required-check producer census requires the exact "
            "reviewed workflow paths, job ids, and display names"
        )
    if dynamic_contexts != EXPECTED_DYNAMIC_JOB_CONTEXT_SHA256:
        raise AssertionError(
            "workflow-wide required-check producer census requires the exact "
            "reviewed matrix expansions for dynamic job display names"
        )

    actual_producers = {name: set() for name in REQUIRED_CHECK_JOB_PRODUCERS}
    reserved_expanded_names = set(REQUIRED_RELEASE_CHECKS) - set(
        REQUIRED_CHECK_JOB_PRODUCERS
    )
    for path, jobs in actual.items():
        for job_id, display_name in jobs.items():
            if display_name in actual_producers:
                actual_producers[display_name].add((path, job_id))
            if display_name in reserved_expanded_names:
                raise AssertionError(
                    "workflow job directly claims a release-required expanded "
                    f"context outside its reviewed producer: {path}:{job_id}: "
                    f"{display_name}"
                )

    if actual_producers != REQUIRED_CHECK_JOB_PRODUCERS:
        raise AssertionError(
            "workflow-wide release-required check producers do not match the "
            "reviewed workflow/job authority map"
        )


def real_check_job_authority_source(job: str) -> str:
    """Return the real check job's admission fields and top-level controls."""

    active_lines = classifier_active_job_source(job).splitlines()
    try:
        steps = active_lines.index("  steps:")
    except ValueError as error:
        raise AssertionError(
            "real Check & Test job is missing its steps mapping"
        ) from error
    authority = active_lines[: steps + 1]
    authority.extend(
        line
        for line in active_lines[steps + 1 :]
        if len(line) - len(line.lstrip()) == 2
    )
    return "\n".join(authority)


def assert_assertion_reachability_gate_wired(workflow: str) -> None:
    """Keep the gate that proves this suite's own checks are reachable.

    This suite cannot notice that one of its assertions stopped being called;
    that is how `assert_windows_public_support_contract` sat defined and
    unreferenced after a stale-base merge removed its call site. A separate
    gate answers that question, and this assertion is the other half of the
    pair: the reachability gate reports an orphaned check in this file, and
    this check reports a reachability gate that CI no longer runs. Removing
    either one turns the other red, so neither can be lost quietly.
    """

    # Match the invocation exactly rather than searching for the path. A
    # substring search accepts `run: # python3 <path>`, which leaves the path
    # in a line that does not itself start with `#` while running nothing.
    # active_lines() is the wrong tool here for a second reason: it strips
    # `/* */` for the shell and JavaScript it is normally handed, and ci.yml
    # holds a bare `docs/*` glob and a later `**/Cargo.lock` that the pattern
    # spans as one 24KB comment, taking most of the check job with it.
    command = f"python3 {ASSERTION_REACHABILITY_POLICY}"
    invocations = {command, f"run: {command}"}
    if not any(line.strip() in invocations for line in workflow.splitlines()):
        raise AssertionError(
            "ci.yml must run "
            f"{ASSERTION_REACHABILITY_POLICY}; without it an assertion can lose "
            "its call site and keep reporting green"
        )
    if not ASSERTION_REACHABILITY.is_file():
        raise AssertionError(
            f"{ASSERTION_REACHABILITY_POLICY} is missing; the release gates "
            "would no longer prove their own checks run"
        )


def assert_kin_vfs_mount_features_built(release: str) -> None:
    """Keep the shipped kin-vfs able to serve a mounted projection.

    Kin has four projections and only one of them, the injected shim, needs no
    feature flag. The published `kin-vfs` is built by this workflow from a
    pinned checkout, and with no `--features` it carries neither `nfs-start` nor
    `mount`, so every mount reports itself unavailable on every machine that
    installs Kin. That is invisible from the release side: the archive shape
    check greps for a file named `kin-vfs` and finds one either way, and nothing
    else reads what the binary can do.

    macOS builds `nfs` because it carries an NFS client in the base system, and
    Linux builds `fuse` because it carries libfuse far more widely than a
    configured NFS client. Both are asserted, because losing either one silently
    removes a platform's mount without removing anything a reader would notice.
    """

    release_lines = {line.strip() for line in release.splitlines()}
    if (
        'cargo build --locked --release --target "$VFS_TARGET" -p kin-vfs-cli --features nfs'
        not in release_lines
    ):
        raise AssertionError(
            "release.yml must build the macOS kin-vfs CLI with --features nfs; "
            "without it the shipped driver carries no nfs-start and every NFS "
            "mount reports itself unavailable on every install"
        )
    if (
        'cargo zigbuild --locked --release --target "${VFS_TARGET}.${floor}" -p kin-vfs-cli --features fuse'
        not in release_lines
    ):
        raise AssertionError(
            "release.yml must build the Linux kin-vfs CLI with --features fuse; "
            "without it the shipped driver carries no mount subcommand and every "
            "FUSE mount reports itself unavailable on every install"
        )


def assert_glibc_floor_guard_wired(ci: str, release: str) -> None:
    """Keep the floor that decides which Linux distributions can start Kin.

    kin and kin-daemon are static musl and carry no glibc floor. The kin-vfs
    pair is the only glibc-linked thing Kin publishes for Linux, and its floor
    used to be a property of the runner image rather than of anything under
    review: Rust std references pidfd_spawnp and pidfd_getpid as weak undefined
    symbols, the linker binds them to whatever libc the build host exports, and
    the ubuntu-24.04 images export them at GLIBC_2.39. v0.5.38 shipped a
    linux-aarch64 kin-vfs that the Debian 12 loader refused outright, while
    every check in the release stayed green, because nothing read the floor.

    Two halves are required here and neither is sufficient alone. The build
    must go through the pinned floor, reading it from the guard rather than
    recording it a second time, or the number the guard enforces and the number
    the build targets can drift apart. And the release must read the floor back
    off the packaged bytes, because a pin that quietly stops taking effect
    looks exactly like a pin that worked.
    """

    for path, policy in (
        (GLIBC_FLOOR_GUARD, GLIBC_FLOOR_GUARD_POLICY),
        (GLIBC_FLOOR_TEST, GLIBC_FLOOR_TEST_POLICY),
    ):
        if not path.is_file():
            raise AssertionError(
                f"{policy} is missing; the Linux archives could ship a kin-vfs "
                "no supported distribution can start and nothing would notice"
            )

    # Match whole invocations rather than searching for the path, which a
    # commented-out line would still satisfy.
    release_lines = {line.strip() for line in release.splitlines()}
    if GLIBC_FLOOR_RELEASE_CHECK not in release_lines:
        raise AssertionError(
            "release.yml must run "
            f"{GLIBC_FLOOR_GUARD_POLICY} against the packaged Linux binaries; "
            "the build's intent to pin a floor is not the same evidence as the "
            "floor of the bytes about to be published"
        )
    if GLIBC_FLOOR_BUILD_READ not in release_lines:
        raise AssertionError(
            "release.yml must read the glibc floor from "
            f"{GLIBC_FLOOR_GUARD_POLICY}; a build targeting one floor while the "
            "guard enforces another is worse than no guard"
        )
    if 'cargo zigbuild --locked --release --target "${VFS_TARGET}.${floor}"' not in release:
        raise AssertionError(
            "release.yml must build the Linux kin-vfs binaries against the "
            "pinned floor; a plain cargo build takes its floor from the runner "
            "image, which is what shipped an unloadable v0.5.38 kin-vfs"
        )

    # The tests are load-bearing rather than decorative: the guard's whole
    # answer is a parse of readelf output, and a parse that silently found
    # nothing would be a guard that cannot fail.
    ci_lines = {line.strip() for line in ci.splitlines()}
    if not ci_lines & {
        GLIBC_FLOOR_TEST_POLICY,
        f"{GLIBC_FLOOR_TEST_POLICY} \\",
        f"./{GLIBC_FLOOR_TEST_POLICY}",
        f"./{GLIBC_FLOOR_TEST_POLICY} \\",
    }:
        raise AssertionError(
            "ci.yml must run "
            f"{GLIBC_FLOOR_TEST_POLICY}; the guard reads a floor out of readelf "
            "output, and an unproven parse is a gate that cannot fail"
        )


def assert_kin_vfs_compat_gate_wired(ci: str) -> None:
    """Keep the pull-request half of the Kin/kin-vfs compatibility check.

    release.yml refuses a release whose Kin lock resolves a different
    kin-vfs-core than the pinned kin-vfs checkout builds. That comparison used
    to run only at release time, so a pull request moving the Kin lock passed
    every required context and went red after the tag existed, where the tag
    has already resolved its own workflows and no fix lands without cutting
    another tag. kin#788 was exactly that shape: its first commit moved the
    lock to 0.4.2 while the pin still built 0.3.0.

    The gate reads the pin out of release.yml instead of recording it a sixth
    time, so its unit tests are load-bearing rather than decorative: an
    extraction that silently found nothing would be a gate that cannot fail.
    Both halves are required here for that reason.
    """

    # Match whole invocations rather than searching for the path, which a
    # commented-out line would still satisfy.
    lines = {line.strip() for line in ci.splitlines()}
    command = f"node {KIN_VFS_COMPAT_GUARD_POLICY}"
    if not lines & {command, f"run: {command}"}:
        raise AssertionError(
            "ci.yml must run "
            f"{KIN_VFS_COMPAT_GUARD_POLICY}; without it a Kin lock change that "
            "outruns the immutable kin-vfs pin stays green until it reds a tag"
        )
    # The test list is a line-continuation block, so the invocation carries a
    # trailing backslash on every entry but the last.
    if not lines & {KIN_VFS_COMPAT_TEST_POLICY, f"{KIN_VFS_COMPAT_TEST_POLICY} \\"}:
        raise AssertionError(
            "ci.yml must run "
            f"{KIN_VFS_COMPAT_TEST_POLICY}; the gate reads the pin out of "
            "release.yml, and an unproven extraction is a gate that cannot fail"
        )
    for path, policy in (
        (KIN_VFS_COMPAT_GUARD, KIN_VFS_COMPAT_GUARD_POLICY),
        (KIN_VFS_COMPAT_TEST, KIN_VFS_COMPAT_TEST_POLICY),
    ):
        if not path.is_file():
            raise AssertionError(
                f"{policy} is missing; Kin could resolve a kin-vfs-core that "
                "the pinned release input does not build and no pull request "
                "would go red"
            )


def assert_installer_asset_guard_wired(ci: str, release: str) -> None:
    """Keep the check that every installer asset name is one the release ships.

    Each install surface builds a release asset name out of the platform it
    detects, and the release publishes a fixed list of names. Nothing compared
    the two lists, so a disagreement rode every release to date: the POSIX
    installer asks `windows` for a `.tar.gz`, mapping the MSYS, MINGW, and
    CYGWIN shells onto it, while the Windows leg published only a `.zip`. The
    documented curl command 404'd there and every check stayed green.

    The guard runs on pull requests against the workflow's own asset lists and
    again inside the release against the bytes staged for upload. The falsifier
    runs beside it because a guard nobody has watched fail is not evidence that
    it can, and this defect is exactly what a check that cannot fail looks like.
    """

    for path, policy in (
        (INSTALLER_ASSET_GUARD, INSTALLER_ASSET_GUARD_POLICY),
        (INSTALLER_ASSET_FALSIFIER, INSTALLER_ASSET_FALSIFIER_POLICY),
    ):
        if not path.is_file():
            raise AssertionError(
                f"{policy} is missing; an installer could ask a release for an "
                "asset it does not publish and nothing would notice"
            )

    # Match whole invocations rather than searching for the path, which a
    # commented-out line would still satisfy.
    ci_lines = {line.strip() for line in ci.splitlines()}
    missing = sorted(
        command
        for command in (
            f"python3 ./{INSTALLER_ASSET_GUARD_POLICY}",
            f"python3 ./{INSTALLER_ASSET_FALSIFIER_POLICY}",
        )
        if command not in ci_lines
    )
    if missing:
        raise AssertionError(
            "ci.yml must run " + " and ".join(missing) + "; without both, an "
            "installer asset name can stop being published and no pull request "
            "would go red"
        )

    release_command = f"run: python3 ./{INSTALLER_ASSET_GUARD_POLICY} --assets-dir ."
    if release_command not in {line.strip() for line in release.splitlines()}:
        raise AssertionError(
            f"release.yml must run {INSTALLER_ASSET_GUARD_POLICY} against the "
            "staged assets; the workflow's intent is not the same evidence as "
            "the bytes about to be uploaded"
        )


def assert_installer_archive_binary_guard_wired(ci: str) -> None:
    """Keep the check that the installer names binaries the archive carries.

    Resolving the right archive name is only half an install. Once the download
    lands, the installer names the binaries inside it, and a Windows archive
    carries `.exe`-suffixed names. The installer named the bare form on every
    platform, so its mandatory-daemon assertion failed against an archive that
    was present, complete, and checksum-verified, aborting after the user had
    already waited for the download.

    This guard reads source rather than staged bytes, so it belongs on pull
    requests alone. The falsifier runs beside it because a guard nobody has
    watched fail is not evidence that it can.
    """

    for path, policy in (
        (INSTALLER_BINARY_GUARD, INSTALLER_BINARY_GUARD_POLICY),
        (INSTALLER_BINARY_FALSIFIER, INSTALLER_BINARY_FALSIFIER_POLICY),
    ):
        if not path.is_file():
            raise AssertionError(
                f"{policy} is missing; the installer could name a binary the "
                "release archive does not carry and nothing would notice"
            )

    # Match whole invocations rather than searching for the path, which a
    # commented-out line would still satisfy.
    ci_lines = {line.strip() for line in ci.splitlines()}
    missing = sorted(
        command
        for command in (
            f"python3 ./{INSTALLER_BINARY_GUARD_POLICY}",
            f"python3 ./{INSTALLER_BINARY_FALSIFIER_POLICY}",
        )
        if command not in ci_lines
    )
    if missing:
        raise AssertionError(
            "ci.yml must run " + " and ".join(missing) + "; without both, the "
            "installer can abort on a complete archive and no pull request "
            "would go red"
        )


# A fixture in the exact shape ci.yml carries: a `case` arm whose glob ends in
# `/*`, a cache key holding `**/`, and a line between them that every assertion
# reading this file depends on being able to see.
ACTIVE_LINES_FIXTURE = """\
case "$path" in
  *.md | docs/*) ;;
esac
run: python3 ./scripts/the-line-between.py
key: ${{ hashFiles('**/Cargo.lock') }}
/* a real block comment
   spanning two lines */
const kept = 1;
/* a one-line block comment */
const alsoKept = 2;
"""
ACTIVE_LINES_SURVIVOR = "run: python3 ./scripts/the-line-between.py"


def assert_active_lines_cannot_span_unrelated_shell(workflows: dict[Path, str]) -> None:
    """Keep the comment stripper from eating the lines every assertion reads.

    `active_lines` used to strip `<# #>`, `/* */` and `<!-- -->` with three
    DOTALL regexes over the whole text, which cannot tell a comment from a pair
    of shell globs. In ci.yml the `docs/*)` arm of a `case` opened one and
    `hashFiles('**/Cargo.lock')` closed it: 46,138 characters, 48% of the file,
    were removed before any assertion saw them, and release-train.yml lost 24%
    the same way. An assertion that cannot see the line it names passes exactly
    like one that checked it, which is the shape this whole suite exists to
    prevent.

    No workflow contains a real block comment, so that stripping never removed
    one. The last check below is what keeps that true: if a workflow ever does
    open a block comment, this fails and asks for the decision to be reviewed
    here rather than discovered as a silent hole later.
    """

    kept = active_lines(ACTIVE_LINES_FIXTURE)
    if ACTIVE_LINES_SURVIVOR not in kept:
        raise AssertionError(
            "active_lines dropped a line between two unrelated shell globs; a "
            "glob is not a block comment and an assertion reading past one "
            "would pass without seeing what it names"
        )
    for survivor in ("const kept = 1;", "const alsoKept = 2;"):
        if survivor not in kept:
            raise AssertionError(f"active_lines dropped live source: {survivor}")
    for comment in ("a real block comment", "spanning two lines */", "a one-line block comment"):
        if any(comment in line for line in kept):
            raise AssertionError(
                f"active_lines kept a real block comment: {comment}; a commented-out "
                "validator would then satisfy a guard"
            )

    # The fixture has to be able to tell the two implementations apart. Without
    # this, a fixture that both forms handle identically would report a fix
    # that is not there.
    superseded = ACTIVE_LINES_FIXTURE
    for pattern in (r"<#.*?#>", r"/\*.*?\*/", r"<!--.*?-->"):
        superseded = re.sub(pattern, "", superseded, flags=re.DOTALL)
    if ACTIVE_LINES_SURVIVOR in {line.strip() for line in superseded.splitlines()}:
        raise AssertionError(
            "the active_lines fixture cannot distinguish the DOTALL form from "
            "the line-oriented one, so it proves nothing"
        )

    for workflow, content in sorted(workflows.items()):
        lines = content.splitlines()
        dropped = len(lines) - len(strip_block_comments(lines))
        if dropped:
            raise AssertionError(
                f"{workflow.relative_to(ROOT).as_posix()} opens a block comment "
                f"and loses {dropped} line(s) before any assertion reads it. If "
                "that comment is real, review this census; if it is a glob, the "
                "stripper is wrong again"
            )


def assert_release_version_gate_wired(ci: str) -> None:
    """Keep the version gate running on the pull request that carries a release.

    `scripts/check-release-version.mjs` has carried the right refusal since
    before the release train existed, and until this job it ran on no pull
    request at all. Its one real invocation sits inside the train's own
    branch-writer step, against a tree that step has just regenerated, so it
    passes once and never re-runs on the head that merges. A release pull
    request could therefore lose its version bump after that step and every
    check would stay green, after which the mint reads a workspace version
    whose tag already exists, reports nothing to release, and exits 0 on a
    fifteen-minute cron with no tag cut and nothing raised.

    Every clause below is load-bearing. The event restriction is what keeps the
    job off the merge queue, where there is no pull request to read a base sha
    from. The branch and label conditions are what scope it to releases: the
    gate refuses a release-affecting diff that does not move the version, and
    asking that of every pull request is a policy change wearing a bug fix's
    clothes. `fetch-depth: 0` is what lets it read the base commit's manifest
    at all. And the base and labels reach the script through the environment,
    never interpolated into a command line, because a pull-request label is
    text an outside contributor writes.
    """

    for path, policy in (
        (RELEASE_VERSION_GUARD, RELEASE_VERSION_GUARD_POLICY),
        (RELEASE_VERSION_FALSIFIER, RELEASE_VERSION_FALSIFIER_POLICY),
    ):
        if not path.is_file():
            raise AssertionError(
                f"{policy} is missing; a release pull request could drop its "
                "version bump and no check would go red"
            )

    job = workflow_job_blocks(ci).get("release-version")
    if job is None:
        raise AssertionError(
            "ci.yml must run the release version gate on pull requests; without "
            "that job the gate's only invocation is the release train's own "
            "branch writer, which never sees the head that merges"
        )

    # Comment-aware, but line by line rather than through `active_lines`.
    # That helper strips `/* ... */` with DOTALL, and ci.yml carries a `/*` and
    # a `*/` about 46,000 characters apart in unrelated shell, so running it
    # over the whole workflow deletes roughly a third of the file and every
    # assertion built on the result passes without ever seeing the lines it
    # names.
    job_lines = {
        line.strip()
        for line in job.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    for clause in (
        "github.event_name == 'pull_request' &&",
        "(github.head_ref == 'automation/release-next' ||",
        "contains(github.event.pull_request.labels.*.name, 'release:automated'))",
        "fetch-depth: 0",
        "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
        "PR_LABELS: ${{ join(github.event.pull_request.labels.*.name, ',') }}",
        f"run: node {RELEASE_VERSION_GUARD_POLICY}",
    ):
        if clause not in job_lines:
            raise AssertionError(
                "ci.yml must run the release version gate against the release "
                f"pull request's own base and labels; missing `{clause}`"
            )

    # Match whole invocations rather than searching for the path, which a
    # commented-out line would still satisfy.
    ci_lines = {line.strip() for line in ci.splitlines()}
    missing = sorted(
        command
        for command in (
            f"run: python3 ./{RELEASE_VERSION_FALSIFIER_POLICY}",
            f"./{RELEASE_INTENT_SUITE_POLICY} \\",
            f"{RELEASE_INTENT_SUITE_POLICY} \\",
            f"./{RELEASE_VERSION_SUITE_POLICY} \\",
            f"{RELEASE_VERSION_SUITE_POLICY} \\",
        )
        if command not in ci_lines
    )
    if missing:
        raise AssertionError(
            "ci.yml must run " + " and ".join(missing) + "; the guards' own "
            "suites and the run that watches them fail are the only evidence "
            "that either gate can refuse anything"
        )


def assert_check_consumer_authority(workflow: str) -> None:
    """Pin both jobs that can emit the release-required Check & Test contexts."""

    blocks = workflow_job_blocks(workflow)
    actual_names = {job: job_display_name(block) for job, block in blocks.items()}
    if actual_names != CI_JOB_DISPLAY_NAMES:
        raise AssertionError(
            "Check & Test consumer authority requires the exact reviewed CI job "
            "identity and display-name map"
        )

    stub = blocks.get("check-pr-fast-path")
    real = blocks.get("check")
    if stub is None or classifier_active_job_source(stub) != PULL_REQUEST_CHECK_STUB:
        raise AssertionError(
            "Check & Test consumer authority requires the exact inert "
            "pull-request job"
        )
    if (
        real is None
        or real_check_job_authority_source(real) != REAL_CHECK_JOB_AUTHORITY
    ):
        raise AssertionError(
            "Check & Test consumer authority requires the exact real check admission "
            "and matrix contract"
        )


def assert_macos_shard_authority(workflow: str) -> None:
    """Pin the sharded macOS producer of `Check & Test (macos-latest)`.

    Sharding a required context is the cheapest possible way to lose half a test
    suite. The shards publish names no ruleset requires, so nothing outside this
    file notices what they run; the aggregate publishes the name the ruleset
    does require, and it is a five-second job that compiles nothing. Everything
    that makes it evidence rather than decoration is asserted here, because none
    of it is visible from the context name:

    the aggregate admits only `success` from the shard roll-up, so a SKIPPED or
    CANCELLED shard fails it instead of passing it; it carries a one-value matrix,
    so a skipped aggregate publishes the bare name and cannot put a second check
    run under the required expanded one beside the documentation-only stub; the
    shards run the partitions, which together are the suite one unpartitioned run
    ran; one shard still runs the doctests nextest does not run; and fail-fast is
    off, so a red shard cannot cancel a sibling that was passing.
    """

    blocks = workflow_job_blocks(workflow)
    shards = blocks.get("check-macos")
    aggregate = blocks.get("check-macos-aggregate")
    if shards is None or aggregate is None:
        raise AssertionError(
            "macOS shard authority requires both the shard job and its aggregate"
        )
    if real_check_job_authority_source(aggregate) != MACOS_SHARD_AGGREGATE_AUTHORITY:
        raise AssertionError(
            "macOS shard authority requires the exact reviewed aggregate admission "
            "and matrix contract"
        )

    active_shards = classifier_active_job_source(shards)
    for policy in (
        MACOS_SHARD_RUNNER,
        MACOS_SHARD_INDEPENDENT_LEGS,
        MACOS_SHARD_MATRIX,
        MACOS_SHARD_PARTITION,
        MACOS_SHARD_DOCTESTS,
    ):
        require(active_shards, policy, "macOS shard authority")
    require(
        classifier_active_job_source(aggregate),
        MACOS_SHARD_SUCCESS_GATE,
        "macOS shard authority",
    )


def shard_step_conditions(job: str) -> dict[str, str]:
    """Map each named step of a job block to its `if:` condition, or "".

    Read from the rendered active source rather than by regex over the raw file,
    because a step's condition is decided by which step it sits under and a
    line-oriented search cannot see that. A step that carries no condition maps
    to the empty string, which is what makes "runs on both legs" an assertion
    rather than the absence of one.
    """

    conditions: dict[str, str] = {}
    name = None
    for line in classifier_active_job_source(job).splitlines():
        indent = len(line) - len(line.lstrip())
        if line.startswith("    - "):
            name = None
            body = line[len("    - ") :]
            if body.startswith("name: "):
                name = body[len("name: ") :].strip()
                conditions[name] = ""
        elif name is not None and indent == 6 and line.lstrip().startswith("if: "):
            conditions[name] = line.lstrip()[len("if: ") :].strip()
        elif indent <= 4 and not line.startswith("    - "):
            name = None
    return conditions


def assert_ubuntu_shard_authority(workflow: str) -> None:
    """Pin the sharded ubuntu producer of `Check & Test (ubuntu-latest)`.

    The macOS docstring above states why sharding a required context needs its
    own authority, and every word of it applies here. What is different is that
    the ubuntu job is also where every source-reading gate in this repository
    runs, so splitting it can lose a gate as well as half a suite, and the two
    failures look identical from outside: a faster green run.

    So the gate list is pinned by NAME rather than by count. A count is crossed
    by any twenty of twenty-one, and the one that goes missing is the one nobody
    named. Each gate must carry an explicit shard-1 condition, and each step a
    partition consumes must carry no shard condition at all, because a partition
    that ran without its build or its nextest install is not a partition of the
    suite.
    """

    blocks = workflow_job_blocks(workflow)
    shards = blocks.get("check")
    aggregate = blocks.get("check-aggregate")
    if shards is None or aggregate is None:
        raise AssertionError(
            "ubuntu shard authority requires both the shard job and its aggregate"
        )
    if real_check_job_authority_source(aggregate) != UBUNTU_SHARD_AGGREGATE_AUTHORITY:
        raise AssertionError(
            "ubuntu shard authority requires the exact reviewed aggregate admission "
            "and matrix contract"
        )

    active_shards = classifier_active_job_source(shards)
    for policy in (
        UBUNTU_SHARD_RUNNER,
        UBUNTU_SHARD_INDEPENDENT_LEGS,
        UBUNTU_SHARD_MATRIX,
        UBUNTU_SHARD_PARTITION,
        UBUNTU_SHARD_DOCTESTS,
    ):
        require(active_shards, policy, "ubuntu shard authority")
    require(
        classifier_active_job_source(aggregate),
        UBUNTU_SHARD_SUCCESS_GATE,
        "ubuntu shard authority",
    )

    conditions = shard_step_conditions(shards)
    for gate in UBUNTU_SHARD_ONE_ONLY_GATES:
        if gate not in conditions:
            raise AssertionError(
                f"ubuntu shard authority requires the gate {gate!r} to still run in "
                "this job; a gate that left it is a gate nothing runs"
            )
        if "matrix.shard == 1" not in conditions[gate]:
            raise AssertionError(
                f"ubuntu shard authority requires {gate!r} to be pinned to shard 1; "
                "a source-reading gate on both legs pays twice for one answer, and "
                "one on neither is a gate nothing runs"
            )
    for step in UBUNTU_SHARD_BOTH_LEGS_STEPS:
        if step not in conditions:
            raise AssertionError(
                f"ubuntu shard authority requires the step {step!r}, which a "
                "partition consumes"
            )
        if "matrix.shard" in conditions[step]:
            raise AssertionError(
                f"ubuntu shard authority requires {step!r} on both legs; a shard "
                "that ran without it did not run a partition of the suite"
            )


def cached_job_cache_inputs(workflow: str) -> dict[str, dict[str, str]]:
    """Map every job running `rust-cache` to that step's `with:` inputs."""

    inputs: dict[str, dict[str, str]] = {}
    for job, block in workflow_job_blocks(workflow).items():
        lines = classifier_active_job_source(block).splitlines()
        for index, line in enumerate(lines):
            if "uses: Swatinem/rust-cache@" not in line:
                continue
            found: dict[str, str] = {}
            for follow in lines[index + 1 :]:
                indent = len(follow) - len(follow.lstrip())
                stripped = follow.strip()
                if stripped == "with:":
                    continue
                # A new step, or a shallower key, ends this step's inputs.
                if stripped.startswith("- ") or indent <= 4:
                    break
                if ": " in stripped:
                    key, value = stripped.split(": ", 1)
                    found[key.strip()] = value.strip()
            inputs[job] = found
            break
    return inputs


def job_cargo_environment(block: str) -> dict[str, str]:
    """The job-level `env:` mapping, which rust-cache would otherwise hash."""

    lines = classifier_active_job_source(block).splitlines()
    try:
        start = lines.index("  env:")
    except ValueError:
        return {}
    environment: dict[str, str] = {}
    for line in lines[start + 1 :]:
        indent = len(line) - len(line.lstrip())
        if indent <= 2:
            break
        if ": " in line:
            key, value = line.strip().split(": ", 1)
            environment[key.strip()] = value.strip()
    return environment


def assert_shared_cache_key_jobs_declare_one_environment(workflow: str) -> None:
    """Keep the jobs that SHARE a cargo cache key on one declared environment.

    FIR-2744 turned `add-rust-environment-hash-key` off, because the hash it
    computes includes every toolchain the runner image happens to carry, so two
    jobs in one run drew different keys off the same prefix and could not share
    an entry. That fix is only safe because of what the hash's other half
    covered.

    The hash covers the toolchain versions AND every CARGO, CC, CFLAGS, CXX,
    CMAKE and RUST environment variable. Toolchain sensitivity survives the
    change, because the pin lives in `rust-toolchain.toml` and the toolchain
    action, both of which are in the key's lockfiles half. Environment
    sensitivity does not survive it.

    That loss is harmless for a job keyed on its own job id, which shares with
    nothing. It is not harmless where a `shared-key` deliberately points one
    job at another's entry: those jobs now agree on a key while declaring
    whatever environment they like, and a divergence would be a silent cache
    collision rather than a failure. Nothing else in this repository would
    notice, which is why it is asserted here.

    The check is the JOIN rather than the endpoints: it reads which jobs
    actually share a key out of the workflow and requires each such group to
    declare one environment, so a new sharer is covered the day it is added
    rather than the day someone remembers to list it.
    """

    inputs = cached_job_cache_inputs(workflow)
    if not inputs:
        raise AssertionError(
            "shared cache-key authority found no job running rust-cache, so it "
            "graded nothing; the extraction is broken or the action was renamed"
        )
    for job, found in inputs.items():
        if found.get("add-rust-environment-hash-key") != "false":
            raise AssertionError(
                "shared cache-key authority requires every rust-cache step to set "
                f"add-rust-environment-hash-key: false (FIR-2744); {job} does not"
            )

    blocks = workflow_job_blocks(workflow)
    # Which jobs share which key, read from the workflow rather than listed.
    # A `shared-key` naming another job's id joins that job's group; an
    # expression naming several joins all of them.
    groups: dict[str, set[str]] = {}
    for job, found in inputs.items():
        shared = found.get("shared-key")
        if shared is None:
            continue
        for other in inputs:
            if f"'{other}'" in shared or shared == other:
                groups.setdefault(other, {other}).add(job)
    if not groups:
        raise AssertionError(
            "shared cache-key authority found no shared-key at all, so it graded "
            "nothing; if sharing was removed on purpose, remove this check with it"
        )

    for owner, members in sorted(groups.items()):
        environments = {job: job_cargo_environment(blocks[job]) for job in sorted(members)}
        distinct = {tuple(sorted(env.items())) for env in environments.values()}
        if len(distinct) != 1:
            raise AssertionError(
                "shared cache-key authority requires every job sharing the "
                f"{owner!r} cargo cache key to declare one environment, because "
                "add-rust-environment-hash-key is off and nothing else would "
                f"notice a divergence: {environments}"
            )


def execute_docs_only_classifier(
    classifier: str,
    *,
    cwd: Path = ROOT,
    environment_overrides: dict[str, str] | None = None,
    privileged: bool = True,
    shell_wrapper: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Execute a classifier mutant on a push and return its emitted outputs."""

    source = classifier_shell_source(classifier)
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "github-output"
        source_path = Path(directory) / "classifier.sh"
        source_path.write_text(source, encoding="utf-8")
        environment = os.environ.copy()
        environment.update(
            {
                "BASH_ENV": "",
                "EVENT_NAME": "push",
                "BASE_SHA": "unused-on-push",
                "HEAD_SHA": "unused-on-push",
                "WORKSPACE": str(cwd),
                "GITHUB_OUTPUT": str(output),
            }
        )
        if environment_overrides is not None:
            environment.update(environment_overrides)
        command = [
            "bash",
            "--noprofile",
            "--norc",
            *(["-p"] if privileged else []),
            "-e",
            "-u",
            "-o",
            "pipefail",
            str(source_path),
        ]
        if shell_wrapper is not None:
            command = [
                "bash",
                "--noprofile",
                "--norc",
                "-c",
                shell_wrapper,
                "classifier-wrapper",
                str(source_path),
            ]
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        outputs = (
            output.read_text(encoding="utf-8").splitlines() if output.exists() else []
        )
    return result, outputs


def assert_classifier_bypass_rejected(
    label: str,
    workflow: str,
    *,
    execute: bool = True,
) -> None:
    """Prove a shell-equivalent bypass is rejected and would otherwise win."""

    expect_assertion(
        label,
        "closed-form",
        lambda: assert_docs_only_classifier_guard(workflow),
    )
    if not execute:
        return

    classifier = workflow_job_blocks(workflow)["changes"]
    result, outputs = execute_docs_only_classifier(classifier)
    assert_classifier_execution_won(label, result, outputs)


def assert_classifier_execution_won(
    label: str,
    result: subprocess.CompletedProcess[str],
    outputs: list[str],
    *,
    changed_path: str | None = None,
) -> None:
    """Prove a rejected authority mutation would report a docs-only push."""

    if result.returncode != 0:
        raise AssertionError(
            f"classifier falsification did not execute: {label}: "
            f"{result.stdout}{result.stderr}"
        )
    if not outputs or outputs[-1] != "docs_only=true":
        raise AssertionError(
            f"classifier falsification did not override push output: {label}: {outputs}"
        )
    if changed_path is not None and changed_path not in result.stdout.splitlines():
        raise AssertionError(
            f"classifier falsification did not inspect {changed_path}: "
            f"{label}: {result.stdout}"
        )


def assert_classifier_execution_failed_closed(
    label: str,
    result: subprocess.CompletedProcess[str],
    outputs: list[str],
) -> None:
    """Prove hostile inherited shell state leaves a push classified as code."""

    if result.returncode != 0:
        raise AssertionError(
            f"classifier fail-closed proof did not execute: {label}: "
            f"{result.stdout}{result.stderr}"
        )
    if outputs != ["docs_only=false"]:
        raise AssertionError(f"classifier did not fail closed: {label}: {outputs}")


def assert_classifier_execution_code_bearing(
    label: str,
    result: subprocess.CompletedProcess[str],
    outputs: list[str],
    *,
    changed_paths: tuple[str, ...],
) -> None:
    """Prove the real classifier rejects and reports a code-bearing diff."""

    if result.returncode != 0:
        raise AssertionError(
            f"classifier code-bearing proof did not execute: {label}: "
            f"{result.stdout}{result.stderr}"
        )
    if outputs != ["docs_only=false"]:
        raise AssertionError(
            f"classifier admitted a code-bearing diff: {label}: {outputs}"
        )
    reported = set(result.stdout.splitlines())
    missing = [path for path in changed_paths if path not in reported]
    if missing:
        raise AssertionError(
            f"classifier omitted code-bearing paths: {label}: {missing}: "
            f"{result.stdout}"
        )


def bash_supports_nameref() -> bool:
    """Return whether the local bash can execute the hosted nameref bypass."""

    probe = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            'target=original; original=false; declare -n ref="$target"; '
            'ref=true; [ "$original" = true ]',
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return probe.returncode == 0


def git_fixture_environment(directory: Path) -> dict[str, str]:
    """Return a process and Git-authority-clean fixture environment."""

    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
        and key not in {"LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"}
    }
    global_config = directory / "git-global-config"
    global_config.write_text("", encoding="utf-8")
    environment.update(
        {
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": str(global_config),
            "GIT_CONFIG_COUNT": "0",
            "GIT_ATTR_NOSYSTEM": "1",
        }
    )
    return environment


def run_fixture_git(
    repository: Path,
    environment: dict[str, str],
    *args: str,
) -> str:
    """Run the reviewed hosted-runner Git path for a hermetic fixture."""

    result = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            *args,
        ],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"classifier Git fixture failed: git {args}: {result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


def create_docs_only_git_fixture(directory: Path) -> tuple[Path, str, str]:
    """Create a hermetic two-commit repository with one docs-only change."""

    repository = directory / "repository"
    repository.mkdir()
    environment = git_fixture_environment(directory)

    def git(*args: str) -> str:
        return run_fixture_git(repository, environment, *args)

    git("init", "--initial-branch=main")
    git("config", "user.email", "kin@example.invalid")
    git("config", "user.name", "Kin")
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    git("add", "--all")
    git("commit", "-m", "seed")
    base_sha = git("rev-parse", "HEAD")

    docs = repository / "docs"
    docs.mkdir()
    (docs / "release-bot.md").write_text("docs-only\n", encoding="utf-8")
    git("add", "--all")
    git("commit", "-m", "docs only")
    head_sha = git("rev-parse", "HEAD")
    return repository, base_sha, head_sha


def create_classifier_authority_attack_fixture(
    directory: Path,
    base_workflow: str,
    hostile_workflow: str,
) -> tuple[Path, str, str, dict[str, str], tuple[Path, ...]]:
    """Create a code diff plus executable, Git-env, and replace-object attacks."""

    repository = directory / "authority-repository"
    repository.mkdir()
    environment = git_fixture_environment(directory)

    def git(*args: str) -> str:
        return run_fixture_git(repository, environment, *args)

    git("init", "--initial-branch=main")
    git("config", "user.email", "kin@example.invalid")
    git("config", "user.name", "Kin")
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    source = repository / "src"
    source.mkdir()
    (source / "lib.rs").write_text("pub fn authority() -> bool { true }\n")
    workflows = repository / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(base_workflow, encoding="utf-8")
    git("add", "--all")
    git("commit", "-m", "seed")
    base_sha = git("rev-parse", "HEAD")

    docs = repository / "docs"
    docs.mkdir()
    (docs / "release-bot.md").write_text("docs-only\n", encoding="utf-8")
    git("add", "--all")
    git("commit", "-m", "docs only")
    docs_sha = git("rev-parse", "HEAD")

    (source / "lib.rs").write_text("pub fn authority() -> bool { false }\n")
    (workflows / "ci.yml").write_text(hostile_workflow, encoding="utf-8")
    (repository / ".gitattributes").write_text(
        "src/lib.rs diff=hostile\n",
        encoding="utf-8",
    )
    attack = repository / "attack"
    attack.mkdir()
    path_git = attack / "git"
    path_git.write_text(
        "#!/bin/sh\nprintf '%s\\n' docs/decoy.md\n",
        encoding="utf-8",
    )
    path_git.chmod(0o755)
    external_marker = directory / "external-diff-ran"
    external_diff = attack / "external-diff"
    external_diff.write_text(
        f"#!/bin/sh\n: > {external_marker!s}\nexit 0\n",
        encoding="utf-8",
    )
    external_diff.chmod(0o755)
    textconv_marker = directory / "textconv-ran"
    textconv = attack / "textconv"
    textconv.write_text(
        f"#!/bin/sh\n: > {textconv_marker!s}\nprintf decoy\n",
        encoding="utf-8",
    )
    textconv.chmod(0o755)
    hostile_config = attack / "gitconfig"
    hostile_config.write_text(
        "[diff]\n"
        f"\texternal = {external_diff!s}\n"
        "\trenames = true\n"
        '[diff "hostile"]\n'
        f"\ttextconv = {textconv!s}\n",
        encoding="utf-8",
    )
    git("add", "--all")
    git("commit", "-m", "code and workflow attack")
    head_sha = git("rev-parse", "HEAD")
    git("replace", head_sha, docs_sha)

    hostile_environment = {
        "PATH": f"{attack!s}:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(attack),
        "XDG_CONFIG_HOME": str(attack),
        "LD_LIBRARY_PATH": str(attack),
        "GIT_DIR": str(attack / "decoy.git"),
        "GIT_WORK_TREE": str(attack),
        "GIT_INDEX_FILE": str(attack / "index"),
        "GIT_COMMON_DIR": str(attack / "common"),
        "GIT_OBJECT_DIRECTORY": str(attack / "objects"),
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(attack / "alternate-objects"),
        "GIT_EXEC_PATH": str(attack),
        "GIT_CONFIG": str(hostile_config),
        "GIT_CONFIG_NOSYSTEM": "0",
        "GIT_CONFIG_SYSTEM": str(hostile_config),
        "GIT_CONFIG_GLOBAL": str(hostile_config),
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "diff.external",
        "GIT_CONFIG_VALUE_0": str(external_diff),
        "GIT_CONFIG_KEY_1": "diff.hostile.textconv",
        "GIT_CONFIG_VALUE_1": str(textconv),
        "GIT_CONFIG_PARAMETERS": "'diff.renames'='true'",
        "GIT_ATTR_NOSYSTEM": "0",
        "GIT_EXTERNAL_DIFF": str(external_diff),
        "GIT_DIFF_OPTS": "--unified=0",
        "GIT_REPLACE_REF_BASE": "refs/replace",
    }
    return (
        repository,
        base_sha,
        head_sha,
        hostile_environment,
        (external_marker, textconv_marker),
    )


def workflow_structural_lines(content: str) -> list[tuple[int, int, str]]:
    """Return active YAML lines while excluding literal and folded bodies."""

    structural: list[tuple[int, int, str]] = []
    block_scalar_indent: int | None = None
    block_scalar = re.compile(
        r"^(?:-\s+)?[A-Za-z0-9_-]+:\s*[|>]"
        r"(?:[+-]?[1-9]?|[1-9][+-]?)?\s*(?:#.*)?$"
    )
    for line_number, line in enumerate(content.splitlines(), start=1):
        if block_scalar_indent is not None:
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            if indent > block_scalar_indent:
                continue
            block_scalar_indent = None

        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = line[: len(line) - len(line.lstrip())]
        if "\t" in indentation:
            raise AssertionError(
                f"workflow YAML indentation must use spaces: line {line_number}"
            )
        stripped = line.lstrip()
        indent = len(indentation)
        structural.append((line_number, indent, stripped))
        if block_scalar.fullmatch(stripped):
            block_scalar_indent = indent
    return structural


def canonical_step_field(
    workflow: Path,
    line_number: int,
    source: str,
) -> tuple[str, str]:
    """Parse one canonical block-style workflow-step field."""

    match = re.fullmatch(
        r"(?P<key>[A-Za-z][A-Za-z0-9-]*):(?P<value>.*)",
        source,
    )
    if match is None:
        raise AssertionError(
            f"{workflow.name}:{line_number} workflow step fields must use "
            "canonical unquoted `key:` syntax in a canonical block mapping"
        )
    key = match.group("key")
    if key not in CANONICAL_STEP_FIELDS:
        raise AssertionError(
            f"{workflow.name}:{line_number} workflow step field is not in the "
            f"canonical Actions grammar: {key}"
        )
    return key, match.group("value").strip()


def canonical_workflow_steps(
    workflow: Path,
    content: str,
) -> list[
    tuple[
        dict[str, tuple[int, int, str]],
        list[tuple[int, int, str]],
    ]
]:
    """Inventory steps under a fail-closed, actionlint-compatible block grammar."""

    structural = workflow_structural_lines(content)
    steps: list[
        tuple[
            dict[str, tuple[int, int, str]],
            list[tuple[int, int, str]],
        ]
    ] = []

    for steps_index, (steps_line, steps_indent, stripped) in enumerate(structural):
        steps_match = re.fullmatch(r"steps:(?P<value>.*)", stripped)
        if steps_match is None:
            continue
        steps_value = steps_match.group("value").strip()
        if steps_value and not steps_value.startswith("#"):
            raise AssertionError(
                f"{workflow.name}:{steps_line} workflow steps must use a "
                "canonical block sequence"
            )
        end = len(structural)
        for index in range(steps_index + 1, len(structural)):
            if structural[index][1] <= steps_indent:
                end = index
                break
        children = structural[steps_index + 1 : end]
        if not children:
            raise AssertionError(
                f"{workflow.name} steps mapping must contain canonical step entries"
            )

        list_indent = steps_indent + 2
        field_indent = list_indent + 2
        fields: dict[str, tuple[int, int, str]] | None = None
        step_lines: list[tuple[int, int, str]] = []

        def finish_step() -> None:
            nonlocal fields, step_lines
            if fields is None:
                return
            execution_fields = {"run", "uses"}.intersection(fields)
            if len(execution_fields) != 1:
                raise AssertionError(
                    f"{workflow.name}:{step_lines[0][0]} canonical workflow "
                    "steps must contain exactly one run or uses field"
                )
            steps.append((fields, step_lines))
            fields = None
            step_lines = []

        for line_number, indent, child in children:
            if indent == list_indent:
                finish_step()
                if not child.startswith("- "):
                    raise AssertionError(
                        f"{workflow.name}:{line_number} workflow steps must use "
                        "a canonical block mapping for every sequence item"
                    )
                fields = {}
                step_lines = [(line_number, indent, child)]
                key, value = canonical_step_field(
                    workflow,
                    line_number,
                    child[2:],
                )
                fields[key] = (line_number, field_indent, value)
                continue

            if fields is None:
                raise AssertionError(
                    f"{workflow.name}:{line_number} workflow step entries must "
                    "start at canonical two-space child indentation"
                )
            step_lines.append((line_number, indent, child))
            if indent == field_indent:
                key, value = canonical_step_field(workflow, line_number, child)
                if key in fields:
                    raise AssertionError(
                        f"{workflow.name}:{line_number} workflow step contains "
                        f"a duplicate {key} field"
                    )
                fields[key] = (line_number, field_indent, value)
            elif indent < field_indent:
                raise AssertionError(
                    f"{workflow.name}:{line_number} workflow step fields must "
                    "use canonical two-space child indentation"
                )
        finish_step()
    return steps


def yaml_uses_scalar(workflow: Path, line_number: int, value: str) -> str:
    """Decode the direct scalar forms permitted for every action reference."""

    double_quoted = re.fullmatch(r'"([^"\r\n]*)"\s*(?:#.*)?', value)
    if double_quoted is not None:
        action = double_quoted.group(1)
        if "\\" in action:
            raise AssertionError(
                f"{workflow.name}:{line_number} workflow uses scalar must not "
                "contain YAML escape sequences"
            )
        return action

    single_quoted = re.fullmatch(r"'([^'\r\n]*)'\s*(?:#.*)?", value)
    if single_quoted is not None:
        return single_quoted.group(1)

    plain = re.fullmatch(r"""([^#\s'"\\]+)\s*(?:#.*)?""", value)
    if plain is None or plain.group(1).startswith(("*", "&", "!", "{", "[", "|", ">")):
        raise AssertionError(
            f"{workflow.name}:{line_number} workflow uses must be one direct "
            "action scalar without aliases, anchors, tags, or flow values"
        )
    return plain.group(1)


def canonical_job_action_uses(workflow: Path, content: str) -> list[str]:
    """Inventory reusable-workflow references alongside action-step references."""

    actions: list[str] = []
    for block in workflow_job_blocks(content).values():
        for key, value in job_top_level_mapping_fields(block):
            if key == "uses":
                actions.append(yaml_uses_scalar(workflow, 0, value))
    return actions


def canonical_child_mapping(
    workflow: Path,
    step_lines: list[tuple[int, int, str]],
    parent_line: int,
    parent_indent: int,
) -> dict[str, tuple[int, str]]:
    """Parse a step field's canonical two-space-indented child mapping."""

    fields: dict[str, tuple[int, str]] = {}
    expected_indent = parent_indent + 2
    for line_number, indent, source in step_lines:
        if line_number <= parent_line:
            continue
        if indent <= parent_indent:
            break
        if indent != expected_indent:
            raise AssertionError(
                f"{workflow.name}:{line_number} workflow with inputs must use "
                "canonical two-space child indentation"
            )
        match = re.fullmatch(
            r"(?P<key>[A-Za-z][A-Za-z0-9_-]*):(?P<value>.*)",
            source,
        )
        if match is None:
            raise AssertionError(
                f"{workflow.name}:{line_number} workflow with inputs must use "
                "canonical unquoted `key:` syntax"
            )
        key = match.group("key")
        if key in fields:
            raise AssertionError(
                f"{workflow.name}:{line_number} workflow with mapping contains "
                f"a duplicate {key} input"
            )
        fields[key] = (line_number, match.group("value").strip())
    return fields


def assert_rust_cache_steps(workflows: dict[Path, str]) -> None:
    rust_cache_uses = 0
    for workflow, content in sorted(workflows.items()):
        for fields, step_lines in canonical_workflow_steps(workflow, content):
            uses_field = fields.get("uses")
            if uses_field is None:
                continue
            uses_line, _, uses_value = uses_field
            action = yaml_uses_scalar(workflow, uses_line, uses_value)
            if RUST_CACHE_REFERENCE.search(action) is None:
                continue
            rust_cache_uses += 1
            if action != RUST_CACHE_ACTION:
                raise AssertionError(
                    f"{workflow.name} uses rust-cache at an unpinned ref"
                )

            with_field = fields.get("with")
            if with_field is None:
                raise AssertionError(
                    f"{workflow.name} rust-cache step must contain one canonical "
                    "with mapping and one main-only save-if"
                )
            with_line, with_indent, with_value = with_field
            if with_value and not with_value.startswith("#"):
                raise AssertionError(
                    f"{workflow.name} rust-cache with field must be a canonical "
                    "block mapping"
                )
            inputs = canonical_child_mapping(
                workflow,
                step_lines,
                with_line,
                with_indent,
            )
            save = inputs.get("save-if")
            if save is None:
                raise AssertionError(
                    f"{workflow.name} rust-cache step must contain one canonical "
                    "with mapping and one main-only save-if"
                )
            _, save_value = save
            save_value = save_value.split(" #", 1)[0].rstrip()
            if save_value not in CACHE_SAVE_VALUES:
                raise AssertionError(
                    f"{workflow.name} rust-cache save-if must be the exact "
                    "main-only scalar or the exact restore-only scalar"
                )

        for action in canonical_job_action_uses(workflow, content):
            if RUST_CACHE_REFERENCE.search(action) is not None:
                raise AssertionError(
                    f"{workflow.name} rust-cache use must be a canonical "
                    "workflow action step, not a reusable-workflow job"
                )

    if rust_cache_uses == 0:
        raise AssertionError("no pinned rust-cache steps found")


def release_train_merge_policy_source(release_train: str) -> str:
    """Extract the exact merge-policy gate executed by the release train."""

    step_anchor = "      - name: Resolve releasable drift and SemVer intent"
    if step_anchor not in release_train:
        raise AssertionError(
            "release train no longer carries the step that owns the "
            f"merge-policy gate: {step_anchor.strip()}"
        )
    step_start = release_train.index(step_anchor)
    if "\n      - name:" not in release_train[step_start + 1 :]:
        raise AssertionError(
            "release train merge-policy step is no longer followed by another "
            "step, so its boundary cannot be resolved"
        )
    step_end = release_train.index("\n      - name:", step_start + 1)
    step = release_train[step_start:step_end]
    open_anchor = '          if [ -z "$MERGE_POLICY_TOKEN" ]; then'
    if open_anchor not in step:
        raise AssertionError(
            "release train merge-policy gate no longer opens with its "
            "installation-token guard, so the executed gate cannot be extracted"
        )
    source_start = step.index(open_anchor)
    close_anchor = "\n          git fetch origin"
    if close_anchor not in step[source_start:]:
        raise AssertionError(
            "release train merge-policy gate no longer ends before the origin "
            "fetch, so the executed gate cannot be extracted"
        )
    source_end = step.index(close_anchor, source_start)
    return textwrap.dedent(step[source_start:source_end])


def execute_merge_policy_gate(
    source: str,
    repository: dict[str, object] | None,
    *,
    token: str = "fixture-installation-token",
    raw: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute the real merge-policy gate against a fixture API response."""

    if (repository is None) == (raw is None):
        raise AssertionError(
            "merge-policy fixture needs exactly one of a repository object or "
            "a raw response body"
        )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        gate = root / "merge-policy-gate.sh"
        gate.write_text(source, encoding="utf-8")
        fixture = root / "repository.json"
        fixture.write_text(
            json.dumps(repository) if raw is None else raw, encoding="utf-8"
        )
        binaries = root / "bin"
        binaries.mkdir()
        shim = binaries / "gh"
        shim.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'if [ "${GH_TOKEN:-}" != "$MERGE_POLICY_EXPECTED_TOKEN" ]; then\n'
            '  echo "policy read presented the wrong token" >&2\n'
            "  exit 77\n"
            "fi\n"
            'cat "$MERGE_POLICY_FIXTURE"\n',
            encoding="utf-8",
        )
        shim.chmod(0o755)
        environment = dict(os.environ)
        environment.pop("GH_TOKEN", None)
        environment["PATH"] = f"{binaries}{os.pathsep}{environment['PATH']}"
        environment["MERGE_POLICY_FIXTURE"] = str(fixture)
        environment["MERGE_POLICY_TOKEN"] = token
        environment["MERGE_POLICY_EXPECTED_TOKEN"] = token
        environment["REPO"] = "firelock-ai/kin"
        return subprocess.run(
            ["bash", "-euo", "pipefail", str(gate)],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )


def assert_merge_policy_gate(release_train: str) -> None:
    """Keep an unreadable merge policy distinct from a violated one."""

    gate = release_train_merge_policy_source(release_train)
    enforced: dict[str, object] = {
        "allow_squash_merge": True,
        "allow_merge_commit": False,
        "allow_rebase_merge": False,
        "squash_merge_commit_title": "PR_TITLE",
        "squash_merge_commit_message": "PR_BODY",
    }
    accepted = execute_merge_policy_gate(gate, enforced)
    if accepted.returncode != 0:
        raise AssertionError(
            "release train merge-policy gate refused the enforced squash "
            f"policy: {accepted.stdout}{accepted.stderr}"
        )

    # Both refusals below read the emptiness of a jq result, and jq emits
    # nothing at all for a body that is not a JSON object, so a gate that
    # judged only those results would pass having read no policy whatsoever.
    for label, body in (
        ("an empty", ""),
        ("a whitespace-only", "   \n"),
        ("a JSON array", "[]"),
        ("a bare JSON string", '"not-an-object"'),
    ):
        unread = execute_merge_policy_gate(gate, None, raw=body)
        if unread.returncode == 0:
            raise AssertionError(
                f"release train merge-policy gate accepted {label} API "
                "response, so it passed without reading any policy"
            )
        if "was not a JSON object" not in unread.stdout:
            raise AssertionError(
                f"release train merge-policy gate must refuse {label} API "
                f"response by naming the response shape: "
                f"{unread.stdout}{unread.stderr}"
            )
        if "immutable PR-body release intent" in unread.stdout:
            raise AssertionError(
                "release train merge-policy gate blamed the repository "
                f"settings for {label} response it could not read"
            )

    # A response carrying none of the policy fields is exactly what a token
    # without push-level repository access receives. It cannot disprove the
    # policy, and calling it a violation sends recovery after a correct
    # repository instead of after the token that could not read it.
    unreadable = execute_merge_policy_gate(
        gate,
        {"full_name": "firelock-ai/kin", "permissions": {"push": False}},
    )
    if unreadable.returncode == 0:
        raise AssertionError(
            "release train merge-policy gate accepted a response that carried "
            "no merge policy at all"
        )
    if "absent from the API response" not in unreadable.stdout:
        raise AssertionError(
            "release train merge-policy gate must refuse an unreadable policy "
            f"as absent fields: {unreadable.stdout}{unreadable.stderr}"
        )
    if "immutable PR-body release intent" in unreadable.stdout:
        raise AssertionError(
            "release train merge-policy gate blamed the repository settings "
            "for a policy it never read"
        )

    for field, drift in (
        ("allow_squash_merge", False),
        ("allow_merge_commit", True),
        ("allow_rebase_merge", True),
        ("squash_merge_commit_title", "COMMIT_OR_PR_TITLE"),
        ("squash_merge_commit_message", "COMMIT_MESSAGES"),
    ):
        drifted = dict(enforced)
        drifted[field] = drift
        refused = execute_merge_policy_gate(gate, drifted)
        if refused.returncode == 0:
            raise AssertionError(
                f"release train merge-policy gate accepted drifted {field}"
            )
        if "immutable PR-body release intent" not in refused.stdout:
            raise AssertionError(
                f"release train merge-policy gate must refuse drifted {field} "
                f"as a policy violation: {refused.stdout}{refused.stderr}"
            )
        if field not in refused.stdout:
            raise AssertionError(
                "release train merge-policy gate must name the offending "
                f"setting {field}: {refused.stdout}"
            )
        if "absent from the API response" in refused.stdout:
            raise AssertionError(
                f"release train merge-policy gate reported present {field} "
                "as absent"
            )

    unscoped = execute_merge_policy_gate(gate, enforced, token="")
    if unscoped.returncode == 0:
        raise AssertionError(
            "release train merge-policy gate read the merge policy without "
            "the release App installation token"
        )


def rebind_release_pr_token(release_train: str, token: str) -> str:
    """Rewrite only the release-PR opener's own GH_TOKEN binding."""

    step = workflow_step_source(
        "release train", release_train, RELEASE_PR_STEP_ANCHOR
    )
    return release_train.replace(
        step,
        STEP_ENV_TOKEN_BINDING.sub(
            lambda _: f"          GH_TOKEN: {token}", step, count=1
        ),
        1,
    )


def assert_release_pr_author_identity(release_train: str) -> None:
    """The release pull request must be opened by the App, not by Actions.

    GitHub refuses `createPullRequest` from an Actions token wherever the
    organization withholds pull-request creation from workflows, so a train
    reaching this step on GITHUB_TOKEN dies holding a prepared release branch
    and no pull request to merge it. The App identity is load bearing a second
    time: only an App-authored pull request emits the events that start its own
    protected checks, which is what the activation fallback below it exists to
    supply when nothing else does. The binding is therefore behavior under
    test, not an incidental credential choice, and the alternative repair is
    the repository-wide toggle that would let any workflow open pull requests.
    """

    step = workflow_step_source(
        "release train", release_train, RELEASE_PR_STEP_ANCHOR
    )
    require(step, "gh pr create", "protected release PR opener")
    bindings = [
        match.group("token") for match in STEP_ENV_TOKEN_BINDING.finditer(step)
    ]
    if bindings != [RELEASE_APP_TOKEN]:
        raise AssertionError(
            "the step that opens the protected release PR must bind GH_TOKEN "
            f"to the minted App installation token {RELEASE_APP_TOKEN} exactly "
            f"once, and binds {bindings or '<nothing>'}. GitHub Actions is not "
            "permitted to create pull requests, so an Actions token here "
            "leaves every prepared release branch unopened"
        )
    if "GH_TOKEN=" in step:
        raise AssertionError(
            "the step that opens the protected release PR must not override "
            "GH_TOKEN inline, because a per-command token re-authors the pull "
            "request as an identity the step's environment no longer describes"
        )


def assert_release_pr_body_preserves_operator_text(
    release_train: str, merge_script: str
) -> None:
    """The train may own a delimited region of the release body, nothing more.

    This repository squashes with the pull-request body as the commit message,
    and the merge queue mints that message when the entry is admitted, so the
    release body is the release's permanent commit message rather than a
    description of it. The train used to overwrite the whole body with its own
    generic line on every reconcile cycle, which erased the disclosures the
    release doctrine requires an operator to add, and a cycle landing between
    that edit and queue admission would have shipped a release carrying none of
    them. A captain-side polling guard covered the window once; a guard that
    lives in a session can always be retired, so the preservation lives here.

    Reading the merge from protected main is load bearing for the same reason
    the proof gate's read is: a release branch that could carry its own body
    merge could decide what its own commit message says.
    """

    step = workflow_step_source(
        "release train", release_train, RELEASE_PR_STEP_ANCHOR
    )
    if '--body "' in step:
        raise AssertionError(
            "the release PR body must never be written from an inline literal: "
            "that overwrite is what discarded the operator-authored release "
            "disclosures the squash message has to carry"
        )
    for policy in (
        f"{TRUSTED_POLICY_PREFIX}{RELEASE_TRAIN_BODY_POLICY}",
        '--body-file "$initial_body"',
        '--body-file "$next_body"',
        '--json body',
    ):
        require(step, policy, "operator-preserving release PR body")
    index = step.find(RELEASE_TRAIN_BODY_POLICY)
    while index >= 0:
        prefix = step[max(0, index - len(TRUSTED_POLICY_PREFIX)) : index]
        if prefix != TRUSTED_POLICY_PREFIX:
            raise AssertionError(
                "the release PR body merge must be read from protected main. A "
                "branch that carries its own body merge decides what its own "
                "squash message says"
            )
        index = step.find(RELEASE_TRAIN_BODY_POLICY, index + 1)
    for marker in (RELEASE_TRAIN_BODY_BEGIN, RELEASE_TRAIN_BODY_END):
        require(merge_script, marker, "release PR body merge")


def release_branch_allowlist(release_train: str) -> str:
    """Return the regex the train uses to admit its own generated branch."""

    match = re.search(r"^\s*allowed='(?P<pattern>[^']+)'", release_train, re.M)
    if match is None:
        raise AssertionError(
            "release train no longer carries the generated-path allowlist that "
            "admits its own release branch"
        )
    return match.group("pattern")


def prepared_release_paths(generator: str) -> set[str]:
    """Return every repo path the release generator writes."""

    bindings = dict(re.findall(r"const\s+(\w+)\s*=\s*'([^']+)'\s*;", generator))
    paths: set[str] = set()
    # Array literals of paths, which is how the npm manifests are carried.
    for block in re.findall(r"const\s+\w+\s*=\s*\[([^\]]*)\]\s*;", generator):
        for literal in re.findall(r"'([^']+)'", block):
            if GENERATED_PATH_LITERAL.match(literal):
                paths.add(literal)
    # Direct writes, whether the destination is a literal or a bound constant.
    for argument in re.findall(r"fs\.writeFile\(\s*([^,\s]+)\s*,", generator):
        candidate = argument[1:-1] if argument.startswith("'") else bindings.get(argument)
        if candidate and GENERATED_PATH_LITERAL.match(candidate):
            paths.add(candidate)
    return paths


def assert_release_branch_allowlist_covers_generator(release_train: str) -> None:
    """The train must admit every path its own generator writes.

    These two drifted apart once already: the generator learned to bump a
    second lockfile and the allowlist did not, so the train refused the branch
    it had just written and no release could be prepared at all. Neither side
    is authority over the other, so the gate is that they agree.
    """

    allowed = re.compile(release_branch_allowlist(release_train))
    generated = prepared_release_paths(
        PREPARE_RELEASE.read_text(encoding="utf-8")
    )
    if not generated:
        raise AssertionError(
            "no generated release path could be resolved from "
            "prepare-release.mjs, so this cross-check proves nothing"
        )
    refused = sorted(path for path in generated if not allowed.match(path))
    if refused:
        raise AssertionError(
            "the release branch guard refuses paths the release generator "
            "writes, so the train cannot open the bump it just prepared: "
            f"{', '.join(refused)}"
        )


def release_check_gate_source(release_tag: str) -> str:
    """Extract the exact Python gate executed by the release-tag workflow."""

    step_start = release_tag.index("      - name: Verify required checks are green")
    step_end = release_tag.index("\n      - name:", step_start + 1)
    step = release_tag[step_start:step_end]
    marker = "          python3 - <<'PY'\n"
    source_start = step.index(marker) + len(marker)
    source_end = step.index("\n          PY", source_start)
    return textwrap.dedent(step[source_start:source_end])


def execute_release_check_gate(
    source: str,
    conclusions: dict[str, str],
    *,
    mutate_fixture: Callable[
        [
            list[dict[str, object]],
            list[dict[str, object]],
            dict[str, object],
        ],
        None,
    ]
    | None = None,
    parent_sha: str = RELEASE_GATE_PARENT_SHA,
) -> subprocess.CompletedProcess[str]:
    """Execute the real gate against a current-API-shaped provenance fixture.

    The default fixture is a merge-queue landing as the API actually reports
    one: every required context published once, by the queue's build of the
    exact sha that landed. That is the mint's authority, so the falsifications
    below mutate the evidence a release is really minted from rather than a
    second copy of it. Fixtures that need the landing push add it explicitly.
    """

    workflow_specs = {
        ".github/workflows/ci.yml": {
            "id": 1001,
            "workflow_id": 245_803_170,
            "path": ".github/workflows/ci.yml",
            "event": "merge_group",
            "head_branch": RELEASE_GATE_QUEUE_REF,
            "head_sha": RELEASE_GATE_FIXTURE_SHA,
            "status": "completed",
            "conclusion": "success",
            "check_suite_id": 101,
        },
        ".github/workflows/sast.yml": {
            "id": 1002,
            "workflow_id": 251_549_972,
            "path": ".github/workflows/sast.yml",
            "event": "merge_group",
            "head_branch": RELEASE_GATE_QUEUE_REF,
            "head_sha": RELEASE_GATE_FIXTURE_SHA,
            "status": "completed",
            "conclusion": "success",
            "check_suite_id": 102,
        },
        # secret-scan.yml carries no merge_group trigger. Inside the queue it
        # publishes from the push that creates the queue ref, which is why the
        # admitted tier is the ref and never the event name.
        ".github/workflows/secret-scan.yml": {
            "id": 1003,
            "workflow_id": 293_452_372,
            "path": ".github/workflows/secret-scan.yml",
            "event": "push",
            "head_branch": RELEASE_GATE_QUEUE_REF,
            "head_sha": RELEASE_GATE_FIXTURE_SHA,
            "status": "completed",
            "conclusion": "success",
            "check_suite_id": 103,
        },
        ".github/workflows/pr-text-hygiene.yml": {
            "id": 1004,
            "workflow_id": 328_945_626,
            "path": ".github/workflows/pr-text-hygiene.yml",
            "event": "merge_group",
            "head_branch": RELEASE_GATE_QUEUE_REF,
            "head_sha": RELEASE_GATE_FIXTURE_SHA,
            "status": "completed",
            "conclusion": "success",
            "check_suite_id": 107,
        },
    }
    workflow_runs = list(workflow_specs.values())
    current_run: dict[str, object] = {
        "id": RELEASE_GATE_CURRENT_RUN_ID,
        "workflow_id": RELEASE_TAG_WORKFLOW_ID,
        "path": ".github/workflows/release-tag.yml",
        "event": "workflow_run",
        "head_branch": "main",
        "head_sha": RELEASE_GATE_FIXTURE_SHA,
        "status": "in_progress",
        "conclusion": None,
        "check_suite_id": 104,
    }
    workflow_runs.append(current_run.copy())
    check_runs = []
    fixture_contexts = list(REQUIRED_RELEASE_CHECKS) + sorted(
        RULESET_ONLY_RELEASE_CHECKS
    )
    for index, name in enumerate(fixture_contexts, start=1):
        if name in RULESET_ONLY_RELEASE_CHECKS:
            workflow_path = RULESET_ONLY_RELEASE_CHECKS[name][1]
        else:
            _, workflow_path, _ = REQUIRED_RELEASE_CHECK_PROVENANCE[name]
        check_runs.append(
            {
                "name": name,
                "status": "completed",
                "conclusion": conclusions.get(name, "success"),
                "id": index,
                "app_id": GITHUB_ACTIONS_APP_ID,
                "app_slug": "github-actions",
                "check_suite_id": workflow_specs[workflow_path]["check_suite_id"],
                "head_sha": RELEASE_GATE_FIXTURE_SHA,
            }
        )
    check_runs.append(
        {
            "name": "Mint release tag",
            "status": "in_progress",
            "conclusion": None,
            "id": len(check_runs) + 1,
            "app_id": GITHUB_ACTIONS_APP_ID,
            "app_slug": "github-actions",
            "check_suite_id": current_run["check_suite_id"],
            "head_sha": RELEASE_GATE_FIXTURE_SHA,
        }
    )
    if mutate_fixture is not None:
        mutate_fixture(check_runs, workflow_runs, current_run)

    with tempfile.TemporaryDirectory() as directory:
        fixture = Path(directory)
        (fixture / "check_runs.ndjson").write_text(
            "".join(f"{json.dumps(run)}\n" for run in check_runs),
            encoding="utf-8",
        )
        (fixture / "workflow_runs.ndjson").write_text(
            "".join(f"{json.dumps(run)}\n" for run in workflow_runs),
            encoding="utf-8",
        )
        (fixture / "current_run.json").write_text(
            json.dumps(current_run),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment.update(
            {
                "CURRENT_RUN_ID": str(RELEASE_GATE_CURRENT_RUN_ID),
                "CURRENT_RUN_EVENT": str(current_run["event"]),
                "REQUIRED_CHECKS": "\n".join(REQUIRED_RELEASE_CHECKS),
                "RULESET_REQUIRED_CHECKS": "\n".join(
                    list(REQUIRED_RELEASE_CHECKS) + sorted(RULESET_ONLY_RELEASE_CHECKS)
                ),
                "SHA": RELEASE_GATE_FIXTURE_SHA,
                "RELEASE_PARENT_SHA": parent_sha,
                "TRIGGER_SHA": RELEASE_GATE_FIXTURE_SHA,
                "GITHUB_ACTIONS_APP_ID": str(GITHUB_ACTIONS_APP_ID),
                "GITHUB_ACTIONS_APP_SLUG": "github-actions",
            }
        )
        return subprocess.run(
            [sys.executable, "-c", source],
            cwd=fixture,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )


def assert_release_gate_fixture_rejected(
    source: str,
    label: str,
    expected_error: str,
    mutate_fixture: Callable[
        [
            list[dict[str, object]],
            list[dict[str, object]],
            dict[str, object],
        ],
        None,
    ],
) -> None:
    """Require a provenance/collision fixture to fail for the expected reason."""

    result = execute_release_check_gate(
        source,
        {},
        mutate_fixture=mutate_fixture,
    )
    output = result.stdout + result.stderr
    if result.returncode == 0:
        raise AssertionError(f"release gate falsification was admitted: {label}")
    if expected_error not in output:
        raise AssertionError(
            f"release gate falsification failed for the wrong reason: {label}: {output}"
        )


def assert_release_check_rejected(
    source: str,
    check_name: str,
    conclusion: str,
) -> None:
    result = execute_release_check_gate(source, {check_name: conclusion})
    output = result.stdout + result.stderr
    expected = f"required check not green: {check_name} (conclusion={conclusion})"
    if result.returncode == 0:
        raise AssertionError(
            f"release check falsification admitted {check_name}={conclusion}"
        )
    if expected not in output:
        raise AssertionError(
            "release check falsification failed without the expected refusal: "
            f"{check_name}={conclusion}: {output}"
        )


def assert_release_check_accepted(
    source: str,
    check_name: str,
    conclusion: str,
) -> None:
    result = execute_release_check_gate(source, {check_name: conclusion})
    if result.returncode != 0:
        raise AssertionError(
            "release check falsification rejected an allowed conclusion: "
            f"{check_name}={conclusion}: {result.stdout}{result.stderr}"
        )

def assert_release_gate_admits(
    source: str,
    label: str,
    expected: tuple[str, ...],
    mutate_fixture: Callable[
        [
            list[dict[str, object]],
            list[dict[str, object]],
            dict[str, object],
        ],
        None,
    ],
) -> None:
    """Require a fixture to be admitted, and to announce what it admitted over.

    A downgrade that is not announced is worse than the refusal it replaces, so
    admission and announcement are asserted together and never separately.
    """

    result = execute_release_check_gate(source, {}, mutate_fixture=mutate_fixture)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise AssertionError(
            f"release gate refused an admissible fixture: {label}: {output}"
        )
    for needle in expected:
        if needle not in output:
            raise AssertionError(
                f"release gate admitted {label} silently, expected {needle!r}: "
                f"{output}"
            )


def run_tag_selector(
    manifest: str,
    candidates: str,
    minting_tag: str = "",
) -> tuple[subprocess.CompletedProcess[str], str]:
    """Execute the shipped admission selector against fixture inputs."""

    with tempfile.TemporaryDirectory() as directory:
        fixture = Path(directory)
        manifest_path = fixture / "abandoned-release-tags.json"
        manifest_path.write_text(manifest, encoding="utf-8")
        candidates_path = fixture / "release-tags"
        candidates_path.write_text(candidates, encoding="utf-8")
        selected_path = fixture / "highest-admissible-tag"
        completed = subprocess.run(
            [
                sys.executable,
                str(TAG_SELECTOR),
                str(manifest_path),
                str(candidates_path),
                minting_tag,
                str(selected_path),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        selected = ""
        if selected_path.exists():
            selected = selected_path.read_text(encoding="utf-8")
    return completed, selected


def assert_admissible_tag(
    label: str,
    manifest: str,
    candidates: str,
    expected: str,
    *,
    minting_tag: str = "",
) -> None:
    """Require the selector to name exactly the tag the rail must wait on."""

    completed, selected = run_tag_selector(manifest, candidates, minting_tag)
    if completed.returncode != 0:
        raise AssertionError(
            f"release-lane admission refused {label}: "
            f"{completed.stdout}{completed.stderr}"
        )
    if selected != expected:
        raise AssertionError(
            f"release-lane admission selected {selected or '<none>'} for "
            f"{label}, expected {expected or '<none>'}"
        )


def assert_tag_selection_refused(
    label: str,
    manifest: str,
    candidates: str,
    expected_error: str,
    *,
    minting_tag: str = "",
) -> None:
    """Require a loud, named refusal rather than a silently degraded skip."""

    completed, selected = run_tag_selector(manifest, candidates, minting_tag)
    output = completed.stdout + completed.stderr
    if completed.returncode == 0:
        raise AssertionError(f"release-lane admission accepted {label}: {output}")
    if expected_error not in output:
        raise AssertionError(
            f"release-lane admission refused {label} for the wrong reason: {output}"
        )
    if selected:
        raise AssertionError(
            f"release-lane admission named {selected} while refusing {label}"
        )


def abandonment_manifest(*records: dict[str, str]) -> str:
    """Serialize an abandonment record the way the tracked file carries it."""

    return json.dumps({"schema_version": 1, "abandoned": list(records)})


def workflow_step_source(workflow: str, content: str, step_anchor: str) -> str:
    """Extract one named workflow step so its internals can be judged."""

    if step_anchor not in content:
        raise AssertionError(
            f"{workflow} no longer carries the step this gate is anchored to: "
            f"{step_anchor.strip()}"
        )
    start = content.index(step_anchor)
    if "\n      - name:" not in content[start + 1 :]:
        raise AssertionError(
            f"{workflow} step {step_anchor.strip()} is no longer followed by "
            "another step, so its boundary cannot be resolved"
        )
    return content[start : content.index("\n      - name:", start + 1)]


def assert_trusted_abandonment_reads(workflow: str, content: str) -> None:
    """Both admission policies must come from protected main, nowhere else."""

    for policy in (ABANDONED_TAGS_POLICY, TAG_SELECTOR_POLICY):
        index = content.find(policy)
        if index < 0:
            raise AssertionError(f"{workflow} never reads {policy}")
        while index >= 0:
            prefix = content[max(0, index - len(TRUSTED_POLICY_PREFIX)) : index]
            if prefix != TRUSTED_POLICY_PREFIX:
                raise AssertionError(
                    f"{workflow} reads {policy} from something other than "
                    "protected main. The release commit under admission can "
                    "predate the abandonment it must honour, so reading either "
                    "policy from the checkout re-deadlocks the lane it unblocks"
                )
            index = content.find(policy, index + 1)


def assert_admission_step_order(
    workflow: str,
    content: str,
    step_anchor: str,
    comparison: str,
) -> None:
    """The waiver must be read, then applied, before the lane predicate runs."""

    step = workflow_step_source(workflow, content, step_anchor)
    manifest_read = step.index(f"{TRUSTED_POLICY_PREFIX}{ABANDONED_TAGS_POLICY}")
    selector_read = step.index(f"{TRUSTED_POLICY_PREFIX}{TAG_SELECTOR_POLICY}")
    selection = step.index('python3 "$selector"')
    adoption = step.index('highest_tag="$(cat "$admissible")"')
    predicate = step.index(comparison)
    if not manifest_read < selector_read < selection < adoption < predicate:
        raise AssertionError(
            f"{workflow} must read the reviewed abandonment record and its "
            "selector from protected main, resolve the highest admissible tag, "
            "and only then admit against finalized GitHub Latest"
        )
    if "git tag --list" in step:
        raise AssertionError(
            f"{workflow} still ranks release tags without consulting the "
            "reviewed abandonment record"
        )


def selector_invocation(workflow: str, content: str) -> tuple[str, ...]:
    """Return the exact argument list a workflow hands the admission selector.

    Every invocation is read, not the first. A second one is what would defeat
    this pin: it can re-run the selector with any argument at all and overwrite
    the file the workflow then adopts as the highest admissible tag, so pinning
    only the first would leave the guard describing bytes that no longer decide
    the outcome.
    """

    anchor = 'python3 "$selector"'
    invocations: list[tuple[str, ...]] = []
    for match in re.finditer(re.escape(anchor), content):
        tail = content[match.end() :]
        if not tail.startswith(" \\\n"):
            raise AssertionError(
                f"{workflow} invokes the admission selector without a "
                "reviewable multi-line argument list"
            )
        arguments: list[str] = []
        for line in tail[len(" \\\n") :].splitlines():
            argument = line.strip()
            if argument.endswith("\\"):
                arguments.append(argument[:-1].strip())
                continue
            arguments.append(argument)
            break
        invocations.append(tuple(arguments))
    if len(invocations) != 1:
        raise AssertionError(
            f"{workflow} must invoke the admission selector exactly once, so "
            "one reviewed argument list decides the highest admissible tag: "
            f"found {len(invocations)}"
        )
    return invocations[0]


def tag_readback_source(release_tag: str) -> str:
    """Extract the post-mint ref readback exactly as the workflow runs it."""

    anchor = "      - name: Verify tag ref and summarize\n"
    if anchor not in release_tag:
        raise AssertionError(
            "release-tag no longer carries the post-mint ref readback step"
        )
    start = release_tag.index(anchor)
    end = release_tag.index("\n      - name:", start + 1) if (
        "\n      - name:" in release_tag[start + 1 :]
    ) else len(release_tag)
    step = release_tag[start:end]
    marker = "        run: |\n"
    return textwrap.dedent(step[step.index(marker) + len(marker) :])


def execute_tag_readback(
    source: str,
    responses: list[tuple[int, str]],
) -> subprocess.CompletedProcess[str]:
    """Run the readback against a scripted sequence of API answers."""

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        script = root / "readback.sh"
        script.write_text(source, encoding="utf-8")
        (root / "responses").write_text(
            "".join(f"{code} {body}\n" for code, body in responses),
            encoding="utf-8",
        )
        (root / "attempts").write_text("0", encoding="utf-8")
        binaries = root / "bin"
        binaries.mkdir()
        (binaries / "gh").write_text(
            "#!/usr/bin/env bash\n"
            'attempt="$(cat "$FIXTURE/attempts")"\n'
            'attempt=$((attempt + 1))\n'
            'printf %s "$attempt" > "$FIXTURE/attempts"\n'
            'line="$(sed -n "${attempt}p" "$FIXTURE/responses")"\n'
            '[ -n "$line" ] || line="$(tail -n 1 "$FIXTURE/responses")"\n'
            'code="${line%% *}"; body="${line#* }"\n'
            '[ "$code" = 0 ] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }\n'
            'printf "%s\\n" "$body"\n',
            encoding="utf-8",
        )
        (binaries / "gh").chmod(0o755)
        # The exhaustion path sleeps ~30s in production; the fixture proves the
        # control flow, not the wall clock.
        (binaries / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        (binaries / "sleep").chmod(0o755)
        environment = dict(os.environ)
        environment["PATH"] = f"{binaries}{os.pathsep}{environment['PATH']}"
        environment.update(
            {
                "FIXTURE": str(root),
                "GH_TOKEN": "fixture",
                "REPO": "firelock-ai/kin",
                "ACTOR": "kin-release-bot[bot]",
                "TAG": "v9.9.9",
                "SHA": RELEASE_GATE_FIXTURE_SHA,
                "GITHUB_STEP_SUMMARY": str(root / "summary.md"),
                "RUNNER_TEMP": str(root),
            }
        )
        return subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=environment,
            timeout=30,
            check=False,
        )


def assert_tag_readback_retries(release_tag: str) -> None:
    """A minted tag must never be reported failed because a read was early."""

    source = tag_readback_source(release_tag)
    good = (0, RELEASE_GATE_FIXTURE_SHA)
    missing = (404, "")

    immediate = execute_tag_readback(source, [good])
    if immediate.returncode != 0:
        raise AssertionError(
            f"post-mint readback failed on a readable ref: "
            f"{immediate.stdout}{immediate.stderr}"
        )

    # The observed defect: the ref exists, the first reads 404, and the mint
    # concluded failure on a release it had already created.
    delayed = execute_tag_readback(source, [missing, missing, good])
    if delayed.returncode != 0:
        raise AssertionError(
            "post-mint readback reported a successful mint as failed because "
            f"the ref was not visible yet: {delayed.stdout}{delayed.stderr}"
        )
    if "retrying" not in delayed.stdout:
        raise AssertionError(
            "post-mint readback must say it is retrying, so a slow read is "
            f"legible in the log: {delayed.stdout}"
        )

    absent = execute_tag_readback(source, [missing])
    if absent.returncode == 0:
        raise AssertionError("post-mint readback accepted a ref that never appeared")
    if "never read back" not in absent.stdout:
        raise AssertionError(
            "post-mint readback must distinguish exhausted reads from a "
            f"mismatch: {absent.stdout}{absent.stderr}"
        )
    # The reason the API gave has to survive into the refusal. A persistent
    # auth or rate-limit failure reads identically to a missing ref from here,
    # and reporting it as absence sends an operator after a tag that exists.
    if "last reason:" not in absent.stdout or "Not Found" not in absent.stdout:
        raise AssertionError(
            "post-mint readback must report why the read failed rather than "
            f"asserting the tag is gone: {absent.stdout}"
        )

    # A ref that reads back pointing elsewhere is terminal on the first read.
    # Retrying it would be waiting for someone else's tag to change.
    mismatch = execute_tag_readback(source, [(0, "0" * 40)])
    if mismatch.returncode == 0:
        raise AssertionError("post-mint readback accepted a ref at the wrong commit")
    if "points at" not in mismatch.stdout:
        raise AssertionError(
            f"post-mint readback must name the wrong commit: {mismatch.stdout}"
        )
    if "retrying" in mismatch.stdout:
        raise AssertionError(
            "post-mint readback retried a ref that resolved to another commit, "
            "which cannot become correct by waiting"
        )


def assert_required_context_action_pins(workflows: dict[Path, str]) -> None:
    """Pin the supply chain of anything that can write a required release context.

    A required context is the evidence a release is minted from, so an action
    running inside its producer can decide what that evidence says. A floating
    tag leaves that decision with whoever can move the tag upstream.
    """

    for path, expected in EXPECTED_REQUIRED_CONTEXT_ACTION_PINS.items():
        content = workflows.get(ROOT / path)
        if content is None:
            raise AssertionError(f"required-context producer is missing: {path}")
        # Every reference is collected, not the last one seen per action. Each
        # `uses:` executes, so a single unpinned reference is an unpinned
        # execution however many pinned ones sit beside it, and whichever order
        # they appear in. Keying on one reference per action hid exactly that:
        # a floating duplicate placed above the pinned line was overwritten by
        # it and the guard stayed green while the floating ref still ran.
        observed: dict[str, set[str]] = {}
        for reference in re.findall(r"uses:\s*(\S+)", content):
            if reference.startswith("actions/"):
                continue
            # A `./` reference resolves inside the checkout this workflow already
            # made, so it carries no upstream that could move under the pin and
            # has no immutable object to name. It changes only by a reviewed pull
            # request to this repository, which is the same control the pin buys.
            if reference.startswith("./"):
                continue
            action, _, version = reference.partition("@")
            observed.setdefault(action, set()).add(version)
        if set(observed) != set(expected):
            raise AssertionError(
                f"{path} produces a presence-required release context, so its "
                "third-party action set must stay exactly as reviewed: "
                f"expected={sorted(expected)} actual={sorted(observed)}"
            )
        for action, references in sorted(observed.items()):
            pin = expected[action]
            if not re.fullmatch(r"[0-9a-f]{40}", pin):
                raise AssertionError(
                    f"{path} pins {action} to '{pin}', which is a movable ref "
                    "rather than an immutable commit"
                )
            drifted = sorted(reference for reference in references if reference != pin)
            if drifted:
                raise AssertionError(
                    f"{path} runs {action} at {drifted} alongside its reviewed "
                    f"pin {pin}; every reference to it must be that pin, "
                    "because each one executes"
                )


def recovery_step_script(release_recovery: str, anchor: str) -> str:
    """Extract a recovery step's script exactly as the controller runs it."""

    if anchor not in release_recovery:
        raise AssertionError(
            f"release-recovery no longer carries {anchor.strip()!r}"
        )
    start = release_recovery.index(anchor)
    remainder = release_recovery[start + 1 :]
    end = (
        release_recovery.index("\n      - name:", start + 1)
        if "\n      - name:" in remainder
        else len(release_recovery)
    )
    step = release_recovery[start:end]
    marker = "        run: |\n"
    return textwrap.dedent(step[step.index(marker) + len(marker) :])


def recovery_escalation_source(release_recovery: str) -> str:
    """Extract the escalation step exactly as the recovery controller runs it."""

    return recovery_step_script(
        release_recovery,
        "      - name: Alert after automatic retries are exhausted\n",
    )


RECOVERY_CLASSIFIER_ANCHOR = (
    "      - name: Classify the failure signature across attempts\n"
)
RECOVERY_FIXTURE_RUN_ID = "4242"


def write_attempt_job_fixtures(
    responses: Path,
    attempt_signatures: list[object],
) -> None:
    """Write one jobs-API response per attempt in the shape GitHub returns.

    A failure entry is `(job, step)`, or `(job, step, job_conclusion)` when the
    job's own conclusion differs from its failing step's — the shape a matrix
    leg takes when a sibling's failure cancels it mid-step. A `None` step is a
    job that failed while recording no failing step at all.
    """

    for index, signature in enumerate(attempt_signatures, start=1):
        if signature is None:
            continue
        # A single failing job makes the jobs API's ordering irrelevant,
        # which is the shape production never produces for a matrix
        # failure. Every attempt therefore carries its failures in the
        # order given, so a caller can vary it the way real queue-time job
        # ids do.
        failures = [signature] if isinstance(signature, tuple) else list(signature)
        jobs: list[dict[str, object]] = [
            {
                "name": "Preflight",
                "conclusion": "success",
                "steps": [{"name": "Checkout", "conclusion": "success"}],
            }
        ]
        for failure in failures:
            job, step_name = failure[0], failure[1]
            job_conclusion = failure[2] if len(failure) > 2 else "failure"
            steps: list[dict[str, object]] = [
                {"name": "Checkout", "conclusion": "success"}
            ]
            if step_name is not None:
                steps.append({"name": step_name, "conclusion": "failure"})
            jobs.append(
                {
                    "name": job,
                    "conclusion": job_conclusion,
                    "steps": steps,
                }
            )
        payload = {"jobs": jobs}
        target = (
            f"repos_firelock-ai_kin_actions_runs_{RECOVERY_FIXTURE_RUN_ID}"
            f"_attempts_{index}_jobs"
        )
        (responses / target).write_text(json.dumps(payload), encoding="utf-8")


def read_step_outputs(path: Path) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            outputs[key] = value
    return outputs


def run_recovery_classifier_in(
    root: Path,
    source: str,
    attempt_signatures: list[object],
) -> dict[str, str]:
    """Run the classifier inside a prepared fixture root and return its outputs.

    The root must already carry `responses/` and the `gh` stub in `bin/`. The
    classifier's signature file lands in this same directory because the alert
    step reads it from RUNNER_TEMP, which is how the two steps share one
    classification inside a single job.

    The classifier decides whether a retry is spent, so it must never fail the
    reconcile job: a controller that dies here neither retries nor alerts, and
    the release lane silently stops moving. That is asserted on every run
    rather than in one dedicated case.
    """

    script = root / "classify.sh"
    script.write_text(source, encoding="utf-8")
    outputs_file = root / "classifier-output"
    outputs_file.write_text("", encoding="utf-8")
    environment = dict(os.environ)
    environment["PATH"] = f"{root / 'bin'}{os.pathsep}{environment['PATH']}"
    environment.update(
        {
            "FIXTURE": str(root),
            "GH_TOKEN": "fixture",
            "REPO": "firelock-ai/kin",
            "RUN_ID": RECOVERY_FIXTURE_RUN_ID,
            "ATTEMPTS": str(len(attempt_signatures)),
            "RUNNER_TEMP": str(root),
            "GITHUB_OUTPUT": str(outputs_file),
        }
    )
    completed = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "the recovery classifier must never fail the reconcile job, "
            "because a controller that dies here neither retries nor alerts: "
            f"{completed.stdout}{completed.stderr}"
        )
    return read_step_outputs(outputs_file)


def execute_recovery_classifier(
    source: str,
    attempt_signatures: list[object],
) -> dict[str, str]:
    """Run the classifier against scripted attempt jobs and return its outputs."""

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        responses = root / "responses"
        responses.mkdir()
        write_attempt_job_fixtures(responses, attempt_signatures)
        binaries = root / "bin"
        binaries.mkdir()
        write_recovery_gh_stub(binaries)
        return run_recovery_classifier_in(root, source, attempt_signatures)


def write_recovery_gh_stub(binaries: Path) -> None:
    """A `gh` that answers `-q` with the real `jq`.

    A stub that returned canned answers would exercise the shell and leave the
    jq that does the classifying unproven.
    """

    (binaries / "gh").write_text(
        textwrap.dedent(
            """\
                #!/usr/bin/env bash
                set -uo pipefail
                case "$1" in
                  api)
                    shift
                    path=""; query=""; slurp=0
                    while [ $# -gt 0 ]; do
                      case "$1" in
                        -q|--jq) shift; query="$1" ;;
                        --slurp) slurp=1 ;;
                        -*) ;;
                        *) [ -n "$path" ] || path="$1" ;;
                      esac
                      shift
                    done
                    path="${path%%\\?*}"
                    file="$FIXTURE/responses/$(printf '%s' "$path" | tr '/' '_')"
                    if [ -f "$file.error" ]; then
                      cat "$file.error" >&2
                      exit 1
                    fi
                    if [ ! -f "$file" ]; then
                      echo "gh: Not Found (HTTP 404)" >&2
                      exit 1
                    fi
                    # `--slurp` returns an array of page responses, which is
                    # the shape the caller's query has to handle.
                    if [ "$slurp" = 1 ]; then
                      body="$(jq -c '[.]' < "$file")"
                    else
                      body="$(cat "$file")"
                    fi
                    if [ -n "$query" ]; then
                      jq -r "$query" <<< "$body"
                    else
                      printf '%s\n' "$body"
                    fi
                    ;;
                  issue)
                    shift
                    case "$1" in
                      list) exit 0 ;;
                      create)
                        shift
                        while [ $# -gt 0 ]; do
                          case "$1" in
                            --title) shift; printf '%s' "$1" > "$FIXTURE/issue-title" ;;
                            --body-file) shift; cp "$1" "$FIXTURE/issue-body" ;;
                          esac
                          shift
                        done
                        ;;
                    esac
                    ;;
                esac
                """
        ),
        encoding="utf-8",
    )
    (binaries / "gh").chmod(0o755)


def execute_recovery_escalation(
    release_recovery: str,
    attempt_signatures: list[object],
    *,
    release: dict[str, object] | None = None,
    release_error: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], str]:
    """Run the reconcile's classify and alert steps the way the job runs them.

    The alert no longer computes the signature itself; it reports what the
    classifier that spent or withheld the retry decided. Driving the two steps
    in order, through one runner temp directory and the classifier's real step
    outputs, is what keeps this a test of the controller rather than of a
    hand-copied duplicate of its logic.
    """

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        script = root / "escalate.sh"
        script.write_text(
            recovery_escalation_source(release_recovery), encoding="utf-8"
        )
        responses = root / "responses"
        responses.mkdir()
        write_attempt_job_fixtures(responses, attempt_signatures)
        binaries = root / "bin"
        binaries.mkdir()
        write_recovery_gh_stub(binaries)
        # The real classifier, run first and into this same runner temp, so the
        # alert reads the signature file and outputs the controller produced.
        classifier_outputs = run_recovery_classifier_in(
            root,
            recovery_step_script(release_recovery, RECOVERY_CLASSIFIER_ANCHOR),
            attempt_signatures,
        )
        release_response = responses / "repos_firelock-ai_kin_releases_tags_v9.9.9"
        if release is not None and release_error is not None:
            raise AssertionError("release fixture cannot be both readable and failed")
        if release is not None:
            release_response.write_text(
                json.dumps(release),
                encoding="utf-8",
            )
        if release_error is not None:
            Path(f"{release_response}.error").write_text(
                release_error,
                encoding="utf-8",
            )
        environment = dict(os.environ)
        environment["PATH"] = f"{binaries}{os.pathsep}{environment['PATH']}"
        environment.update(
            {
                "FIXTURE": str(root),
                "GH_TOKEN": "fixture",
                "REPO": "firelock-ai/kin",
                "TAG": "v9.9.9",
                "SHA": RELEASE_GATE_FIXTURE_SHA,
                "RUN_ID": RECOVERY_FIXTURE_RUN_ID,
                "RUN_URL": (
                    f"https://example.invalid/runs/{RECOVERY_FIXTURE_RUN_ID}"
                ),
                "ATTEMPTS": str(len(attempt_signatures)),
                "RUNNER_TEMP": str(root),
                # resolve declares exhaustion at the third attempt; the alert
                # distinguishes that from a repeat stop that left budget unspent.
                "EXHAUSTED": "true" if len(attempt_signatures) >= 3 else "false",
                "UNKNOWN": classifier_outputs.get("unknown", ""),
                "REPEATED": classifier_outputs.get("repeated", ""),
                "DISTINCT": classifier_outputs.get("distinct", ""),
            }
        )
        completed = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
            check=False,
        )
        body_path = root / "issue-body"
        body = body_path.read_text(encoding="utf-8") if body_path.exists() else ""
        return completed, body


def assert_recovery_escalation_classifies(release_recovery: str) -> None:
    """Recovery must classify before advising without inventing root-cause proof.

    A repeated job/step surface is useful evidence that another immediate rerun
    is unlikely to help, but it cannot distinguish a source-bound failure from
    an external outage that repeatedly reaches the same step. The issue must
    preserve that distinction before it tells an operator to burn a version.
    """

    compile_failure = ("build-artifacts (x86_64-unknown-linux-musl)", "Build release binaries")

    repeated, body = execute_recovery_escalation(
        release_recovery,
        [compile_failure, compile_failure, compile_failure],
    )
    if repeated.returncode == 0:
        raise AssertionError(
            "recovery escalation stopped failing the run: "
            f"{repeated.stdout}{repeated.stderr}"
        )
    for needle in (
        "Classification: **repeated failure signature**",
        # The strongest claim the alert can make, and it is only earned when
        # every attempt really did produce one signature. Pinning the sentence
        # itself is what keeps the all-attempts count from being deleted as
        # redundant to the last-two stop rule it does not duplicate.
        "Every observed attempt failed in the same job and step set",
        "another immediate rerun is unlikely to help",
        "recut only after confirming a source-bound defect",
        "preserve this tag for a same-release rerun if the cause is external",
        "- attempt 1: build-artifacts (x86_64-unknown-linux-musl) / Build release binaries",
        "after 3 attempt(s)",
        "No GitHub Release object exists for `v9.9.9`.",
    ):
        if needle not in body:
            raise AssertionError(
                f"identical repeated signatures were not reported: {needle!r}: {body}"
            )
    if "a rerun cannot reach a different outcome" in body:
        raise AssertionError(
            f"step identity was overstated as root-cause proof: {body}"
        )

    # The only shape that can reach the exhausted alert with a repeat verdict.
    # The controller stops at two identical attempts, so a run that spent all
    # three necessarily failed differently first, and the verdict text has to
    # describe the equality the classifier actually established rather than
    # claiming every attempt matched. Claiming it would contradict the
    # per-attempt list three lines below it and send an operator past attempt 1,
    # which is the evidence that the cause is not purely deterministic.
    _, tail_repeat_body = execute_recovery_escalation(
        release_recovery,
        [("publish", "Push image"), compile_failure, compile_failure],
    )
    for needle in (
        "Classification: **repeated failure signature**",
        "The two most recent attempts failed in the same job and step set",
        "Earlier attempts failed differently",
        "- attempt 1: publish / Push image",
        "- attempt 3: build-artifacts (x86_64-unknown-linux-musl) / Build release binaries",
    ):
        if needle not in tail_repeat_body:
            raise AssertionError(
                "a repeat established only across the last two attempts was not "
                f"reported as one: {needle!r}: {tail_repeat_body}"
            )
    if "Every observed attempt failed in the same job and step set" in tail_repeat_body:
        raise AssertionError(
            "the alert claimed every attempt failed identically while its own "
            f"per-attempt list shows attempt 1 differing: {tail_repeat_body}"
        )

    # The stop that spends one confirmation instead of the whole budget. The
    # alert still fires, and it must not describe unspent budget as exhausted:
    # the remedy for a repeat differs from the remedy for a run that tried
    # everything, and the tag is still eligible for a same-release rerun.
    stopped, stopped_body = execute_recovery_escalation(
        release_recovery,
        [compile_failure, compile_failure],
    )
    if stopped.returncode == 0:
        raise AssertionError(
            "a confirmed repeat did not raise the release alarm: "
            f"{stopped.stdout}{stopped.stderr}"
        )
    for needle in (
        "Classification: **repeated failure signature**",
        "stopped retrying",
        "after 2 attempt(s)",
    ):
        if needle not in stopped_body:
            raise AssertionError(
                f"a repeat stop was not reported as one: {needle!r}: {stopped_body}"
            )
    if "exhausted its retries" in stopped_body:
        raise AssertionError(
            "a repeat stop that left retry budget unspent was reported as "
            f"exhaustion: {stopped_body}"
        )

    _, transient_body = execute_recovery_escalation(
        release_recovery,
        [
            ("build-artifacts (x86_64-apple-darwin)", "Notarize"),
            ("publish", "Push image"),
            compile_failure,
        ],
    )
    for needle in (
        "Classification: **varying failure signatures**",
        "Diagnose and rerun the same release",
    ):
        if needle not in transient_body:
            raise AssertionError(
                f"differing failures lost the rerun advice: {needle!r}: "
                f"{transient_body}"
            )

    # An attempt whose jobs cannot be read is not evidence that the failure
    # repeated. Claiming deterministic from an unreadable attempt would retire
    # a recoverable release on a transient API error.
    _, unreadable_body = execute_recovery_escalation(
        release_recovery,
        [compile_failure, None, compile_failure],
    )
    for needle in (
        "Classification: **indeterminate**",
        "- attempt 2: unrecorded",
        "neither a deterministic nor a transient cause is established",
        "Inspect the unrecorded attempts",
    ):
        if needle not in unreadable_body:
            raise AssertionError(
                "an unreadable attempt was folded into a deterministic verdict: "
                f"{needle!r}: {unreadable_body}"
            )
    if "The attempts did not fail identically" in unreadable_body:
        raise AssertionError(
            "an unreadable attempt was reported as an observed difference: "
            f"{unreadable_body}"
        )

    # The shape production actually produces. Release builds are a matrix, so
    # more than one leg fails, and the jobs API orders by job id, which is
    # minted at queue time. Real attempts of run 30627672394 returned the two
    # failing legs in the order below: aarch64 first, then x86_64 first, then
    # aarch64 again. Reducing the failing set to its first element reads that
    # as two different failures and advises a rerun that cannot work, which
    # is verbatim the advice this suite exists to eliminate.
    aarch64 = (
        "Build (kin-linux-aarch64)",
        "Build kin-cli + kin-daemon (native)",
    )
    x86_64 = (
        "Build (kin-linux-x86_64)",
        "Build kin-cli + kin-daemon (native)",
    )
    _, matrix_body = execute_recovery_escalation(
        release_recovery,
        [[aarch64, x86_64], [x86_64, aarch64], [aarch64, x86_64]],
    )
    if "Classification: **repeated failure signature**" not in matrix_body:
        raise AssertionError(
            "a matrix failure that repeated identically was classified by the "
            f"order its legs happened to queue in: {matrix_body}"
        )

    # Every attempt unreadable is the case that isolates the unknown count.
    # The signatures all match each other, so nothing but that count stands
    # between a total read failure and a verdict of "deterministic, recut it".
    _, blind_body = execute_recovery_escalation(release_recovery, [None, None, None])
    if "Classification: **indeterminate**" not in blind_body:
        raise AssertionError(
            "a run whose attempts could not be read at all was classified "
            f"deterministic: {blind_body}"
        )

    # A mint that reported failure on a release it had already created would
    # otherwise send this controller to repair a healthy release.
    _, existing_release_body = execute_recovery_escalation(
        release_recovery,
        [compile_failure, compile_failure, compile_failure],
        release={
            "draft": False,
            "prerelease": True,
            "assets": [{"name": "kin-x86_64.tar.gz"}],
        },
    )
    if (
        "already exists with 1 asset(s)" not in existing_release_body
        or "prerelease=true" not in existing_release_body
        or "Confirm it is genuinely incomplete before repairing it."
        not in existing_release_body
    ):
        raise AssertionError(
            "recovery advised repair without saying the release already exists: "
            f"{existing_release_body}"
        )

    # Only a real 404 proves absence. A permissions, rate-limit, server, or
    # network failure is unknown state and must never be rewritten as "no
    # Release", which would send repair after an object that may exist.
    _, unreadable_release_body = execute_recovery_escalation(
        release_recovery,
        [compile_failure, compile_failure, compile_failure],
        release_error="gh: API rate limit exceeded (HTTP 403)\n",
    )
    for needle in (
        "GitHub Release state for `v9.9.9` could not be read",
        "Do not infer that the Release is absent",
    ):
        if needle not in unreadable_release_body:
            raise AssertionError(
                "recovery converted an unreadable Release API state into absence: "
                f"{needle!r}: {unreadable_release_body}"
            )
    if "No GitHub Release object exists" in unreadable_release_body:
        raise AssertionError(
            "recovery claimed Release absence after a non-404 API failure: "
            f"{unreadable_release_body}"
        )


def assert_ruleset_mirror_stays_a_superset(release_tag: str) -> None:
    """The reviewed mirror must never shrink below what the mint vetoes on.

    `missing_from_ruleset` runs unconditionally in the mint and refuses when the
    mint requires a context the reviewed mirror does not gate. `REQUIRED_CHECKS`
    is the veto set and `RULESET_REQUIRED_CHECKS` is the mirror of live ruleset
    19746451, so the mirror has to stay a superset of the veto set forever, and
    the day it stops being one EVERY release refuses.

    That is not a theoretical edit. FIR-2815 thins the live ruleset to a short
    admission list, which makes "sync the mirror to the ruleset" the obvious
    next tidy-up and makes it fatal. Nothing caught it before this: the mint's
    own refusal is driven here only against a synthetic environment, so the
    file's actual mirror content was unread, and a shrunken mirror landed green
    and failed at the next mint with no pull request to blame.

    The mirror may hold MORE than the veto set. That is its purpose: a context a
    ruleset gates and the mint does not veto on still has to be published by an
    admitted build, or the queue waits on a name nobody produces.
    """

    def block(key: str) -> tuple[str, ...]:
        found = re.search(
            rf"\n          {key}: \|\n((?:            \S.*\n)+)", release_tag
        )
        if found is None:
            raise AssertionError(
                f"release-tag.yml no longer declares {key} as a block scalar"
            )
        return tuple(
            line.strip() for line in found.group(1).splitlines() if line.strip()
        )

    veto = block("REQUIRED_CHECKS")
    mirror = block("RULESET_REQUIRED_CHECKS")
    dropped = sorted(set(veto) - set(mirror))
    if dropped:
        raise AssertionError(
            "the reviewed ruleset mirror must stay a superset of the checks the "
            f"mint vetoes on; it no longer gates {dropped}, which makes "
            "missing_from_ruleset non-empty and refuses EVERY release"
        )


def assert_required_check_set_is_single_sourced(release_tag: str) -> None:
    """The env list and the provenance table must name the same contexts.

    Dropping a context from the env alone leaves the table intact, so every
    literal needle still matches and the suite stays green while the mint has
    quietly stopped requiring a release-critical check. The workflow's own
    order check fails that closed at runtime, but only after the drift has
    landed and started burning mint attempts, which is a log to read rather
    than a red PR.
    """

    workflow = ".github/workflows/release-tag.yml"
    step = workflow_step_source(
        workflow,
        release_tag,
        "      - name: Verify required checks are green",
    )
    block = re.search(
        r"\n          REQUIRED_CHECKS: \|\n((?:            \S.*\n)+)",
        step,
    )
    if block is None:
        raise AssertionError(
            f"{workflow} no longer declares REQUIRED_CHECKS as a block scalar"
        )
    env_names = tuple(
        line.strip() for line in block.group(1).splitlines() if line.strip()
    )
    table = re.search(
        r"\nexpected_provenance = \{\n(.*?)\n\}\n",
        release_check_gate_source(release_tag),
        re.DOTALL,
    )
    if table is None:
        raise AssertionError(
            f"{workflow} no longer declares an expected_provenance table"
        )
    table_names = tuple(
        re.findall(r'^    "(.+?)": \(', table.group(1), re.MULTILINE)
    )
    if env_names != REQUIRED_RELEASE_CHECKS:
        raise AssertionError(
            "the release gate's REQUIRED_CHECKS env no longer matches the "
            f"reviewed required set: {env_names}"
        )
    if table_names != REQUIRED_RELEASE_CHECKS:
        raise AssertionError(
            "the release gate's expected_provenance table no longer matches "
            f"the reviewed required set: {table_names}"
        )


def decline_escalation_source(release_tag: str) -> str:
    """Extract the persistent-decline shell exactly as the mint runs it."""

    step = workflow_step_source(
        ".github/workflows/release-tag.yml",
        release_tag,
        "      - name: Escalate a persistent mint decline",
    )
    marker = "        run: |\n"
    if marker not in step:
        raise AssertionError("persistent-decline step no longer has a shell body")
    return textwrap.dedent(step[step.index(marker) + len(marker) :])


def execute_decline_escalation(
    source: str,
    prior_runs: list[tuple[int, str, str | None]],
) -> subprocess.CompletedProcess[str]:
    """Run the decline counter against production-shaped workflow/job payloads.

    Each tuple is `(run id, Mint release tag job conclusion, escalation-step
    conclusion)`. A `None` marker models a whole job skipped by the workflow's
    job-level `workflow_run` guard; that is the high-volume production shape
    that must be ignored rather than mistaken for a successful mint.
    """

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        script = root / "decline.sh"
        script.write_text(source, encoding="utf-8")
        responses = root / "responses"
        responses.mkdir()
        list_path = responses / (
            "repos_firelock-ai_kin_actions_workflows_release-tag.yml_runs"
        )
        list_path.write_text(
            json.dumps({"workflow_runs": [{"id": run_id} for run_id, _, _ in prior_runs]}),
            encoding="utf-8",
        )
        for run_id, job_conclusion, marker in prior_runs:
            steps = []
            if marker is not None:
                steps.append(
                    {
                        "name": "Escalate a persistent mint decline",
                        "conclusion": marker,
                    }
                )
            payload = {
                "jobs": [
                    {
                        "name": "Mint release tag",
                        "conclusion": job_conclusion,
                        "steps": steps,
                    }
                ]
            }
            (responses / f"repos_firelock-ai_kin_actions_runs_{run_id}_jobs").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )

        binaries = root / "bin"
        binaries.mkdir()
        (binaries / "gh").write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -uo pipefail
                [ "$1" = api ] || exit 2
                shift
                path=""; query=""
                while [ $# -gt 0 ]; do
                  case "$1" in
                    -q|--jq) shift; query="$1" ;;
                    -*) ;;
                    *) [ -n "$path" ] || path="$1" ;;
                  esac
                  shift
                done
                path="${path%%\\?*}"
                file="$FIXTURE/responses/$(printf '%s' "$path" | tr '/' '_')"
                if [ ! -f "$file" ]; then
                  echo "gh: Not Found (HTTP 404)" >&2
                  exit 1
                fi
                if [ -n "$query" ]; then
                  jq -r "$query" < "$file"
                else
                  cat "$file"
                fi
                """
            ),
            encoding="utf-8",
        )
        (binaries / "gh").chmod(0o755)
        environment = dict(os.environ)
        environment["PATH"] = f"{binaries}{os.pathsep}{environment['PATH']}"
        environment.update(
            {
                "FIXTURE": str(root),
                "GH_TOKEN": "fixture",
                "REPO": "firelock-ai/kin",
                "CURRENT_RUN_ID": "99999",
                "DECLINE_REASON": "unrecovered-latest",
                "DECLINE_LIMIT": "4",
                "DECLINE_SCAN_LIMIT": "100",
                "GITHUB_STEP_SUMMARY": str(root / "summary.md"),
            }
        )
        return subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=environment,
            timeout=30,
            check=False,
        )


def assert_soft_decline_is_legible(release_tag: str) -> None:
    """A decline exits the job green, so it has to be loud, named, and counted.

    The failure this pins is not a wrong answer but an invisible one: the mint
    declining to mint concluded success and read on the board exactly like a
    mint that happened, so a blocked release stayed hidden until somebody read
    the step conclusions by hand.
    """

    workflow = ".github/workflows/release-tag.yml"
    admission = workflow_step_source(
        workflow,
        release_tag,
        "      - name: Admit the serialized release lane",
    )
    for needle in (
        "decline() { # <reason> <sentence>",
        "printf '::warning::release mint declined (%s): %s\\n' \"$1\" \"$2\"",
        '} >> "$GITHUB_STEP_SUMMARY"',
        'echo "decline_reason=$1"',
    ):
        require(admission, needle, f"{workflow} soft-decline legibility")

    # Every automatic decline goes through the helper. A bare `ready=false`
    # beside a `::notice::` is the exact shape that made a blocked release
    # indistinguishable from a healthy one, so exactly one write may exist and
    # it is the helper's.
    ready_false_writes = admission.count('echo "ready=false"')
    if ready_false_writes != 1:
        raise AssertionError(
            f"{workflow} must write ready=false only through the decline helper, "
            f"so every decline is announced and named: found {ready_false_writes}"
        )
    declines = re.findall(r"^\s+decline [a-z][a-z-]* ", admission, re.MULTILINE)
    if len(declines) != 3:
        raise AssertionError(
            f"{workflow} has three automatic soft-decline branches, each of "
            f"which must announce itself: found {len(declines)}"
        )

    escalation_name = "Escalate a persistent mint decline"
    escalation = workflow_step_source(
        workflow,
        release_tag,
        f"      - name: {escalation_name}",
    )
    if "steps.prior.outputs.ready == 'false'" not in escalation:
        raise AssertionError(
            f"{workflow} must escalate only on the decline path, so an ordinary "
            "mint is never held against a decline budget"
        )
    # The counter's only decline marker is this step's own conclusion on prior
    # runs, so the name it selects on and the name it runs under have to be the
    # same string. Renaming the step without renaming the query would silently
    # reset the count to one on every run and never escalate again.
    if f'select(.name == "{escalation_name}")' not in escalation:
        raise AssertionError(
            f"{workflow} escalation must count prior runs by its own step name, "
            f"which is the only durable record of a decline: {escalation_name}"
        )
    limit = re.search(r'DECLINE_LIMIT: "(\d+)"', escalation)
    if limit is None or int(limit.group(1)) < 2:
        raise AssertionError(
            f"{workflow} needs a decline budget above one, because a single "
            "decline while a release is in flight is correct behaviour"
        )

    source = decline_escalation_source(release_tag)
    # `workflow_run` creates skipped controller jobs for unrelated CI
    # completions. They interleave with real scheduled declines in production
    # and must not reset the streak. The previous implementation stopped at the
    # first such run, so this fixture makes the fourth real decline fail only
    # when the skipped jobs are actively ignored.
    interleaved = execute_decline_escalation(
        source,
        [
            (910, "skipped", None),
            (909, "success", "success"),
            (908, "skipped", None),
            (907, "success", "success"),
            (906, "skipped", None),
            (905, "failure", "failure"),
        ],
    )
    if interleaved.returncode == 0 or "declined 4 times in a row" not in (
        interleaved.stdout + interleaved.stderr
    ):
        raise AssertionError(
            "whole-job workflow_run skips reset the persistent-decline counter: "
            f"{interleaved.stdout}{interleaved.stderr}"
        )

    # A mint job that really ran and skipped the escalation step is a genuine
    # non-decline (mint/no-op/refusal elsewhere), so it must reset the streak
    # even when older declines exist behind it.
    reset = execute_decline_escalation(
        source,
        [
            (920, "success", "skipped"),
            (919, "success", "success"),
            (918, "failure", "failure"),
            (917, "success", "success"),
        ],
    )
    if reset.returncode != 0 or "1 in a row" not in reset.stdout:
        raise AssertionError(
            "a completed non-decline mint no longer resets decline escalation: "
            f"{reset.stdout}{reset.stderr}"
        )


def assert_selector_arguments(
    release_tag: str,
    release_train: str,
    release_recovery: str,
) -> None:
    """Pin which tag each workflow declares it is about to mint."""

    actual = {
        "release-tag": selector_invocation("release-tag", release_tag),
        "release-train": selector_invocation("release-train", release_train),
        "release-recovery": selector_invocation(
            "release-recovery", release_recovery
        ),
    }
    if actual != EXPECTED_SELECTOR_INVOCATIONS:
        raise AssertionError(
            "each release workflow must hand the admission selector its own "
            "reviewed arguments. The mint-intent argument names the tag that "
            "workflow is about to create, and only the mint creates one. The "
            "train resolves drift from a base tag it never mints, and recovery "
            "reconciles a tag it never mints either, so naming that tag as "
            "mint intent refuses exactly when a record covers it, "
            f"which is every abandonment: expected={EXPECTED_SELECTOR_INVOCATIONS} "
            f"actual={actual}"
        )


RELEASE_PR_HEAD_REF = "automation/release-next"


def assert_release_pr_ci_scope_cannot_widen(ci: str) -> None:
    """A release-PR CI carve-out must be unable to reach the queue or main.

    The release pull request is the one whose whole content is the version
    bump, and the merge queue is what proves it. A carve-out scoped loosely
    enough to match `merge_group` would merge that pull request with no full
    pass anywhere. One that matched `push` would leave a skipped required
    context on the release sha, which the mint reads as not green and refuses
    permanently. Neither failure announces itself as a scoping mistake: the
    first is invisible until something ships broken, and the second looks like
    a broken mint rather than a broken condition.

    `github.head_ref` is what makes the scoping structural rather than
    conventional: it is set only on pull-request events and is empty under
    both `push` and `merge_group`, so a condition written against it cannot
    match either however the rest of the expression is edited. This assertion
    passes vacuously today, because ci.yml carries no such carve-out yet, and
    starts constraining the moment one lands.
    """

    for job, block in workflow_job_blocks(ci).items():
        active = "\n".join(active_lines(block))
        if RELEASE_PR_HEAD_REF not in active:
            continue
        if "github.head_ref" not in active:
            raise AssertionError(
                f"ci.yml job {job} scopes the release pull request by something "
                "other than github.head_ref, which is the only selector that is "
                "empty under push and merge_group"
            )
        if "github.event_name == 'pull_request'" not in active:
            raise AssertionError(
                f"ci.yml job {job} carves out the release pull request without "
                "pinning the pull_request event, so the carve-out's reach "
                "depends on expression evaluation rather than on the event"
            )
        for reaching in ("github.ref ", "github.ref=", "github.ref==", "github.base_ref"):
            if reaching in active:
                raise AssertionError(
                    f"ci.yml job {job} scopes the release pull request with a "
                    f"context that is populated off pull requests: {reaching.strip()}"
                )


def assert_mint_trigger_survives_advisory_flakes(release_tag: str) -> None:
    """The event-driven mint must evaluate on any completed main-push CI run.

    ci.yml carries jobs beyond the release-critical ones, so its aggregate
    conclusion goes red whenever a non-required advisory leg flakes, which is
    most main pushes. Gating the workflow_run trigger on that aggregate made
    the event path hostage to a flake and left the schedule as the only
    automatic mint, which GitHub then failed to deliver for roughly four hours.
    The mint's own "Verify required checks are green" step is the release
    authority: it binds each reviewed required context to its exact producing
    workflow and explicitly refuses to let that producer's aggregate conclusion
    veto through it. A trigger that re-imposes the aggregate contradicts the
    gate it precedes and can only ever subtract mint occasions.
    """

    block = workflow_job_blocks(release_tag).get("mint-release-tag")
    if block is None:
        raise AssertionError("release-tag no longer declares the mint job")
    guard: list[str] = []
    inside = False
    for line in block.splitlines():
        stripped = line.strip()
        if not inside:
            if stripped.startswith("if:"):
                inside = True
                guard.append(stripped)
            continue
        if stripped.startswith("runs-on:"):
            break
        if stripped.startswith("#"):
            continue
        guard.append(stripped)
    active = "\n".join(guard)
    if not inside:
        raise AssertionError("the release mint no longer guards its triggers")
    if "github.event.workflow_run.conclusion" in active:
        raise AssertionError(
            "the release mint's workflow_run trigger must not consult the CI "
            "run's aggregate conclusion: a single non-required advisory flake "
            "reds that aggregate and would silence the event-driven mint, "
            "leaving only the schedule GitHub is free not to deliver"
        )
    for clause in (
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'main'",
        # The queue's own CI run is the occasion that removes the wait: it
        # concludes when the landing does, roughly half an hour before the
        # landing push's run concludes, and the mint now keys off exactly the
        # sha that build proved. Losing this clause does not break a release,
        # which is what makes it worth pinning: it silently restores the
        # half-hour of pure waiting the rekey exists to delete.
        "github.event.workflow_run.event == 'merge_group'",
        "startsWith(github.event.workflow_run.head_branch, 'gh-readonly-queue/main/')",
    ):
        if clause not in active:
            raise AssertionError(
                "the release mint's workflow_run trigger must pin both reviewed "
                f"occasions it evaluates: {clause}"
            )
    if "gh-readonly-queue/'" in active or "'gh-readonly-queue/')" in active:
        raise AssertionError(
            "the release mint's queue trigger must pin the merge-queue ref for "
            "main, not any merge-queue ref in the repository"
        )

    # A widened trigger must not widen what the mint may release. The event's
    # own head sha is the only stale-capable input into the candidate: a rerun
    # of an older CI run carries the sha main held then, so resolving from it
    # selects the version of that moment rather than the version main carries
    # now, which is a class the scheduled arm structurally cannot reach. Both
    # automatic arms therefore read one freshly fetched protected main, and the
    # trigger stays a decision about when to look.
    resolve = workflow_step_source(
        "release-tag",
        release_tag,
        "      - name: Resolve exact coherent release commit\n",
    )
    if "workflow_run.head_sha" in resolve:
        raise AssertionError(
            "the release mint must not resolve its release candidate from the "
            "triggering CI run's head sha, because a rerun of an older run "
            "carries a stale one and the trigger decides only when to look"
        )
    if 'sha="$(git rev-parse refs/remotes/origin/main)"' not in resolve:
        raise AssertionError(
            "the release mint's automatic path must resolve its candidate from "
            "the freshly fetched protected main it just verified"
        )


def assert_recovery_stops_on_repeated_signature(release_recovery: str) -> None:
    """A deterministic failure must cost one confirmation, not the whole budget.

    The controller exists for transient failures. A failure that reproduces
    with an identical failing-step signature is not transient in any way a
    rerun can fix, and each blind retry costs a full Release run. The classifier
    therefore runs BEFORE the rerun is requested, and its verdict has to be
    driven by the real jobs API shapes rather than by a stub's canned answer.
    """

    classify_at = release_recovery.index(
        "      - name: Classify the failure signature across attempts\n"
    )
    rerun_at = release_recovery.index("      - name: Re-run failed jobs\n")
    if classify_at > rerun_at:
        raise AssertionError(
            "release recovery must classify the failure signature before it "
            "requests any rerun, because a rerun issued ahead of the verdict "
            "is exactly the blind retry this controller exists to prevent"
        )

    source = recovery_step_script(
        release_recovery,
        "      - name: Classify the failure signature across attempts\n",
    )
    compile_failure = ("build-artifacts (x86_64-unknown-linux-musl)", "Build release binaries")
    notarize = ("build-artifacts (aarch64-apple-darwin)", "Notarize")

    outputs = execute_recovery_classifier(source, [compile_failure, compile_failure])
    if outputs.get("repeated") != "true":
        raise AssertionError(
            "a second identical failing-step signature did not stop the retry "
            f"budget: {outputs}"
        )

    outputs = execute_recovery_classifier(source, [compile_failure, notarize])
    if outputs.get("repeated") != "false":
        raise AssertionError(
            f"a differing second failure was reported as deterministic: {outputs}"
        )

    # The stop rule is last-two equality, not all-attempts equality, and the two
    # are only distinguishable on this shape. A failure that reproduces after a
    # differing first attempt still has to stop, because the budget it would
    # spend buys another identical failure. The all-attempts count is reported
    # beside it rather than deciding it, so the alert can say which of the two
    # it observed instead of asserting the stronger one either way.
    outputs = execute_recovery_classifier(
        source, [notarize, compile_failure, compile_failure]
    )
    if outputs.get("repeated") != "true":
        raise AssertionError(
            "a failure that reproduced after a differing first attempt was not "
            f"read as a repeat: {outputs}"
        )
    if outputs.get("distinct") != "2":
        raise AssertionError(
            "the all-attempts signature count did not observe the differing "
            f"first attempt: {outputs}"
        )

    # One attempt cannot repeat anything. Stopping here would retire a release
    # on its first failure and defeat the controller's entire purpose.
    outputs = execute_recovery_classifier(source, [compile_failure])
    if outputs.get("repeated") != "false":
        raise AssertionError(
            f"a single first failure was treated as a repeat: {outputs}"
        )

    # A transient API error is not evidence that the release failure repeats.
    outputs = execute_recovery_classifier(source, [compile_failure, None])
    if outputs.get("repeated") != "false" or outputs.get("unknown") == "0":
        raise AssertionError(
            f"an unreadable attempt was folded into a repeat verdict: {outputs}"
        )
    outputs = execute_recovery_classifier(source, [None, None])
    if outputs.get("repeated") != "false":
        raise AssertionError(
            "two unreadable attempts compared equal to each other and stopped "
            f"the retries: {outputs}"
        )

    # A shape GitHub can produce, hardened against rather than observed here:
    # when one matrix leg fails its siblings can be cancelled, and a cancelled
    # job still carries the step that actually failed. Filtering on the job's
    # own conclusion first drops exactly that evidence and reads a repeat as two
    # unreadable attempts, which retries a deterministic failure to the end of
    # the budget. The runs this classifier was built from carried no cancelled
    # job at all, so a step-primary read is defence and not the repair: what
    # cost three attempts there was classifying only once the budget was gone.
    cancelled = ("build-artifacts (aarch64-unknown-linux-musl)", "Build release binaries", "cancelled")
    outputs = execute_recovery_classifier(source, [cancelled, cancelled])
    if outputs.get("repeated") != "true":
        raise AssertionError(
            "a failing step inside a cancelled matrix leg was not read as "
            f"failure evidence: {outputs}"
        )

    # A job that failed while recording no failing step at all — a runner
    # startup failure — is still a signature, not an unreadable attempt.
    startup = ("publish", None, "failure")
    outputs = execute_recovery_classifier(source, [startup, startup])
    if outputs.get("repeated") != "true" or outputs.get("unknown") != "0":
        raise AssertionError(
            f"a job-level failure with no failing step was unreadable: {outputs}"
        )

    # The order matrix legs queue in must not decide the verdict.
    aarch64 = ("Build (kin-linux-aarch64)", "Build kin-cli + kin-daemon (native)")
    x86_64 = ("Build (kin-linux-x86_64)", "Build kin-cli + kin-daemon (native)")
    outputs = execute_recovery_classifier(
        source, [[aarch64, x86_64], [x86_64, aarch64]]
    )
    if outputs.get("repeated") != "true":
        raise AssertionError(
            "a matrix failure that repeated identically was classified by the "
            f"order its legs happened to queue in: {outputs}"
        )


def assert_recovery_record_authority(release_recovery: str) -> None:
    """Recovery must decide abandonment through the rail's own selector.

    Two readers of one record is how an alarm gets disarmed in the state that
    needs it most. A reader of its own accepts entries the selector refuses, so
    recovery would stand down for a record too malformed to waive the mint: the
    rail hard stuck, and the check-run that would say so green. Recovery
    therefore asks the selector the same question the mint asks, and this pins
    that it keeps asking rather than reading the record itself.

    Recovery is deliberately absent from the protected-main read above. The mint
    and the train run on a release commit that predates the abandonment it has
    to honour, so they must reach past their checkout; recovery checks out
    GITHUB_SHA, which is the default-branch commit itself, and honours no
    abandonment from a tree whose HEAD is not that commit.
    """

    step = workflow_step_source(
        "release-recovery",
        release_recovery,
        "      - name: Reconcile against the tracked abandonment record\n",
    )
    for policy in (TAG_SELECTOR_POLICY, 'python3 "$selector"'):
        require(step, policy, "record-aware release recovery")
    for reader in ("jq ", "python3 -c"):
        if reader in step:
            raise AssertionError(
                "release recovery must decide abandonment through "
                f"{TAG_SELECTOR_POLICY} and not read the record a second way, "
                "because a second reader accepts what the rail refuses and "
                f"quiets the alarm the refusal exists to raise: {reader.strip()}"
            )
    # The selector answers by ranking, and it drops a candidate that is not a
    # vX.Y.Z release tag for the same reason it drops an abandoned one. An empty
    # ranking therefore means "waived" only while the tag handed to it is known
    # to be a release tag, which resolve establishes before it declares the
    # reconcile needed. The order is what makes it true at the ranking.
    resolve = workflow_step_source(
        "release-recovery",
        release_recovery,
        "      - name: Resolve exact retry candidate\n",
    )
    shape = resolve.index(r'[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]')
    declared = resolve.index('echo "needed=true"')
    if shape > declared:
        raise AssertionError(
            "release recovery must prove its retry candidate is a vX.Y.Z "
            "release tag before it declares a reconcile needed, because the "
            "admission selector drops anything else from its ranking and "
            "recovery reads an empty ranking as a reviewed waiver"
        )


def assert_recovery_abandonment_stand_down(release_recovery: str) -> None:
    """Pin both retry and alert to the active reviewed-abandonment condition."""

    condition = "steps.record.outputs.abandoned != 'true'"
    for marker, duty in (
        ("name: Re-run failed jobs", "bounded retry"),
        (
            "name: Classify the failure signature across attempts",
            "failure-signature classification",
        ),
        (
            "name: Alert after automatic retries are exhausted",
            "exhausted-retry alert",
        ),
    ):
        active = "\n".join(job_step_active_lines(release_recovery, "reconcile", marker))
        if condition not in active:
            raise AssertionError(
                f"release recovery's {duty} must actively stand down for a tag "
                "the tracked abandonment record already retired"
            )


def assert_release_proof_key_authority(
    release_train: str,
    release_tag: str,
    release: str,
    proof_gate: str,
) -> None:
    """Pin the release evidence to a commit nothing rewrites, and to the tag.

    This guard did not exist while the thing it guards was load-bearing. The
    FIR-2525 proof gate lived in release-train.yml keyed on the head of
    automation/release-next, the train mints a new head on every cycle that
    finds drift, and nothing in this file noticed either fact. Removing that
    step outright left the whole suite green, which is how a release chain
    acquires a rule that only a runbook sentence enforces.

    What is pinned now is the arrangement that replaced it. The candidate is a
    main commit, so nothing can rewrite it out from under its records; the mint
    refuses to write the tag ref without them; the tag names the exact sha the
    gate verified; and the train keys nothing on a branch head any more, which
    is the property that lets main keep moving through a proof window.
    """

    mint = workflow_job_blocks(release_tag).get("mint-release-tag")
    if mint is None:
        raise AssertionError("release-tag.yml no longer declares the mint job")

    gate_anchor = "- name: Require proof-loop artifacts for the release candidate"
    tag_write_anchor = "- name: Create release tag ref"
    for anchor in (gate_anchor, tag_write_anchor):
        if mint.count(anchor) != 1:
            raise AssertionError(
                f"the mint must declare exactly one {anchor!r} step, so the "
                "release proof gate has one reviewed place to live"
            )
    if mint.index(gate_anchor) > mint.index(tag_write_anchor):
        raise AssertionError(
            "the release proof gate must run before the tag ref is written; a "
            "tag run resolves its workflows from the tag and can never be "
            "repaired, so a gate after the write refuses nothing"
        )

    gate_step = "\n".join(
        job_step_active_lines(release_tag, "mint-release-tag", gate_anchor)
    )
    for needle, duty in (
        (
            f'"refs/remotes/origin/main:{PROOF_GATE_POLICY}"',
            "read the gate from protected main rather than from the commit "
            "under judgement",
        ),
        (
            'CANDIDATE_SHA="$SHA"',
            "ask about the exact sha it is going to tag",
        ),
        (
            'if [ "$proven" != "$SHA" ]',
            "refuse when the sha the gate verified is not the sha it would tag",
        ),
        (
            'git diff --name-only "$proven" "$SHA"',
            "state that the tree it tags is the tree that was proven",
        ),
    ):
        if needle not in gate_step:
            raise AssertionError(
                f"the release proof gate must {duty}: {needle}"
            )

    resolve = "\n".join(
        job_step_active_lines(
            release_tag, "mint-release-tag", "name: Resolve exact coherent release"
        )
    )
    for needle, duty in (
        (
            "git/trees/release-evidence?recursive=1",
            "select the candidate from the records the proof loop published",
        ),
        (
            '.truncated // false',
            "refuse a truncated listing rather than shipping the older "
            "candidate it can still see",
        ),
        (
            'if ! listing="$(gh api',
            "test the status of the listing read, because a transport "
            "failure, a GitHub error object and an empty evidence branch "
            "otherwise print the same green no-op and only one of them means "
            "there is nothing to release",
        ),
        (
            '2>"$read_error"',
            "keep the error text from the listing read, because a refusal "
            "that cannot say what went wrong is one an operator has to "
            "reproduce before they can act on it",
        ),
        (
            'echo "needed=false"',
            "stand down as a no-op when no candidate is proven, rather than "
            "declining or tagging one that is not",
        ),
    ):
        if needle not in resolve:
            raise AssertionError(
                f"the mint's candidate selection must {duty}: {needle}"
            )

    reconcile = workflow_job_blocks(release_train).get("reconcile")
    if reconcile is None:
        raise AssertionError("release-train.yml no longer declares the reconcile job")

    if PROOF_GATE_POLICY in workflow_active_text(reconcile):
        raise AssertionError(
            "the release train must key nothing on the version bump branch's "
            "head; that key is what forced the fleet to freeze main for the "
            "length of every proof window, and the refusal now lives on the "
            "tag the mint writes"
        )

    # The removed proof step was the only code that ever drafted or un-drafted
    # the bump pull request, and it drafted it while it held. The arm step now
    # runs on drift alone, so without this a draft left behind by that step
    # arms auto-merge on a pull request the merge queue never takes: the bump
    # never lands, no candidate is ever provable, and the plan step's all-clear
    # marker reports a healthy rail every fifteen minutes while nothing moves.
    arm = "\n".join(
        job_step_active_lines(
            release_train, "reconcile", "name: Arm protected auto-merge"
        )
    )
    for needle, duty in (
        (
            'gh pr ready "$PR"',
            "un-draft the bump pull request before it arms auto-merge, "
            "because the merge queue never takes a draft and nothing else "
            "here un-drafts one any more",
        ),
        (
            "--json headRefOid,isDraft",
            "read the draft state in the same call that reads the head, so "
            "the check costs no extra round trip and cannot go stale between "
            "two of them",
        ),
    ):
        if needle not in arm:
            raise AssertionError(
                f"the release train's arm step must {duty}: {needle}"
            )
    if arm.index('gh pr ready "$PR"') > arm.index('gh pr merge "$PR"'):
        raise AssertionError(
            "the release train must un-draft the bump pull request BEFORE it "
            "arms auto-merge; arming first is what leaves a draft armed and "
            "unmergeable while the rail reports itself clear"
        )

    promote = "\n".join(
        job_step_active_lines(
            release, "finalize_release", "name: Require proof-loop artifacts"
        )
    )
    for needle, duty in (
        (
            "CANDIDATE_SHA: ${{ github.sha }}",
            "ask about the tagged commit directly, because the mint now tags "
            "the candidate itself",
        ),
        (
            "RESOLVE_FROM_COMMIT: ${{ github.sha }}",
            "keep the bridge, which is what makes a tag with no direct record "
            "refuse by naming where it came from rather than only naming the "
            "file that was missing",
        ),
        (
            "process.stdout.write(result.sha)",
            "read back the sha the gate verified rather than only its exit "
            "status, because the exit status alone cannot say which commit "
            "the evidence was about",
        ),
        (
            'if [ "$proven" != "$CANDIDATE_SHA" ]',
            "refuse when the sha the gate verified is not the sha it "
            "promotes; the mint makes that comparison before it writes the "
            "ref, and without it here a bridged answer flips a tag to Latest "
            "on evidence about a different commit and a different tree",
        ),
    ):
        if needle not in promote:
            raise AssertionError(
                f"the promote gate must {duty}: {needle}"
            )

    gate_source = "\n".join(active_lines(proof_gate))

    # The bridge is the one path in the gate that can answer about a sha nobody
    # named, so it is bounded to the branch that is the only place a record was
    # ever published. The bound is read out of the release train rather than
    # written down twice: renaming the bump branch there must fail here until
    # the gate follows, because a bridge pointed at a branch that no longer
    # exists resolves the head of whatever feature pull request produced the
    # tagged commit, and that head never carried a record.
    bump_branch = re.search(
        r"^BRANCH: (\S+)$", workflow_active_text(reconcile), re.MULTILINE
    )
    if bump_branch is None:
        raise AssertionError(
            "release-train.yml no longer names the bump branch it writes, so "
            "the proof gate's bridge cannot be bounded to it"
        )
    if f"export const BUMP_BRANCH = '{bump_branch.group(1)}';" not in gate_source:
        raise AssertionError(
            "the proof gate's bridge must be bounded to the same bump branch "
            f"the release train writes ({bump_branch.group(1)})"
        )
    if (
        "produced.filter((pull) => pull?.head?.ref === BUMP_BRANCH)"
        not in gate_source
    ):
        raise AssertionError(
            "the proof gate must apply the bump-branch bound when it bridges, "
            "or a tag whose records were removed resolves the head of the "
            "feature pull request that produced it and asks about a build "
            "nobody proved"
        )

    if "absent.evidenceAbsent = true" not in gate_source:
        raise AssertionError(
            "the proof gate must mark an absent record as absent, so a caller "
            "deciding to bridge is not matching on an error message"
        )
    if "if (!error.evidenceAbsent || !resolveFromCommit)" not in gate_source:
        raise AssertionError(
            "the proof gate must bridge only when the direct record is ABSENT; "
            "widening the search on an unreadable record is a check reporting "
            "success for the wrong reason"
        )


def assert_release_hold_marker_contract(
    release_train: str,
    release_sentinel: str,
    hold_alarm: str,
) -> None:
    """Pin the hold marker to a producer, a consumer, and one alarm title.

    A marker nobody reads and an alarm keyed to a title that moves are the two
    ways this reporting path fails back into silence, and both of them look
    exactly like a working rail from the run history. The producer, the
    deterministic consumer, and the sentinel prompt each spell the same title
    and the same schema, so this is what stops the three drifting apart.
    """

    plan = "\n".join(
        job_step_active_lines(
            release_train, "reconcile", "name: Resolve releasable drift"
        )
    )
    stand_downs = plan.count('echo "needed=false"')
    holds = plan.count("write_marker held ")
    if stand_downs == 0:
        raise AssertionError(
            "the release train must still have a stand-down path to report"
        )
    if holds != stand_downs:
        raise AssertionError(
            "every release-train stand-down must publish a hold marker; "
            f"{stand_downs} stand-down(s) publish {holds} marker(s)"
        )
    if "write_marker clear " not in plan:
        raise AssertionError(
            "the release train must publish an all-clear marker when it "
            "proceeds, because only an all-clear can close the alarm"
        )

    schema = '"kin.release-hold.v1"'
    if schema not in plan:
        raise AssertionError(
            "the release train must stamp the reviewed hold-marker schema"
        )
    if f"MARKER_SCHEMA = {schema}" not in hold_alarm:
        raise AssertionError(
            "the hold-alarm reader must accept exactly the schema the release "
            "train stamps, or every marker reads as unreadable"
        )

    artifact = "name: release-hold-marker"
    upload = "\n".join(
        job_step_active_lines(
            release_train, "reconcile", "name: Publish this cycle's hold marker"
        )
    )
    if artifact not in upload:
        raise AssertionError(
            "the release train must upload the hold marker under the reviewed "
            "artifact name"
        )
    if "if: always()" not in upload:
        raise AssertionError(
            "the hold marker must be uploaded on every path, including the "
            "stand-downs that are the whole reason it exists"
        )
    gather = "\n".join(
        job_step_active_lines(
            release_train, "hold-alarm", "name: Gather this cycle"
        )
    )
    # Compared as a whole token, not as a substring. `release-hold-marker-v2`
    # contains `release-hold-marker`, so a prefix test would pass a rename that
    # points the reader at an artifact the train never uploads, and the alarm
    # would go quiet exactly the way it did before any of this existed.
    downloaded = re.findall(r"--name (\S+)", gather)
    if downloaded != ["release-hold-marker"]:
        raise AssertionError(
            "the alarm must download exactly the artifact the train uploads, "
            f"not {downloaded}"
        )

    title = "Release rail is held with releasable drift"
    for source, surface in (
        (hold_alarm, "the hold-alarm reader"),
        (release_train, "the release train's alarm job"),
        (release_sentinel, "the release sentinel prompt"),
    ):
        if source.count(title) < 1:
            raise AssertionError(
                f"{surface} must spell the one reviewed alarm title exactly, "
                "or a second issue is opened every time the wording drifts"
            )
    if re.search(r"v\d+\.\d+\.\d+", title) or any(char.isdigit() for char in title):
        raise AssertionError(
            "the alarm title must carry no tag and no count, because a title "
            "that moves with the rail opens a new issue on every move"
        )

    decide = "\n".join(
        job_step_active_lines(
            release_train, "hold-alarm", "name: Decide whether the rail"
        )
    )
    # An issue on its own leaves the run history reading all-green, and the
    # all-green run history is the surface that lied. Both loud verdicts have to
    # end the job nonzero, and neither quiet verdict may.
    for verdict in ("open)", "update)"):
        segment = decide.split(verdict, 1)
        if len(segment) != 2:
            raise AssertionError(
                f"the alarm must still handle the {verdict[:-1]} verdict"
            )
        tail = segment[1].split(";;", 1)[0]
        if "exit 1" not in tail:
            raise AssertionError(
                f"an alarm that {verdict[:-1]}s an issue must also fail its run; "
                "a green run beside an open alarm is the silence this replaces"
            )
    for verdict in ("quiet)", "close)"):
        segment = decide.split(verdict, 1)
        if len(segment) != 2:
            raise AssertionError(
                f"the alarm must still handle the {verdict[:-1]} verdict"
            )
        tail = segment[1].split(";;", 1)[0]
        if "exit 1" in tail:
            raise AssertionError(
                f"a {verdict[:-1]} verdict must not fail the run; a rail that "
                "is merely idle would then cry wolf every cycle"
            )

    # The alarm must stand down when the reconcile job was skipped, and this is
    # load-bearing rather than tidiness. Almost every train run is a skipped
    # workflow_run tick. A job that ran on those would contribute a cycle with no
    # marker, and an unreadable cycle breaks the streak, so the count could never
    # reach the threshold. It would also conclude those runs success rather than
    # skipped, which is exactly how the gather step tells a non-cycle from a
    # cycle. The alarm would read as working and be unable to fire.
    alarm_job = workflow_job_blocks(release_train).get("hold-alarm")
    if alarm_job is None:
        raise AssertionError("the release train must declare its hold-alarm job")
    alarm_condition = "\n".join(
        line for line in alarm_job.splitlines() if not line.lstrip().startswith("#")
    )
    if "needs.reconcile.result != 'skipped'" not in alarm_condition:
        raise AssertionError(
            "the hold alarm must stand down on a skipped reconcile; counting "
            "skipped ticks as cycles breaks the streak it needs to reach and "
            "erases the skipped conclusion the gather step reads"
        )

    threshold = re.search(r"DEFAULT_THRESHOLD = (\d+)", hold_alarm)
    if threshold is None:
        raise AssertionError("the hold-alarm reader must declare its threshold")
    if f'THRESHOLD: "{threshold.group(1)}"' not in release_train:
        raise AssertionError(
            "the release train must pass the same consecutive-cycle threshold "
            "the reader defaults to, so one number describes the alarm"
        )



def health_join_copies() -> list[tuple[str, str]]:
    """Every pasted copy of the health join, as (home, dedented text).

    Extracted from the start of the BEGIN line so the first line carries the
    same indentation as the rest, which is what makes `textwrap.dedent` able to
    remove it. Slicing from the marker itself leaves line one at column zero,
    dedent finds a common prefix of "" and every copy compares unequal for a
    reason that has nothing to do with the rule.
    """

    found: list[tuple[str, str]] = []
    for home in HEALTH_JOIN_HOMES:
        text = (ROOT / home).read_text(encoding="utf-8")
        cursor = 0
        while True:
            begin = text.find(HEALTH_JOIN_BEGIN, cursor)
            if begin < 0:
                break
            line_start = text.rfind("\n", 0, begin) + 1
            end = text.index(HEALTH_JOIN_END, begin)
            end = text.index("\n", end) + 1
            found.append((home, textwrap.dedent(text[line_start:end])))
            cursor = end
    return found


def assert_health_join_copies_agree() -> None:
    """One roll-up rule, however many files have to carry the letters.

    FIR-2919. install-proof.yml and rc-build.yml run with no checkout by design,
    so they cannot import `scripts/verify-capability-proof.mjs` and each pastes
    the rule instead. Four copies of a rule drift, and this set drifts in the
    worst direction: every copy kept agreeing with every other while all four
    disagreed with the product, so a fresh Windows install emitted
    `"healthy": true` over a pending and a degraded row and the release's own
    proof threw at tag time, where no fix on main can reach the tag.
    """

    copies = health_join_copies()
    expected = 4
    if len(copies) != expected:
        raise AssertionError(
            f"the health join must appear exactly {expected} times across "
            f"{', '.join(HEALTH_JOIN_HOMES)}; found {len(copies)}: "
            f"{[home for home, _ in copies]}"
        )
    # The module's copy is the reference. It is the one with a test suite.
    reference_home, reference = copies[0]
    if reference_home != HEALTH_JOIN_HOMES[0]:
        raise AssertionError(
            f"the first copy must come from {HEALTH_JOIN_HOMES[0]}, which is the "
            f"one with unit tests; found {reference_home}"
        )
    for home, block in copies[1:]:
        if block != reference:
            diff = "\n".join(
                difflib.unified_diff(
                    reference.splitlines(),
                    block.splitlines(),
                    fromfile=reference_home,
                    tofile=home,
                    lineterm="",
                )
            )
            raise AssertionError(
                f"{home} carries a health join that differs from "
                f"{reference_home}; one rule, one text:\n{diff}"
            )
    # The extractor itself must be able to come up empty, or "every copy agrees"
    # is a sentence about a list nothing ever put anything into.
    if HEALTH_JOIN_BEGIN.replace("HEALTH JOIN", "HEALTH JOIN THAT IS NOT THERE") in reference:
        raise AssertionError("the control marker must not appear in the real block")
    for home in HEALTH_JOIN_HOMES:
        text = (ROOT / home).read_text(encoding="utf-8")
        if "// --- BEGIN HEALTH JOIN THAT IS NOT THERE ---" in text:
            raise AssertionError(
                f"{home} carries the fabricated control marker, so the extractor "
                "cannot be trusted to have found the real ones"
            )
    # Every copy must carry both halves of the rule. A block that lost
    # `healthNeedsAttention` would still be identical in four places.
    for clause in (
        'check.status !== "healthy" && check.status !== "unsupported"',
        'check.status === "missing"',
        'check.id === "semantic_query_readiness" && check.status === "stale"',
        'return checks.some(healthNeedsAttention) ? "needs_attention" : "ready";',
    ):
        if clause not in reference:
            raise AssertionError(
                f"the health join must carry the clause {clause!r}; four identical "
                "copies of the wrong rule is the failure this pin exists to catch"
            )


def assert_capability_canary_contract(
    install_proof: str,
    canary: str,
    capability_script: str,
) -> None:
    """Bind the branch canary to the same capability contract the proof enforces.

    The install proof cannot read a tracked script. It runs anonymously with no
    checkout, which is what makes it worth trusting and also why the contract
    cannot simply be shared by import. Two copies of a contract drift, and this
    pair drifts in the worst direction: the canary keeps passing while the proof
    it was built to predict starts failing at tag time, where no fix on main can
    reach the tag. So the copies are compared here instead.
    """

    blocks = re.findall(
        r"const required = new Map\(\[\n(.*?)\n\s*\]\);", install_proof, re.S
    )
    if len(blocks) != 2:
        raise AssertionError(
            "the install proof is expected to carry exactly two required-check "
            f"tables, the Windows repo-free one and the capability one; found {len(blocks)}"
        )
    # The second table is the capability validator's, which is the one the canary
    # mirrors. The first belongs to the Windows repository-free proof, which
    # asserts a different surface on a leg the canary does not run.
    proof_ids = set(re.findall(r'\["([a-z_0-9]+)",', blocks[1]))
    # The proof asserts readiness in its own arm rather than in the table, so it
    # is required by the proof without appearing in it.
    proof_ids.add("semantic_query_readiness")

    listed = re.search(
        r"export const REQUIRED_CHECK_IDS = \[(.*?)\];", capability_script, re.S
    )
    if listed is None:
        raise AssertionError(
            "the capability contract must export the check ids it requires"
        )
    canary_ids = set(re.findall(r'"([a-z_0-9]+)"', listed.group(1)))

    if canary_ids != proof_ids:
        missing = sorted(proof_ids - canary_ids)
        extra = sorted(canary_ids - proof_ids)
        raise AssertionError(
            "the canary's capability contract must require exactly the health "
            "checks the install proof requires; "
            f"absent from the canary: {missing or 'none'}; "
            f"required by the canary but not the proof: {extra or 'none'}"
        )

    # The rule the proof applies to every health report it reads lives in one
    # delimited block, pasted into the workflows that cannot import it, and
    # `assert_health_join_copies_agree` requires every copy identical. A text
    # probe for one clause was what stood here, and a clause probe cannot see the
    # half of the rule that was wrong: the copies all agreed on `stale` while
    # none of them counted `pending` or `degraded`, which is what fenced v0.6.1.
    assert_health_join_copies_agree()

    # Everything below is judged on active lines only, in both directions.
    #
    # A comment must not be able to satisfy a requirement, which is the trap this
    # suite already guards elsewhere: this file explains its own rules at length,
    # so a whole-file scan would find `--require-observed` in the paragraph
    # explaining it and pass a canary that no longer passes the flag. A comment
    # must not be able to trip a prohibition either, for the same reason in
    # reverse: the header explains why the proof installs from the public
    # endpoint and why the canary must not, and a naive scan refuses the very
    # sentence documenting the rule.
    active_canary = "\n".join(
        line for line in canary.splitlines() if not line.lstrip().startswith("#")
    )

    # The two triggers the ticket asked for, and the reason for each. A canary
    # with only a path filter misses a break arriving through a path nobody
    # anticipated; one with only a schedule finds it a night late.
    if "schedule:" not in active_canary:
        raise AssertionError("the canary must run nightly against main")
    if "pull_request:" not in active_canary or "paths:" not in active_canary:
        raise AssertionError(
            "the canary must run path-filtered on the proof's known inputs"
        )
    for required_path in (
        '".github/workflows/install-proof.yml"',
        '"crates/kin-cli/src/commands/health.rs"',
    ):
        if required_path not in active_canary:
            raise AssertionError(
                "the canary's path filter must cover the proof itself and the "
                f"readiness classifier that fenced v0.5.18; absent: {required_path}"
            )

    if "scripts/verify-capability-proof.mjs" not in active_canary:
        raise AssertionError(
            "the canary must actually run the shared capability contract"
        )
    if "--require-observed" not in active_canary:
        raise AssertionError(
            "the canary must assert against an observed coverage at least once; "
            "a run that only ever saw unobservable coverage judged nothing, and a "
            "check that cannot fail is not evidence"
        )

    # A canary publishes nothing and promotes nothing. The release path stays the
    # release path, and a branch binary never touches it.
    for forbidden in (
        "contents: write",
        "id-token: write",
        "packages: write",
        "gh release",
        "npm publish",
        "get.kinlab.dev",
        "curl -fsSL https://get",
    ):
        if forbidden in active_canary:
            raise AssertionError(
                f"the canary must neither publish nor promote anything: {forbidden}"
            )


def assert_abandoned_tag_admission(
    release_tag: str,
    release_train: str,
    release_recovery: str,
) -> None:
    """Only a reviewed record may waive release-lane serialization."""

    assert_selector_arguments(release_tag, release_train, release_recovery)
    assert_recovery_record_authority(release_recovery)

    for workflow, content, step_anchor, comparison in (
        (
            "release-tag",
            release_tag,
            "      - name: Admit the serialized release lane\n",
            '[ "$highest_tag" != "$latest_tag" ]',
        ),
        (
            "release-train",
            release_train,
            "      - name: Resolve releasable drift and SemVer intent\n",
            '[ "$highest_tag" != "$latest_tag" ]',
        ),
    ):
        assert_trusted_abandonment_reads(workflow, content)
        assert_admission_step_order(workflow, content, step_anchor, comparison)

    unbuildable = "1" * 40
    superseding = "2" * 40
    stable = "3" * 40
    older = "4" * 40
    unversioned = "5" * 40
    # A non-release tag ahead of every version tag, because the version filter
    # has to survive whatever else the repository has tagged.
    candidates = (
        f"nightly {unversioned}\n"
        f"v0.4.3 {unbuildable}\n"
        f"v0.3.6 {stable}\n"
        f"v0.3.5 {older}\n"
    )
    record = {
        "tag": "v0.4.3",
        "sha": unbuildable,
        "reason": "the tagged lockfile pins a dependency that cannot build",
        "superseded_by": "v0.4.4",
        "failed_release_run_id": "30627672394",
    }

    # The invariant this whole gate exists for: a tag that is only failing so
    # far is not skippable, so it still holds its successor. Nothing but a
    # reviewed record changes that, and a record that does not describe the tag
    # in the repository is not one.
    assert_admissible_tag(
        "an unlisted tag whose release keeps failing",
        abandonment_manifest(),
        candidates,
        "v0.4.3",
    )
    assert_admissible_tag(
        "an abandonment naming a different tag",
        abandonment_manifest({**record, "tag": "v0.3.5", "sha": older}),
        candidates,
        "v0.4.3",
    )
    assert_admissible_tag(
        "an abandonment of a tag that no longer exists",
        abandonment_manifest({**record, "tag": "v0.9.9"}),
        candidates,
        "v0.4.3",
    )
    assert_tag_selection_refused(
        "an abandonment whose tag has since moved",
        abandonment_manifest({**record, "sha": superseding}),
        candidates,
        f"abandonment of v0.4.3 waives {superseding} but the tag now names",
    )

    # With the record present the unbuildable tag stops holding the lane, and
    # ranking otherwise stays exactly what git already decided.
    assert_admissible_tag(
        "a reviewed abandonment",
        abandonment_manifest(record),
        candidates,
        "v0.3.6",
    )
    assert_admissible_tag(
        "consecutive reviewed abandonments",
        abandonment_manifest(
            record,
            {**record, "tag": "v0.3.6", "sha": stable, "superseded_by": "v0.4.4"},
        ),
        candidates,
        "v0.3.5",
    )
    assert_admissible_tag(
        "an abandonment of every version tag",
        abandonment_manifest(
            record,
            {**record, "tag": "v0.3.6", "sha": stable, "superseded_by": "v0.4.4"},
            {**record, "tag": "v0.3.5", "sha": older, "superseded_by": "v0.4.4"},
        ),
        candidates,
        "",
    )
    # The mint-intent contract, in the state that actually occurs. A record is
    # written the moment a release is stuck, and main's version still equals the
    # stuck tag then, because the mint only ever creates `v$(workspace version)`
    # and the bump that moves main past it is the thing being unblocked. So the
    # tag under a fresh record IS the tag both workflows are holding. Naming it
    # as mint intent must refuse, and resolving drift without naming it must
    # walk past it. Getting this backwards turns the record's own scenario into
    # a permanently failing scheduled workflow.
    assert_tag_selection_refused(
        "minting a tag that is itself recorded as abandoned",
        abandonment_manifest(record),
        candidates,
        "v0.4.3 is recorded as an abandoned release tag and must not be released",
        minting_tag="v0.4.3",
    )
    assert_admissible_tag(
        "resolving drift in the same state, declaring no mint intent",
        abandonment_manifest(record),
        candidates,
        "v0.3.6",
        minting_tag="",
    )

    for label, manifest, expected_error in (
        ("a manifest that is not JSON", "{not json", "is not valid JSON"),
        ("a manifest that is a JSON array", "[]", "must be a JSON object"),
        (
            "a manifest declaring another schema",
            json.dumps({"schema_version": 2, "abandoned": []}),
            "must declare schema_version 1",
        ),
        (
            "a manifest carrying an unreviewed key",
            json.dumps({"schema_version": 1, "abandoned": [], "waive_all": True}),
            "unreviewed keys: waive_all",
        ),
        (
            "a manifest with no abandonment array",
            json.dumps({"schema_version": 1}),
            "must carry an 'abandoned' array",
        ),
        (
            "a manifest whose abandonments are an object",
            json.dumps({"schema_version": 1, "abandoned": {}}),
            "must carry an 'abandoned' array",
        ),
        (
            "an abandonment that is a bare tag string",
            json.dumps({"schema_version": 1, "abandoned": ["v0.4.3"]}),
            "every abandonment entry must be a JSON object",
        ),
        (
            "an abandonment carrying an unreviewed field",
            abandonment_manifest({**record, "force": "yes"}),
            "unreviewed fields: force",
        ),
        (
            "an abandonment with no reason",
            abandonment_manifest(
                {key: value for key, value in record.items() if key != "reason"}
            ),
            "missing required evidence: reason",
        ),
        (
            "an abandonment whose reason is blank",
            abandonment_manifest({**record, "reason": "   "}),
            "missing required evidence: reason",
        ),
        (
            "an abandonment with no superseding tag",
            abandonment_manifest(
                {
                    key: value
                    for key, value in record.items()
                    if key != "superseded_by"
                }
            ),
            "missing required evidence: superseded_by",
        ),
        (
            "an abandonment that is not a release tag",
            abandonment_manifest({**record, "tag": "0.4.3"}),
            "abandoned tag '0.4.3' is not a vX.Y.Z release tag",
        ),
        (
            "an abandonment with an abbreviated commit",
            abandonment_manifest({**record, "sha": unbuildable[:12]}),
            "must record the exact 40-hex commit it waives",
        ),
        (
            "an abandonment superseded by a non-release tag",
            abandonment_manifest({**record, "superseded_by": "main"}),
            "must name a vX.Y.Z superseding tag",
        ),
        (
            "an abandonment superseded by itself",
            abandonment_manifest({**record, "superseded_by": record["tag"]}),
            "cannot name itself as its successor",
        ),
        (
            "an abandonment citing no failed run",
            abandonment_manifest({**record, "failed_release_run_id": "0"}),
            "must cite the Release run id that failed",
        ),
        (
            "an abandonment recorded twice",
            abandonment_manifest(record, record),
            "v0.4.3 is recorded as abandoned more than once",
        ),
    ):
        assert_tag_selection_refused(label, manifest, candidates, expected_error)

    assert_tag_selection_refused(
        "a tag listing with no commit",
        abandonment_manifest(record),
        "v0.4.3\n",
        "release tag listing carries an unreadable record",
    )
    assert_tag_selection_refused(
        "a tag listed against two commits",
        abandonment_manifest(record),
        f"v0.3.6 {stable}\nv0.3.6 {older}\n",
        "release tag v0.3.6 was listed against two different commits",
    )

    # The tracked record itself is release authority, so it is exercised rather
    # than trusted: every entry it carries must survive the same validation and
    # actually stop holding the lane.
    shipped = ABANDONED_TAGS.read_text(encoding="utf-8")
    entries = json.loads(shipped)["abandoned"]
    if not entries:
        raise AssertionError(
            "the tracked abandonment record must stay a reviewed ledger of "
            "every tag the release rail has given up on"
        )
    floor = "v0.0.1"
    shipped_candidates = "".join(
        f"{entry['tag']} {entry['sha']}\n" for entry in entries
    )
    assert_admissible_tag(
        "the tracked abandonment record",
        shipped,
        f"{shipped_candidates}{floor} {'9' * 40}\n",
        floor,
    )


def assert_container_base_image_authority(
    dockerfile: str,
    docker_workflow: str,
    release: str,
) -> None:
    """Keep one registry from being able to refuse a release on its own.

    `Docker Image Build (no push)` publishes a check-run against every commit
    that reaches main, and release-tag.yml's second sweep refuses a release
    commit carrying any non-green check-run whether or not a ruleset requires
    it. Minutes of registry unavailability therefore refuse a release
    permanently, which has already cost a cut. Two properties remove that: the
    build resolves base images through a mirror before the canonical registry,
    and every base image is pinned by digest so the two doors cannot serve
    different bytes.
    """

    references = [
        match.group("reference") for match in BASE_IMAGE_PIN.finditer(dockerfile)
    ]
    if not references:
        raise AssertionError(
            "the release container Dockerfile must declare at least one base image"
        )
    for reference in references:
        if re.search(r"@sha256:[0-9a-f]{64}$", reference) is None:
            raise AssertionError(
                "release container base images must be pinned by digest, so a "
                "mirror cannot serve different bytes than the canonical "
                f"registry: {reference}"
            )
        if not reference.startswith(f"{BASE_IMAGE_REGISTRY}/"):
            raise AssertionError(
                "release container base images must name their registry, so the "
                f"reviewed mirror rewrite applies to them: {reference}"
            )

    for label, source, job in (
        ("docker.yml", docker_workflow, "build-image"),
        ("release.yml", release, "build_daemon_image"),
    ):
        block = workflow_job_blocks(source).get(job)
        if block is None:
            raise AssertionError(
                f"{label} no longer declares the {job} job that builds the Dockerfile"
            )
        mirror_input = setup_buildx_mirror_input(block, f"{label}:{job}")
        for needle in (f'[registry."{BASE_IMAGE_REGISTRY}"]', BASE_IMAGE_MIRROR):
            require(mirror_input, needle, f"{label}:{job} base image mirror")


def assert_pin_prover_cannot_refuse_a_release(pins_workflow: str) -> None:
    """Keep the scheduled pin prover unable to red the sha it runs against.

    A `schedule` run's check-runs land on the default branch HEAD, and the
    release sweep treats anything but success, skipped or neutral as a terminal
    refusal. This job therefore must not conclude on what it finds. That held by
    accident once and then stopped holding, because a `run:` step is executed by
    `bash -e {0}` and the step's own `set -o pipefail` is what armed errexit
    against the prover's non-zero status. The remedy read correctly and did
    nothing for a full review round, so the properties it depends on are pinned
    here rather than left to the next reader to re-derive.
    """

    verify = job_step_active_lines(pins_workflow, "verify-pins", "id: verify")
    shell = next(
        (line for line in verify if line.strip().startswith("shell:")),
        None,
    )
    if shell is None:
        raise AssertionError(
            "the pin prover step must declare its shell explicitly; the default "
            "carries -e, which kills the step on the prover status it exists to "
            "capture"
        )
    if re.search(r"(?<![\w-])-\w*e", shell.split("shell:", 1)[1]) is not None:
        raise AssertionError(
            f"the pin prover step's shell must not carry errexit: {shell.strip()}"
        )
    for policy in ("set +e", "exit 0"):
        require(
            "\n".join(verify),
            policy,
            "pin prover step that must not conclude on what it finds",
        )

    checkout = job_step_active_lines(pins_workflow, "verify-pins", "actions/checkout@")
    require(
        "\n".join(checkout),
        "continue-on-error: true",
        "pin prover checkout, whose failure would fail the job regardless of "
        "the guard below it",
    )


def job_step_active_lines(workflow: str, job: str, marker: str) -> list[str]:
    """Return the active lines of the step in `job` that contains `marker`."""

    block = workflow_job_blocks(workflow).get(job)
    if block is None:
        raise AssertionError(f"workflow no longer declares the {job} job")
    lines = block.splitlines()
    hits = [
        index
        for index, line in enumerate(lines)
        if marker in line and not line.lstrip().startswith("#")
    ]
    if len(hits) != 1:
        raise AssertionError(
            f"{job} must contain exactly one step matching {marker!r}, "
            f"found {len(hits)}"
        )
    start = hits[0]
    while start >= 0 and re.match(r"^\s*-\s", lines[start]) is None:
        start -= 1
    if start < 0:
        raise AssertionError(f"{job} step matching {marker!r} has no step start")
    step_indent = len(lines[start]) - len(lines[start].lstrip())
    active = [lines[start]]
    for line in lines[start + 1 :]:
        if not line.strip():
            continue
        if len(line) - len(line.lstrip()) <= step_indent:
            break
        if line.lstrip().startswith("#"):
            continue
        active.append(line)
    return active


def comment_out_mirror_input(workflow: str) -> str:
    """Comment out the buildx mirror input while leaving its text in the file."""

    lines = workflow.splitlines(keepends=True)
    mutated: list[str] = []
    commenting = False
    input_indent = 0
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if stripped.startswith(BASE_IMAGE_MIRROR_INPUT):
            commenting = True
            input_indent = indent
            mutated.append(f"{' ' * indent}# {line.lstrip()}")
            continue
        if commenting:
            if not stripped or indent > input_indent:
                mutated.append(f"{' ' * indent}# {line.lstrip()}" if stripped else line)
                continue
            commenting = False
        mutated.append(line)
    return "".join(mutated)


def setup_buildx_mirror_input(job_block: str, label: str) -> str:
    """Return the active `buildkitd-config-inline` the buildx action receives.

    Asserting the mirror against the job body as raw text accepts a config that
    was commented out and left behind, which is the shape a debugging session
    produces and the one shape a delete-the-string falsification cannot catch.
    Binding the assertion to the input of the step whose `uses:` is the buildx
    action, with comment lines dropped, means only a configuration the action
    is actually handed can satisfy it.
    """

    lines = job_block.splitlines()
    uses = [
        index
        for index, line in enumerate(lines)
        if SETUP_BUILDX_ACTION in line and not line.lstrip().startswith("#")
    ]
    if len(uses) != 1:
        raise AssertionError(
            f"{label} base image mirror expects exactly one buildx setup step, "
            f"found {len(uses)}"
        )

    start = uses[0]
    while start >= 0 and re.match(r"^\s*-\s", lines[start]) is None:
        start -= 1
    if start < 0:
        raise AssertionError(
            f"{label} base image mirror could not find the buildx step's start"
        )
    step_indent = len(lines[start]) - len(lines[start].lstrip())

    active: list[str] = []
    for line in lines[start + 1 :]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= step_indent:
            break
        if line.lstrip().startswith("#"):
            continue
        active.append(line)

    input_index = next(
        (
            index
            for index, line in enumerate(active)
            if line.strip().startswith(BASE_IMAGE_MIRROR_INPUT)
        ),
        None,
    )
    if input_index is None:
        raise AssertionError(
            f"{label} base image mirror is missing required policy: "
            f"{BASE_IMAGE_MIRROR_INPUT}"
        )

    input_indent = len(active[input_index]) - len(active[input_index].lstrip())
    body: list[str] = []
    for line in active[input_index + 1 :]:
        if len(line) - len(line.lstrip()) <= input_indent:
            break
        body.append(line)
    return "\n".join(body)


def main() -> None:
    retired = (
        "auto-tag-release.yml",
        "daemon-image.yml",
        "kin-dependency-wave.yml",
        "publish-install-scripts.yml",
    )
    for name in retired:
        if (WORKFLOWS / name).exists():
            raise AssertionError(
                f"{name} must stay retired; release.yml owns protected public writes"
            )

    release = RELEASE.read_text(encoding="utf-8")
    release_recovery = RELEASE_RECOVERY.read_text(encoding="utf-8")
    release_tag = RELEASE_TAG.read_text(encoding="utf-8")
    release_train = RELEASE_TRAIN.read_text(encoding="utf-8")
    release_sentinel = RELEASE_SENTINEL.read_text(encoding="utf-8")
    sast = SAST.read_text(encoding="utf-8")
    advisory_sweep = ADVISORY_SWEEP.read_text(encoding="utf-8")
    hold_alarm = HOLD_ALARM.read_text(encoding="utf-8")
    proof_gate = PROOF_GATE.read_text(encoding="utf-8")
    release_bot_doc = RELEASE_BOT_DOC.read_text(encoding="utf-8")
    install_proof = INSTALL_PROOF.read_text(encoding="utf-8")
    install_proof_canary = INSTALL_PROOF_CANARY.read_text(encoding="utf-8")
    capability_contract = CAPABILITY_CONTRACT.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    ci_workflow = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    installer_callback = INSTALLER_CALLBACK.read_text(encoding="utf-8")
    update_trust = UPDATE_TRUST.read_text(encoding="utf-8")
    install_sh = INSTALL_SH.read_text(encoding="utf-8")
    install_ps1 = INSTALL_PS1.read_text(encoding="utf-8")
    health = HEALTH.read_text(encoding="utf-8")
    setup = SETUP.read_text(encoding="utf-8")
    quickstart = QUICKSTART_DOC.read_text(encoding="utf-8")
    mcp_tools = MCP_TOOLS_DOC.read_text(encoding="utf-8")
    npm_canonical_readme = NPM_CANONICAL_README.read_text(encoding="utf-8")
    docker_workflow = (WORKFLOWS / "docker.yml").read_text(encoding="utf-8")
    workflow_sources = {
        workflow: workflow.read_text(encoding="utf-8") for workflow in workflow_paths()
    }
    assert_workflow_job_census(workflow_sources)

    external_context_spoof = dict(workflow_sources)
    external_context_spoof[WORKFLOWS / "required-context-spoof.yaml"] = (
        EXTERNAL_REQUIRED_CONTEXT_SPOOF
    )
    expect_assertion(
        "external workflow emits the release-required Check & Test matrix contexts",
        "workflow-wide required-check producer census",
        lambda: assert_workflow_job_census(external_context_spoof),
    )

    quoted_job_spoof = dict(workflow_sources)
    quoted_job_spoof[WORKFLOWS / "ci.yml"] = quoted_job_spoof[
        WORKFLOWS / "ci.yml"
    ].replace(
        "jobs:\n",
        'jobs:\n  "context-spoof":\n'
        "    name: Check & Test\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo success\n",
        1,
    )
    expect_assertion(
        "quoted job id hides a required-context producer before the first job",
        "canonical unquoted scalar",
        lambda: assert_workflow_job_census(quoted_job_spoof),
    )

    unnamed_workflow = WORKFLOWS / "registry-index-migrate.yml"
    if unnamed_workflow not in workflow_sources:
        raise AssertionError(
            "workflow census falsification could not identify an unnamed job"
        )
    unnamed_source = workflow_sources[unnamed_workflow]
    unnamed_lines = unnamed_source.splitlines()
    try:
        unnamed_job_start = unnamed_lines.index("  migrate:")
    except ValueError as error:
        raise AssertionError(
            "workflow census falsification could not identify the unnamed job block"
        ) from error
    for label, child_indent in (
        ("one-space job child mapping", 1),
        ("three-space job child mapping", 3),
        ("wider four-space job child mapping", 4),
    ):
        delta = child_indent - 2
        reindented_children = []
        for line in unnamed_lines[unnamed_job_start + 1 :]:
            if not line.strip():
                reindented_children.append(line)
            elif delta > 0:
                reindented_children.append(" " * delta + line)
            else:
                remove = -delta
                if len(line) - len(line.lstrip()) < remove:
                    raise AssertionError(
                        f"workflow census falsification could not reindent {label}"
                    )
                reindented_children.append(line[remove:])
        indentation_spoof = dict(workflow_sources)
        indentation_spoof[unnamed_workflow] = (
            "\n".join(
                unnamed_lines[: unnamed_job_start + 1]
                + [" " * (2 + child_indent) + "name: cargo-deny"]
                + reindented_children
            )
            + "\n"
        )
        expect_assertion(
            f"{label} hides a required context on an expected unnamed job",
            "canonical two-space child indentation",
            lambda indentation_spoof=indentation_spoof: assert_workflow_job_census(
                indentation_spoof
            ),
        )

    for label, alternate_name_key in (
        ("double-quoted job name key", '"name": cargo-deny'),
        ("single-quoted job name key", "'name': cargo-deny"),
        ("job name key with whitespace before the colon", "name : cargo-deny"),
        ("tagged job name key", "!!str name: cargo-deny"),
    ):
        alternate_name_spoof = dict(workflow_sources)
        alternate_name_spoof[unnamed_workflow] = textwrap.dedent(
            f"""\
            name: Registry Index Migrate
            on:
              push:
                branches: [main]
            permissions:
              contents: read
            jobs:
              migrate:
                {alternate_name_key}
                runs-on: ubuntu-latest
                steps:
                  - run: echo success
            """
        )
        expect_assertion(
            f"{label} emits a required context from an expected unnamed job",
            "canonical unquoted `key:` syntax",
            lambda alternate_name_spoof=alternate_name_spoof: (
                assert_workflow_job_census(alternate_name_spoof)
            ),
        )

    auxiliary_dco = WORKFLOWS / "dco.yml"
    promoted_dco = dict(workflow_sources)
    if promoted_dco[auxiliary_dco].count("    name: DCO sign-off") != 1:
        raise AssertionError(
            "workflow census falsification could not identify auxiliary DCO name"
        )
    promoted_dco[auxiliary_dco] = promoted_dco[auxiliary_dco].replace(
        "    name: DCO sign-off",
        "    name: DCO Sign-off",
        1,
    )
    expect_assertion(
        "auxiliary DCO workflow claims the release-required DCO context",
        "workflow-wide required-check producer census",
        lambda: assert_workflow_job_census(promoted_dco),
    )

    install_proof_workflow = WORKFLOWS / "install-proof.yml"
    dynamic_context_spoof = dict(workflow_sources)
    matrix_row = '{"os":"ubuntu-latest","setup-shell":"bash"}'
    if dynamic_context_spoof[install_proof_workflow].count(matrix_row) != 2:
        raise AssertionError(
            "workflow census falsification could not identify install-proof matrix"
        )
    dynamic_context_spoof[install_proof_workflow] = dynamic_context_spoof[
        install_proof_workflow
    ].replace(
        matrix_row,
        '{"os":"Check & Test (ubuntu-latest)","setup-shell":"bash"}',
        1,
    )
    expect_assertion(
        "dynamic matrix-only job resolves to a release-required context",
        "exact reviewed matrix expansions",
        lambda: assert_workflow_job_census(dynamic_context_spoof),
    )

    require(
        install_sh,
        '"$EXTRACT_DIR/kin$BIN_EXT" registry authority --initialize',
        "content-free Unix installer registry-authority initialization",
    )
    require(
        install_sh,
        "No installed binary or registry authority file was replaced.",
        "fail-closed Unix installer registry-authority preflight",
    )
    require(
        install_ps1,
        '@("registry", "authority", "--json")',
        "honest Windows registry-authority capability report",
    )
    if "KIN_REGISTRY_REPAIR" in install_ps1:
        raise AssertionError(
            "Windows installer must not imply Unix mode repair support"
        )
    if "KIN_CI_BOT_TOKEN" in release or "bump_homebrew:" in release:
        raise AssertionError(
            "release.yml must not use a long-lived PAT or wait on cross-repo "
            "follow-ups before the completed-release callback can run"
        )
    if "workflow_dispatch:" in release:
        raise AssertionError(
            "release.yml must not expose branch-selectable workflow_dispatch"
        )
    require(release, 'tags:\n      - "v*.*.*"', "release trigger")
    require(release, "  build_daemon_image:", "release daemon image job")
    require(release, "  attest_daemon_image:", "release daemon attestation job")
    for policy in (
        "  seal_release_completion:",
        "name: Seal completed stable release",
        "needs.promote_ghcr_latest.result == 'success'",
        "needs.publish_boundary_contracts.result == 'success'",
        "release-promotion.json.sha256",
        "release_workflow_run_id",
        "completed_capstones",
        "Attest terminal completion marker",
        "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
        "Refuse mismatched existing completion assets",
        "Verify public terminal completion proof",
    ):
        require(release, policy, "terminal stable-release completion seal")

    for policy in (
        'workflows: ["CI"]',
        "types: [completed]",
        'cron: "11,26,41,56 * * * *"',
        "actions: read",
        "attestations: read",
        "contents: read",
        "checks: read",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'main'",
        "repository_dispatch:",
        "types: [release_tag]",
        "github.event.action",
        "github.event.repository.default_branch",
        "github.event.client_payload.tag",
        "github.event.client_payload.sha",
        "EVENT_SHA: ${{ github.sha }}",
        'EVENT_NAME" != repository_dispatch',
        'EVENT_ACTION" != release_tag',
        'DEFAULT_BRANCH" != main',
        'REF" != "refs/heads/$DEFAULT_BRANCH"',
        "environment: release-tag",
        'git show "${authority_main}:scripts/release-intent.mjs" > "$policy"',
        '"$node_bin" "$policy"',
        "git merge-base --is-ancestor",
        "break-glass release sha",
        "actions/workflows/release.yml/runs?per_page=100",
        '.status == "requested"',
        ".status == \"queued\"",
        ".conclusion == \"success\"",
        "release-provenance.json.sha256",
        "release-promotion.json.sha256",
        "gh attestation verify release-provenance.json",
        "gh attestation verify release-promotion.json",
        "release_workflow_run_id",
        "runInvocationURI",
        "runDetails.metadata.invocationId",
        "ltrimstr($run_uri)",
        "verifiedTimestamps",
        "registry.npmjs.org/@kinlab%2F",
        "ghcr.io/v2/firelock-ai/kin/manifests",
        "oci://ghcr.io/firelock-ai/kin@${ghcr_latest}",
        "--bundle-from-oci",
        'latest_tag" != v0.3.6',
        "markerless logless fallback is retired",
        "matching_count",
        "highest_tag",
        "refs/remotes/origin/main:scripts/abandoned-release-tags.json",
        "refs/remotes/origin/main:scripts/select-admissible-release-tag.py",
        "git for-each-ref",
        TAG_LISTING_FORMAT,
        'python3 "$selector"',
        'highest_tag="$(cat "$admissible")"',
        "REQUIRED_CHECKS:",
        'GITHUB_ACTIONS_APP_ID: "15368"',
        "GITHUB_ACTIONS_APP_SLUG: github-actions",
        "app_id: (.app.id // 0)",
        'actual_app = (run.get("app_id"), run.get("app_slug"))',
        "if actual_app != expected_app:",
        "check-runs?per_page=100&filter=all",
        "head_branch: .head_branch",
        'release_branch = "main"',
        "expected_provenance = {",
        "tier = evidence_tier(workflow)",
        ") != expected_producer:",
        "if tier == authority_tier:",
        "ambiguous required check",
        # The rekey onto the merge-group-proven sha. Each of these is one half
        # of a proof that cannot be dropped on its own: the queue anchor names
        # the ref, the parent read from checked-out history is what the ref's
        # embedded base has to equal, and the tier decision is what keeps a
        # duplicated context from reading as ambiguous authority.
        'RELEASE_PARENT_SHA="$(git rev-parse "${SHA}^")"',
        "queue_anchor_workflow = (245803170",
        'authority_tier = "merge_group" if queue_ref is not None else "push"',
        "ambiguous merge-group evidence",
        "merge-group evidence is not on a merge-queue ref",
        "merge-group evidence sha mismatch",
        "merge-group evidence proved a different tree",
        "corroborating required check not green",
        "RULESET_REQUIRED_CHECKS:",
        "ruleset-required context has no admitted build at",
        "mint requires a context the reviewed main ruleset does not",
        'allowed_conclusions = (\n                  {"success", "skipped"}',
        "release_tag_suite_ids",
        "did not settle within 30 minutes",
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "repositories: kin",
        "break-glass release sha $SHA is no longer current origin/main HEAD",
        'ref="refs/tags/$TAG"',
    ):
        require(release_tag, policy, "automatic App-mediated release tag admission")
    for forbidden in (
        "workflow_dispatch:",
        "${{ inputs.",
        "contents: write",
        "packages: write",
        "id-token: write",
        "KIN_CI_BOT_TOKEN",
    ):
        if forbidden in release_tag:
            raise AssertionError(
                f"release-tag workflow contains forbidden standing authority: {forbidden}"
            )

    resolve_start = release_tag.index(
        "      - name: Resolve exact coherent release commit\n"
    )
    resolve_end = release_tag.index(
        "      - name: Re-verify checked-out SHA is on reviewed origin/main history\n"
    )
    resolve_step = release_tag[resolve_start:resolve_end]
    authority_main = resolve_step.index(
        'authority_main="$(git rev-parse refs/remotes/origin/main)"'
    )
    automatic_authority = resolve_step.index(
        'git merge-base --is-ancestor "$sha" "$authority_main"'
    )
    break_glass_authority = resolve_step.index(
        'elif [ "$sha" != "$authority_main" ]; then'
    )
    trusted_node = resolve_step.index('node_bin="$(command -v node)"')
    trusted_policy = resolve_step.index(
        'git show "${authority_main}:scripts/release-intent.mjs" > "$policy"'
    )
    target_checkout = resolve_step.index('git checkout --detach "$sha"')
    intent_execution = resolve_step.index('"$node_bin" "$policy"')
    runner_state_isolation = tuple(
        resolve_step.index(marker)
        for marker in (
            'GITHUB_ENV="$intent_env"',
            'GITHUB_PATH="$intent_path"',
            'GITHUB_STATE="$intent_state"',
        )
    )
    if not (
        authority_main
        < automatic_authority
        < break_glass_authority
        < trusted_node
        < trusted_policy
        < target_checkout
        < min(runner_state_isolation)
        <= max(runner_state_isolation)
        < intent_execution
    ):
        raise AssertionError(
            "release-tag must validate the selected SHA against freshly fetched "
            "main, copy trusted current-main policy, and isolate runner state "
            "before checkout or policy execution"
        )
    if "node scripts/release-intent.mjs" in resolve_step:
        raise AssertionError(
            "release-tag must not execute release policy from the "
            "payload-selected checkout"
        )

    for policy in (
        'name: Release Train',
        'workflows: ["CI"]',
        'cron: "7,22,37,52 * * * *"',
        "types: [release-reconcile]",
        "contents: read",
        "issues: write",
        "pull-requests: write",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'main'",
        "github.event.workflow_run.conclusion == 'success'",
        # The train reconciles off the queue's CI completion as well, for the
        # same reason the mint does: it is the occasion that arrives when the
        # landing does rather than half an hour later.
        "github.event.workflow_run.event == 'merge_group'",
        "startsWith(github.event.workflow_run.head_branch, 'gh-readonly-queue/main/')",
        "environment: release-tag",
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "repositories: kin",
        "BRANCH: automation/release-next",
        'git show "refs/remotes/origin/main:${policy}"',
        'node "$policy_dir/prepare-release.mjs"',
        'node "$policy_dir/check-release-version.mjs"',
        'node "$policy_dir/release-intent.mjs"',
        "release branch contains non-generated paths",
        "git restore --source refs/remotes/origin/main",
        '.headRepositoryOwner.login == "firelock-ai"',
        '.headRepository.nameWithOwner == "firelock-ai/kin"',
        "highest_tag",
        "refs/remotes/origin/main:scripts/abandoned-release-tags.json",
        "refs/remotes/origin/main:scripts/select-admissible-release-tag.py",
        "git for-each-ref",
        TAG_LISTING_FORMAT,
        'python3 "$selector"',
        'highest_tag="$(cat "$admissible")"',
        "git merge --signoff --no-edit -X ours refs/remotes/origin/main",
        'gh pr merge "$PR"',
        "GH_TOKEN: ${{ steps.app-token.outputs.token }}",
        "--match-head-commit",
        "--auto",
        "--squash",
        "git commit --allow-empty --signoff",
        "Activate protected checks for the automated release PR",
        'node "$intent_policy"',
        'git show "refs/remotes/origin/main:scripts/resolve-release-intent.mjs"',
        '--base-ref "$tag"',
        "--head-ref refs/remotes/origin/main",
        "unsupported immutable release intent",
        '.squash_merge_commit_title == "PR_TITLE"',
        '.squash_merge_commit_message == "PR_BODY"',
        "immutable PR-body release intent requires enforced PR_TITLE + PR_BODY "
        "squash-only merging",
        # GitHub withholds the merge-policy fields from a token without
        # push-level repository access, so the read must stay bound to the
        # repository-scoped App installation token rather than the read-scoped
        # GITHUB_TOKEN that the rest of the step uses.
        "MERGE_POLICY_TOKEN: ${{ steps.app-token.outputs.token }}",
        'GH_TOKEN="$MERGE_POLICY_TOKEN" gh api "repos/${REPO}"',
        "absent from the API response",
        "repository merge policy response was not a JSON object",
    ):
        require(release_train, policy, "coalescing protected release train")
    assert_merge_policy_gate(release_train)
    assert_release_pr_author_identity(release_train)
    # The reverts this pin has to survive, in the order they are reachable: the
    # binding falling back to the default token, a per-command token quietly
    # restoring it while the environment still reads as the App, and creation
    # moving out from under the step the pin is anchored to.
    expect_assertion(
        "the release PR opener falls back to the Actions token",
        f"must bind GH_TOKEN to the minted App installation token {RELEASE_APP_TOKEN}",
        lambda: assert_release_pr_author_identity(
            rebind_release_pr_token(release_train, DEFAULT_WORKFLOW_TOKEN)
        ),
    )
    expect_assertion(
        "the release PR opener overrides its token for the create call",
        "must not override GH_TOKEN inline",
        lambda: assert_release_pr_author_identity(
            release_train.replace(
                "            gh pr create \\",
                '            GH_TOKEN="$FALLBACK" gh pr create \\',
                1,
            )
        ),
    )
    expect_assertion(
        "pull-request creation leaves the step whose token the pin binds",
        "protected release PR opener is missing required policy: gh pr create",
        lambda: assert_release_pr_author_identity(
            release_train.replace("gh pr create \\", "gh pr view \\", 1)
        ),
    )
    release_train_body = RELEASE_TRAIN_BODY.read_text(encoding="utf-8")
    assert_release_pr_body_preserves_operator_text(release_train, release_train_body)
    # The reverts this preservation has to survive, in the order they are
    # reachable: the generic line going back to an inline overwrite, the merge
    # moving off protected main and onto the branch under judgement, and the
    # created body losing its file.
    expect_assertion(
        "the release PR body returns to an inline literal overwrite",
        "must never be written from an inline literal",
        lambda: assert_release_pr_body_preserves_operator_text(
            release_train.replace(
                '--body-file "$next_body"',
                '--body "Automated, coalescing Kin release PR."',
                1,
            ),
            release_train_body,
        ),
    )
    expect_assertion(
        "the release PR body merge stops being read from protected main",
        f"is missing required policy: {TRUSTED_POLICY_PREFIX}"
        f"{RELEASE_TRAIN_BODY_POLICY}",
        lambda: assert_release_pr_body_preserves_operator_text(
            release_train.replace(
                f"{TRUSTED_POLICY_PREFIX}{RELEASE_TRAIN_BODY_POLICY}",
                RELEASE_TRAIN_BODY_POLICY,
                1,
            ),
            release_train_body,
        ),
    )
    expect_assertion(
        "a second body merge runs from the branch beside the trusted read",
        "must be read from protected main",
        lambda: assert_release_pr_body_preserves_operator_text(
            release_train.replace(
                'node "$merge_body"',
                f"node {RELEASE_TRAIN_BODY_POLICY}",
                1,
            ),
            release_train_body,
        ),
    )
    expect_assertion(
        "the created release PR body stops coming from the merged file",
        'is missing required policy: --body-file "$initial_body"',
        lambda: assert_release_pr_body_preserves_operator_text(
            release_train.replace('--body-file "$initial_body"', "--body-file -", 1),
            release_train_body,
        ),
    )
    expect_assertion(
        "the body merge loses the markers that delimit what the train owns",
        f"is missing required policy: {RELEASE_TRAIN_BODY_BEGIN}",
        lambda: assert_release_pr_body_preserves_operator_text(
            release_train, release_train_body.replace(RELEASE_TRAIN_BODY_BEGIN, "")
        ),
    )
    assert_release_branch_allowlist_covers_generator(release_train)
    assert_abandoned_tag_admission(release_tag, release_train, release_recovery)
    # The release bump must never be resolvable from anything a merged pull
    # request can still change.
    for forbidden in (
        "workflow_dispatch:",
        "contents: write",
        "packages: write",
        "id-token: write",
        "git push --force",
        "git push -f",
        "client_payload.bump",
        "OVERRIDE_BUMP",
        "/pulls\" \\",
        "raise_bump",
        "train_labels",
    ):
        if forbidden in release_train:
            raise AssertionError(
                f"release train contains forbidden authority or history rewrite: {forbidden}"
            )

    for policy in (
        "Create the protected `release-tag` Environment",
        "allows **only `main`**",
        "forbids",
        "branch-selectable",
        "`workflow_dispatch`",
        "last commit on the default branch",
        "exists there",
        "only as `release-tag` Environment secrets",
        "any other eligible workflow",
        "repository could explicitly request a broadly scoped secret",
        "Remove or rotate away every",
        "organization-level copy visible",
        "gh api --method POST repos/firelock-ai/kin/dispatches --input -",
        '{event_type:"release_tag",client_payload:{tag:$tag,sha:$sha}}',
        # The abandonment operating rule has to live where an operator editing
        # the record will read it. JSON carries no comments, so the record file
        # itself cannot hold it, and a Python module docstring is not where the
        # person writing an entry is looking.
        "## Abandoning a release tag",
        "record the abandonment and leave the tag in place",
        "The only exit from that state is a hand-landed version bump",
        "a tag that has since moved refuses loudly",
        "fails the rail closed rather",
        # No CI job executes a line of release-recovery.yml: it triggers on
        # schedule and workflow_run only, so this prose is the whole of what an
        # operator has when a reconcile goes green while a release is visibly
        # broken. Each clause is pinned because each is separately droppable:
        # that the stand-down exists, that it is narrow, that recovery is a
        # consumer of the record at all, and that a record too weak for the rail
        # is too weak to quiet the alarm.
        "is reconciled instead of alerted",
        "still opens the issue and still fails the reconcile",
        "automatic recovery stands down for it",
        "cannot quiet the alarm either",
    ):
        require(
            release_bot_doc,
            policy,
            "default-branch-pinned release dispatch runbook",
        )
    if "Recommended hardening (optional)" in release_bot_doc:
        raise AssertionError(
            "release App Environment isolation must be mandatory, not optional"
        )
    if "gh workflow run release-tag.yml" in release_bot_doc:
        raise AssertionError(
            "release break glass must use typed repository_dispatch, not "
            "branch-selectable workflow_dispatch"
        )
    for policy in (
        "last commit on the default branch",
        "exists there",
        "forbids",
        "branch-selectable `workflow_dispatch`",
        "exact current-main payload",
        "must",
        "exist only as Environment secrets",
        "every broader copy must be removed or",
        "production-ready",
    ):
        require(
            update_trust,
            policy,
            "default-branch-pinned release App trust boundary",
        )

    for policy in (
        "name: Release Recovery",
        'workflows: ["Release"]',
        'cron: "3,18,33,48 * * * *"',
        "actions: write",
        "contents: read",
        "issues: write",
        "github.event.workflow_run.conclusion == 'failure'",
        "github.event.workflow_run.conclusion == 'timed_out'",
        "github.event.workflow_run.conclusion == 'startup_failure'",
        "actions/workflows/release.yml/runs?per_page=100",
        '.status == "requested"',
        '.path == ".github/workflows/release.yml"',
        '.head_repository.full_name == $repo',
        "rerun-failed-jobs",
        '[ "$attempt" -ge 3 ]',
        "name: Classify the failure signature across attempts",
        "steps.classify.outputs.repeated != 'true'",
        "steps.classify.outputs.repeated == 'true'",
        "Release blocked after automatic retries",
        "scripts/abandoned-release-tags.json",
        "scripts/select-admissible-release-tag.py",
        '[ "$head" != "$GITHUB_SHA" ]',
        "reconciled by abandonment",
    ):
        require(release_recovery, policy, "bounded automatic release recovery")

    # Recovery is outside the mint's reviewed veto set, but it still must not
    # spend runners or raise an advisory alarm for a release the reviewed record
    # retired. Parse active step fields so a comment repeating the condition
    # cannot satisfy the guard while the YAML `if` omits it.
    # The proof is the best gate Kin has and it ran only once a tag existed, so
    # a change that broke it was discovered one release late and could not be
    # repaired in place. The canary moves the portable half of that contract onto
    # main. What binds the two is here, because two copies of one contract drift
    # in the direction that matters: the canary stays green while the proof it
    # predicts starts failing at a tag.
    assert_capability_canary_contract(
        install_proof, install_proof_canary, capability_contract
    )
    expect_assertion(
        "the proof requires a check the canary does not",
        "must require exactly the health checks",
        lambda: assert_capability_canary_contract(
            install_proof,
            install_proof_canary,
            capability_contract.replace('  "setup_ledger",\n', "", 1),
        ),
    )
    expect_assertion(
        "the canary drops the classifier that fenced v0.5.18 from its path filter",
        "path filter must cover",
        lambda: assert_capability_canary_contract(
            install_proof,
            install_proof_canary.replace(
                '      - "crates/kin-cli/src/commands/health.rs"\n', "", 2
            ),
            capability_contract,
        ),
    )
    expect_assertion(
        "the canary can pass without ever observing coverage",
        "check that cannot fail is not evidence",
        lambda: assert_capability_canary_contract(
            install_proof,
            install_proof_canary.replace("--require-observed \\\n", ""),
            capability_contract,
        ),
    )
    expect_assertion(
        "the canary grows the authority to publish",
        "must neither publish nor promote",
        lambda: assert_capability_canary_contract(
            install_proof,
            install_proof_canary.replace(
                "permissions:\n  contents: read\n",
                "permissions:\n  contents: write\n",
                1,
            ),
            capability_contract,
        ),
    )
    expect_assertion(
        "the canary stops running the shared contract at all",
        "must actually run the shared capability contract",
        lambda: assert_capability_canary_contract(
            install_proof,
            install_proof_canary.replace("scripts/verify-capability-proof.mjs", "true"),
            capability_contract,
        ),
    )
    expect_assertion(
        "the canary loses its nightly run and only fires on anticipated paths",
        "must run nightly against main",
        lambda: assert_capability_canary_contract(
            install_proof,
            install_proof_canary.replace("  schedule:\n", "  # schedule:\n", 1),
            capability_contract,
        ),
    )

    assert_recovery_abandonment_stand_down(release_recovery)
    expect_assertion(
        "recovery repeats its stand-down condition only in comments",
        "must actively stand down",
        lambda: assert_recovery_abandonment_stand_down(
            release_recovery.replace(
                "          steps.record.outputs.abandoned != 'true'",
                "          # steps.record.outputs.abandoned != 'true'",
            )
        ),
    )

    # Where the release evidence is keyed decides whether main has to hold
    # still. Keyed to a branch head the train rewrites, it did; keyed to a main
    # commit and checked against the tag, it does not. Nothing pinned that
    # before, so the whole arrangement is pinned here together with the refusal
    # it carries.
    assert_release_proof_key_authority(
        release_train, release_tag, release, proof_gate
    )
    expect_assertion(
        "the mint stops comparing the proven sha to the sha it tags",
        "refuse when the sha the gate verified",
        lambda: assert_release_proof_key_authority(
            release_train,
            replace_exactly_once(
                release_tag,
                'if [ "$proven" != "$SHA" ]; then',
                'if [ "$proven" = "never" ]; then',
                "proof gate identity",
            ),
            release,
            proof_gate,
        ),
    )
    expect_assertion(
        "the mint stops stating that the tagged tree is the proven tree",
        "state that the tree it tags is the tree that was proven",
        lambda: assert_release_proof_key_authority(
            release_train,
            replace_exactly_once(
                release_tag,
                'delta="$(git diff --name-only "$proven" "$SHA")"',
                'delta=""',
                "proof gate tree identity",
            ),
            release,
            proof_gate,
        ),
    )
    expect_assertion(
        "the proof gate runs after the tag ref it was supposed to gate",
        "must run before the tag ref is written",
        lambda: assert_release_proof_key_authority(
            release_train,
            swap_release_tag_step_order(release_tag),
            release,
            proof_gate,
        ),
    )
    expect_assertion(
        "the mint takes a truncated evidence listing at face value",
        "refuse a truncated listing",
        lambda: assert_release_proof_key_authority(
            release_train,
            replace_exactly_once(
                release_tag,
                "jq -r '.truncated // false' <<< \"$listing\"",
                "jq -r 'false' <<< \"$listing\"",
                "truncated listing refusal",
            ),
            release,
            proof_gate,
        ),
    )
    expect_assertion(
        "the train keys a release on the version bump branch's head again",
        "must key nothing on the version bump branch's head",
        lambda: assert_release_proof_key_authority(
            replace_exactly_once(
                release_train,
                "      - name: Arm protected auto-merge\n",
                "      - name: Require proof-loop artifacts for the candidate\n"
                "        run: |\n"
                "          git show "
                f'"refs/remotes/origin/main:{PROOF_GATE_POLICY}" > gate\n'
                "\n"
                "      - name: Arm protected auto-merge\n",
                "release train proof key",
            ),
            release_tag,
            release,
            proof_gate,
        ),
    )
    # The same regression, planted where the general comment stripper cannot
    # see it. `refs/tags/*` opens a C-style block comment for `active_lines`,
    # which then swallows the next eleven thousand characters of the reconcile
    # job, and this anchor sits inside that range. Reading the job through that
    # rule reports absence for a step that is right there, so the guard uses a
    # shell-safe reader and this proves it.
    expect_assertion(
        "the train keys a release on the bump branch head inside the "
        "block-comment blind spot",
        "must key nothing on the version bump branch's head",
        lambda: assert_release_proof_key_authority(
            replace_exactly_once(
                release_train,
                '          test -s "$abandoned"\n',
                '          test -s "$abandoned"\n'
                f'          git show "refs/remotes/origin/main:{PROOF_GATE_POLICY}" > gate\n',
                "release train proof key, blind spot",
            ),
            release_tag,
            release,
            proof_gate,
        ),
    )
    expect_assertion(
        "the promote gate stops asking about the tagged commit itself",
        "ask about the tagged commit directly",
        lambda: assert_release_proof_key_authority(
            release_train,
            release_tag,
            replace_exactly_once(
                release,
                "          CANDIDATE_SHA: ${{ github.sha }}\n",
                "",
                "promote gate direct key",
            ),
            proof_gate,
        ),
    )
    expect_assertion(
        "the promote gate stops bridging a tag with no direct record",
        "keep the bridge, which is what makes a tag with no direct record",
        lambda: assert_release_proof_key_authority(
            release_train,
            release_tag,
            replace_exactly_once(
                release,
                "          RESOLVE_FROM_COMMIT: ${{ github.sha }}\n",
                "",
                "promote gate bridge",
            ),
            proof_gate,
        ),
    )
    expect_assertion(
        "the proof gate's bridge stops being bounded to the bump branch",
        "must apply the bump-branch bound when it bridges",
        lambda: assert_release_proof_key_authority(
            release_train,
            release_tag,
            release,
            replace_exactly_once(
                proof_gate,
                "produced.filter((pull) => pull?.head?.ref === BUMP_BRANCH)",
                "produced.filter((pull) => pull !== null)",
                "proof gate bump-branch bound",
            ),
        ),
    )
    expect_assertion(
        "the bump branch is renamed in the train and not in the gate",
        "must be bounded to the same bump branch",
        lambda: assert_release_proof_key_authority(
            replace_exactly_once(
                release_train,
                "          BRANCH: automation/release-next\n",
                "          BRANCH: automation/release-later\n",
                "bump branch rename",
            ),
            release_tag,
            release,
            proof_gate,
        ),
    )
    expect_assertion(
        "the proof gate bridges on a record it could not read",
        "must bridge only when the direct record is ABSENT",
        lambda: assert_release_proof_key_authority(
            release_train,
            release_tag,
            release,
            replace_exactly_once(
                proof_gate,
                "if (!error.evidenceAbsent || !resolveFromCommit) {",
                "if (!resolveFromCommit) {",
                "proof gate absence-only bridge",
            ),
        ),
    )
    expect_assertion(
        "the mint reads the evidence listing without testing whether it read one",
        "test the status of the listing read",
        lambda: assert_release_proof_key_authority(
            release_train,
            replace_exactly_once(
                release_tag,
                'if ! listing="$(gh api',
                'if listing="$(gh api',
                "listing read status",
            ),
            release,
            proof_gate,
        ),
    )
    expect_assertion(
        "the mint throws away why the evidence listing could not be read",
        "keep the error text from the listing read",
        lambda: assert_release_proof_key_authority(
            release_train,
            replace_exactly_once(
                release_tag,
                '"repos/${REPO}/git/trees/release-evidence?recursive=1" \\\n'
                '              2>"$read_error")"; then',
                '"repos/${REPO}/git/trees/release-evidence?recursive=1" \\\n'
                '              2>/dev/null)"; then',
                "listing read diagnostics",
            ),
            release,
            proof_gate,
        ),
    )
    expect_assertion(
        "the train arms auto-merge without un-drafting the bump pull request",
        "un-draft the bump pull request before it arms auto-merge",
        lambda: assert_release_proof_key_authority(
            replace_exactly_once(
                release_train,
                '            gh pr ready "$PR" --repo "$GITHUB_REPOSITORY"\n',
                "",
                "release train un-draft",
            ),
            release_tag,
            release,
            proof_gate,
        ),
    )
    # The same regression as an ordering change rather than a deletion. Both
    # commands survive, so only the ordering check can catch it, and arming
    # first is not a smaller mistake: auto-merge registered against a draft is
    # what leaves the rail reporting itself clear while nothing lands.
    expect_assertion(
        "the train un-drafts the bump pull request after it has already armed",
        "must un-draft the bump pull request BEFORE it",
        lambda: assert_release_proof_key_authority(
            swap_train_undraft_after_arm(release_train),
            release_tag,
            release,
            proof_gate,
        ),
    )
    expect_assertion(
        "the promote gate stops reading back the sha the gate verified",
        "read back the sha the gate verified",
        lambda: assert_release_proof_key_authority(
            release_train,
            release_tag,
            replace_exactly_once(
                release,
                "process.stdout.write(result.sha);",
                'process.stdout.write("verified");',
                "promote gate sha readback",
            ),
            proof_gate,
        ),
    )
    expect_assertion(
        "the promote gate stops comparing the proven sha to the one it promotes",
        "not the sha it promotes",
        lambda: assert_release_proof_key_authority(
            release_train,
            release_tag,
            replace_exactly_once(
                release,
                'if [ "$proven" != "$CANDIDATE_SHA" ]; then',
                'if [ "$proven" = "never" ]; then',
                "promote gate identity",
            ),
            proof_gate,
        ),
    )

    # A hold is a correct decision that used to reach nobody. The marker is what
    # makes it readable and the alarm job is what makes it heard, so the pair is
    # pinned together: a producer with no consumer and a consumer with no
    # producer both read exactly like a healthy rail.
    assert_release_hold_marker_contract(release_train, release_sentinel, hold_alarm)
    expect_assertion(
        "a release-train stand-down publishes no hold marker",
        "must publish a hold marker",
        lambda: assert_release_hold_marker_contract(
            release_train.replace(
                '            write_marker held no_drift "main has no commits beyond ${tag}" \\\n'
                '              "" "$tag" 0\n',
                "",
                1,
            ),
            release_sentinel,
            hold_alarm,
        ),
    )
    expect_assertion(
        "the alarm opens an issue and still concludes the run green",
        "must also fail its run",
        lambda: assert_release_hold_marker_contract(
            release_train.replace(
                '              echo "::error::The release rail has held with releasable drift '
                'for $(jq -er .consecutive "$decision") consecutive cycles. Opened the tracking '
                'issue that names the blocking tag and the two ways out."\n'
                "              exit 1\n",
                '              echo "::error::The release rail has held with releasable drift '
                'for $(jq -er .consecutive "$decision") consecutive cycles. Opened the tracking '
                'issue that names the blocking tag and the two ways out."\n',
                1,
            ),
            release_sentinel,
            hold_alarm,
        ),
    )
    expect_assertion(
        "the sentinel stops naming the one alarm title the reader owns",
        "must spell the one reviewed alarm title",
        lambda: assert_release_hold_marker_contract(
            release_train,
            release_sentinel.replace(
                "Release rail is held with releasable drift",
                "Release rail is stuck",
            ),
            hold_alarm,
        ),
    )
    expect_assertion(
        "the reader accepts a schema the train never stamps",
        "must accept exactly the schema",
        lambda: assert_release_hold_marker_contract(
            release_train,
            release_sentinel,
            hold_alarm.replace(
                'MARKER_SCHEMA = "kin.release-hold.v1"',
                'MARKER_SCHEMA = "kin.release-hold.v2"',
            ),
        ),
    )
    expect_assertion(
        "the train and the reader disagree about how many cycles it takes",
        "must pass the same consecutive-cycle threshold",
        lambda: assert_release_hold_marker_contract(
            release_train,
            release_sentinel,
            hold_alarm.replace(
                "DEFAULT_THRESHOLD = 4",
                "DEFAULT_THRESHOLD = 6",
            ),
        ),
    )
    expect_assertion(
        "the alarm counts every skipped workflow_run tick as a cycle",
        "must stand down on a skipped reconcile",
        lambda: assert_release_hold_marker_contract(
            release_train.replace(
                "    if: always() && needs.reconcile.result != 'skipped'",
                "    if: always()",
                1,
            ),
            release_sentinel,
            hold_alarm,
        ),
    )
    expect_assertion(
        "the train stops uploading the marker later cycles read",
        "must download exactly the artifact the train uploads",
        lambda: assert_release_hold_marker_contract(
            release_train.replace(
                "--name release-hold-marker \\",
                "--name release-hold-marker-v2 \\",
                1,
            ),
            release_sentinel,
            hold_alarm,
        ),
    )
    for forbidden in (
        "workflow_dispatch:",
        "contents: write",
        "packages: write",
        "id-token: write",
        "conclusion == 'cancelled'",
    ):
        if forbidden in release_recovery:
            raise AssertionError(
                f"release recovery contains forbidden authority or retry state: {forbidden}"
            )

    # A dotted quad is not a version. `\b\d+\.\d+\.\d+\b` matches "127.0.0" inside
    # "127.0.0.1", so documenting a loopback endpoint tripped this guard with a message
    # about pinning a release. Refuse a match that has a digit or dot on either side.
    pinned_readme_version = re.search(r"(?<![\d.])v?\d+\.\d+\.\d+(?![\d.])", readme)
    if pinned_readme_version:
        raise AssertionError(
            "README must follow the proven latest release instead of pinning "
            f"{pinned_readme_version.group(0)}"
        )
    for policy in (
        "[![Latest release](https://img.shields.io/badge/release-latest-6E56CF.svg)]",
        "https://github.com/firelock-ai/kin/releases/latest",
        "https://github.com/firelock-ai/kin/releases/latest/download/",
        "npm install -g @kinlab/kin@latest",
    ):
        require(readme, policy, "moving latest-release README reference")
    if "img.shields.io/github/v/release" in readme:
        raise AssertionError(
            "README release badge must follow /releases/latest, not an unpromoted GitHub tag"
        )

    first_run_start = install_proof.index(
        "      - name: First-run repository, daemon, and setup proof"
    )
    # The guarded span ends at the next step rather than three steps later, so
    # the failure message naming the first-run step describes the region it
    # actually covers and a legitimate later `kin init` is not misdiagnosed.
    graph_query_start = install_proof.index(
        "      - name: Graph query and MCP tool-call proof",
        first_run_start,
    )
    embedding_start = install_proof.index(
        "      - name: Unix embedding and semantic retrieval proof",
        graph_query_start,
    )
    restore_start = install_proof.index(
        "      - name: Restore captured proof reports into the proof repository",
        embedding_start,
    )
    validation_start = install_proof.index(
        "      - name: Validate installed capability proof",
        restore_start,
    )
    preserve_start = install_proof.index(
        "      - name: Preserve proof reports",
        validation_start,
    )
    first_run = install_proof[first_run_start:graph_query_start]
    graph_query = install_proof[graph_query_start:embedding_start]
    embedding = install_proof[embedding_start:restore_start]
    restore = install_proof[restore_start:validation_start]
    validation = install_proof[validation_start:preserve_start]
    for policy in (
        'case "$PROOF_SHELL" in',
        "export SHELL=/bin/bash",
        "export SHELL=/bin/zsh",
        'printf \'SHELL=%s\\n\' "$SHELL" >> "$GITHUB_ENV"',
    ):
        require(first_run, policy, "cross-step install-proof shell pin")
    assert_install_proof_init_log_authority(first_run)
    assert_install_proof_first_run_never_pipes_the_daemon_spawner(first_run)
    for label, original, mutation, expected in (
        (
            "the first setup goes back through a pipe",
            '            > "$captures/kin-setup.txt" 2>&1 || setup_status=$?',
            '            2>&1 | tee "$captures/kin-setup.txt"',
            "never by pipe",
        ),
        (
            "the fallback setup goes back through a pipe",
            '            > "$captures/kin-claude-fallback-setup.txt" 2>&1 || fallback_setup_status=$?',
            '            2>&1 | tee "$captures/kin-claude-fallback-setup.txt"',
            "never by pipe",
        ),
        (
            "a failing setup stops reaching the job log",
            '          cat "$captures/kin-setup.txt"\n',
            "",
            "unpiped first-run setup capture",
        ),
        (
            "a refused setup stops failing the install proof",
            '          if [ "$setup_status" -ne 0 ]; then exit "$setup_status"; fi\n',
            "",
            "unpiped first-run setup capture",
        ),
        (
            "a refused fallback setup stops failing the install proof",
            '          if [ "$fallback_setup_status" -ne 0 ]; then exit "$fallback_setup_status"; fi\n',
            "",
            "unpiped first-run setup capture",
        ),
    ):
        if original not in first_run:
            raise AssertionError(
                "first-run unpiped-setup falsification lost fixture for "
                f"{label}: {original!r}"
            )
        expect_assertion(
            label,
            expected,
            lambda mutated=first_run.replace(original, mutation, 1): (
                assert_install_proof_first_run_never_pipes_the_daemon_spawner(mutated)
            ),
        )
    expect_assertion(
        "kin init writes its log into the worktree it admits",
        "outside the worktree it admits",
        lambda: assert_install_proof_init_log_authority(
            first_run.replace(
                'kin init > "$captures/kin-init.txt" 2>&1 || init_status=$?',
                "kin init 2>&1 | tee kin-init.txt",
                1,
            )
        ),
    )
    expect_assertion(
        "a second kin init escapes the admitted-worktree contract",
        "exactly once",
        lambda: assert_install_proof_init_log_authority(
            f"{first_run}\n          kin init\n"
        ),
    )
    for label, active_line in (
        (
            "the capture directory stops being rooted outside the worktree",
            'captures="$RUNNER_TEMP/kin-proof-captures"',
        ),
        (
            "a refused init stops failing the install proof",
            'if [ "$init_status" -ne 0 ]; then exit "$init_status"; fi',
        ),
    ):
        expect_assertion(
            label,
            "install-proof init log capture",
            lambda mutated=first_run.replace(
                active_line, f"# {active_line}", 1
            ): assert_install_proof_init_log_authority(mutated),
        )
    for label, wrapped_init in (
        ("a wrapped second kin init", "(cd sub && kin init)"),
        ("an indirect second admission", '"$KIN" init'),
        ("an evaluated second admission", "eval kin init"),
    ):
        expect_assertion(
            f"{wrapped_init} escapes the exactly-once count",
            "exactly once",
            lambda mutated=f"{first_run}\n          {wrapped_init}\n": (
                assert_install_proof_init_log_authority(mutated)
            ),
        )
    expect_assertion(
        "an unrelated write into the admitted worktree escapes the guard",
        "only the committed Git bootstrap may run",
        lambda: assert_install_proof_init_log_authority(
            first_run.replace(
                '          captures="$RUNNER_TEMP/kin-proof-captures"\n',
                "          echo scratch > proof-note.txt\n"
                '          captures="$RUNNER_TEMP/kin-proof-captures"\n',
                1,
            )
        ),
    )
    expect_assertion(
        "kin's own init status is propagated before init has run",
        "must admit, then propagate",
        lambda: assert_install_proof_init_log_authority(
            first_run.replace(
                '          kin init > "$captures/kin-init.txt" 2>&1 || init_status=$?\n'
                '          cat "$captures/kin-init.txt"\n'
                '          if [ "$init_status" -ne 0 ]; then exit "$init_status"; fi\n',
                '          if [ "$init_status" -ne 0 ]; then exit "$init_status"; fi\n'
                '          kin init > "$captures/kin-init.txt" 2>&1 || init_status=$?\n'
                '          cat "$captures/kin-init.txt"\n',
                1,
            )
        ),
    )

    # The capture contract the init log was the first case of, now covering
    # every report the proof writes while the watcher is admitting.
    proof_steps = {
        "the first-run proof": first_run,
        "the graph query, MCP, and VFS proof": graph_query,
        "the embedding proof": embedding,
    }
    restore_position = (embedding_start, restore_start, validation_start)
    assert_install_proof_captures_stay_out_of_the_admitted_tree(
        proof_steps, restore, restore_position
    )
    for label, step_name, original, mutation in (
        (
            "a first-run capture reverts to a relative redirect",
            "the first-run proof",
            'kin status --json > "$captures/kin-status.json" 2>&1',
            "kin status --json > kin-status.json 2>&1",
        ),
        (
            "a graph-query capture reverts to a relative tee",
            "the graph query, MCP, and VFS proof",
            'kin doctor --json | tee "$captures/kin-doctor.json"',
            "kin doctor --json | tee kin-doctor.json",
        ),
        (
            "a VFS capture reverts to a relative stderr redirect",
            "the graph query, MCP, and VFS proof",
            '2> "$captures/vfs-graph-read.stderr.txt"',
            "2> vfs-graph-read.stderr.txt",
        ),
        (
            "an embedding capture reverts to a relative tee",
            "the embedding proof",
            'kin locate hello --json --explain --max-files 5 | tee "$captures/kin-semantic-locate.json"',
            "kin locate hello --json --explain --max-files 5 | tee kin-semantic-locate.json",
        ),
        (
            "an MCP Node capture reverts to a relative write",
            "the graph query, MCP, and VFS proof",
            'fs.writeFileSync(path.join(captures, "kin-mcp-out.jsonl"), stdout);',
            'fs.writeFileSync("kin-mcp-out.jsonl", stdout);',
        ),
    ):
        expect_assertion(
            label,
            "writes a proof report into the admitted tree",
            lambda mutated_steps={
                **proof_steps,
                step_name: proof_steps[step_name].replace(original, mutation, 1),
            }: assert_install_proof_captures_stay_out_of_the_admitted_tree(
                mutated_steps, restore, restore_position
            ),
        )
    for label, active_line in (
        (
            "the captures never reach the proof reports",
            'cp "$captures/$capture" "$destination/$capture"',
        ),
        (
            "the restore stops listing the capture directory",
            'done < <(ls -1 "$captures")',
        ),
    ):
        expect_assertion(
            label,
            "install-proof capture restore",
            lambda mutated=restore.replace(
                active_line, f"# {active_line}", 1
            ): assert_install_proof_captures_stay_out_of_the_admitted_tree(
                proof_steps, mutated, restore_position
            ),
        )
    expect_assertion(
        "a failed leg stops handing over what it captured",
        "must run on failure too",
        lambda: assert_install_proof_captures_stay_out_of_the_admitted_tree(
            proof_steps, restore.replace("if: always()", "if: success()", 1), restore_position
        ),
    )
    expect_assertion(
        "the captures are restored before the assertions that read the store",
        "after the last step that reads the store",
        lambda: assert_install_proof_captures_stay_out_of_the_admitted_tree(
            proof_steps, restore, (embedding_start, embedding_start - 1, validation_start)
        ),
    )

    assert_install_proof_embedding_settles_before_measurement(embedding)
    for label, expected, original, mutation in (
        (
            "the settle stops requiring a drained embedding pass",
            "poll the counters to quiescence",
            "coverage.pending === 0 &&",
            "coverage.pending >= 0 &&",
        ),
        (
            "the settle stops requiring two agreeing reads",
            "poll the counters to quiescence",
            "drained && current === previous",
            "drained",
        ),
        (
            "an expired settle stops failing the leg",
            "poll the counters to quiescence",
            "process.exit(1);",
            "process.exitCode = 0;",
        ),
        (
            "the store is measured before it has settled",
            "embed, then settle, then capture",
            'PROOF_CAPTURES="$captures" node <<\'NODE\'',
            "kin status --json --wait-quiesce 60 | tee \"$captures/kin-embedded-status.json\"\n"
            "          PROOF_CAPTURES=\"$captures\" node <<'NODE'",
        ),
    ):
        expect_assertion(
            label,
            expected,
            lambda mutated=embedding.replace(
                original, mutation, 1
            ): assert_install_proof_embedding_settles_before_measurement(mutated),
        )
    expect_assertion(
        "the settle becomes a duration nobody measured",
        "rather than on a duration nobody measured",
        lambda: assert_install_proof_embedding_settles_before_measurement(
            embedding.replace(
                '          PROOF_CAPTURES="$captures" node',
                "          sleep 30\n"
                '          PROOF_CAPTURES="$captures" node',
                1,
            )
        ),
    )

    # Native Windows release bytes must admit both supported repository
    # boundaries, leave no transaction residue, and retain the non-empty
    # boundary refusal.
    windows_contract = windows_init_contract_strings()
    windows_admission = install_proof_step(
        install_proof, "Windows admission contract proof"
    )
    assert_install_proof_windows_admission_contract(windows_admission, windows_contract)
    windows_contract_source = WINDOWS_INIT_CONTRACT.read_text(encoding="utf-8")
    assert_windows_contract_stage_check_is_reachable(windows_contract_source)

    # Every shipped copy of the one public native-Windows capability claim.
    windows_public_surfaces = {
        README: readme,
        QUICKSTART_DOC: quickstart,
        WINDOWS_WSL2_DOC: WINDOWS_WSL2_DOC.read_text(encoding="utf-8"),
        UPDATE_TRUST: update_trust,
        NPM_CANONICAL_README: npm_canonical_readme,
        LLMS_DOC: LLMS_DOC.read_text(encoding="utf-8"),
    }
    compatibility_mcp_readme = NPM_MCP_README.read_text(encoding="utf-8")
    assert_windows_public_support_contract(
        windows_contract_source,
        install_ps1,
        windows_public_surfaces,
        compatibility_mcp_readme,
    )
    windows_notice = windows_public_support_notice(install_ps1)
    windows_doc_notice = windows_public_support_doc_notice(windows_notice)

    altered_surfaces = dict(windows_public_surfaces)
    altered_surfaces[README] = readme.replace(
        windows_doc_notice,
        "Native Windows supports the graph and daemon without vectors.",
        1,
    )
    expect_assertion(
        "a shipped surface restates the notice in its own words",
        "exactly once; found 0",
        lambda: assert_windows_public_support_contract(
            windows_contract_source,
            install_ps1,
            altered_surfaces,
            compatibility_mcp_readme,
        ),
    )
    duplicated_surfaces = dict(windows_public_surfaces)
    duplicated_surfaces[README] = readme.replace(
        windows_doc_notice,
        f"{windows_doc_notice}\n{windows_doc_notice}",
        1,
    )
    expect_assertion(
        "a shipped surface carries the notice twice rather than once",
        "exactly once; found 2",
        lambda: assert_windows_public_support_contract(
            windows_contract_source,
            install_ps1,
            duplicated_surfaces,
            compatibility_mcp_readme,
        ),
    )
    for stale_claim in (
        "repository admission is currently unavailable",
        "kin init fails closed",
        "Native Windows cannot admit a Kin repository",
        "it ships the supported vector-free runtime",
    ):
        stale_surfaces = dict(windows_public_surfaces)
        stale_surfaces[LLMS_DOC] = (
            f"{windows_public_surfaces[LLMS_DOC]}\n{stale_claim}\n"
        )
        expect_assertion(
            f"a shipped surface restores the stale claim {stale_claim!r}",
            "found stale claim",
            lambda mutated=stale_surfaces: assert_windows_public_support_contract(
                windows_contract_source,
                install_ps1,
                mutated,
                compatibility_mcp_readme,
            ),
        )
    expect_assertion(
        "the compatibility MCP package restores a refusal-era Windows claim",
        "found stale claim",
        lambda: assert_windows_public_support_contract(
            windows_contract_source,
            install_ps1,
            windows_public_surfaces,
            f"{compatibility_mcp_readme}\nkin init fails closed on native Windows.\n",
        ),
    )
    expect_assertion(
        "the installer binds the public notice twice",
        "must bind $NativeWindowsSupportNotice exactly once",
        lambda: assert_windows_public_support_contract(
            windows_contract_source,
            install_ps1.replace(
                f'$NativeWindowsSupportNotice = "{windows_notice}"',
                f'$NativeWindowsSupportNotice = "{windows_notice}"\n'
                f'$NativeWindowsSupportNotice = "{windows_notice}"',
                1,
            ),
            windows_public_surfaces,
            compatibility_mcp_readme,
        ),
    )
    expect_assertion(
        "the installer repeats the notice outside its one binding",
        "must carry the Windows support notice exactly once",
        lambda: assert_windows_public_support_contract(
            windows_contract_source,
            install_ps1.replace(
                f'$NativeWindowsSupportNotice = "{windows_notice}"',
                f'$NativeWindowsSupportNotice = "{windows_notice}"\n'
                f'Write-Host "{windows_notice}"',
                1,
            ),
            windows_public_surfaces,
            compatibility_mcp_readme,
        ),
    )
    expect_assertion(
        "the public notice drops the admission the contract proves",
        "no longer states the executable admission contract",
        lambda: assert_windows_public_support_contract(
            windows_contract_source,
            install_ps1.replace(
                "Repository admission works:",
                "Repository admission is unavailable:",
                1,
            ),
            windows_public_surfaces,
            compatibility_mcp_readme,
        ),
    )
    expect_assertion(
        "the executable contract reverts to refusing repository admission",
        "tied to executable admission",
        lambda: assert_windows_public_support_contract(
            windows_contract_source.replace(
                'require_admitted "Windows exact-Git admission"',
                'require_refused "Windows exact-Git admission"',
                1,
            ),
            install_ps1,
            windows_public_surfaces,
            compatibility_mcp_readme,
        ),
    )
    expect_assertion(
        "the installer resolves native ARM64 to a release archive",
        "only windows-x86_64 is published",
        lambda: assert_windows_public_support_contract(
            windows_contract_source,
            install_ps1.replace(
                '"ARM64" { throw "No native Windows ARM64 archive is published.',
                '"ARM64" { return "aarch64" }\n        "ARM64_" { throw "x.',
                1,
            ),
            windows_public_surfaces,
            compatibility_mcp_readme,
        ),
    )
    expect_assertion(
        "the installer configures workflows the install proof does not cover",
        "must not configure MCP/review workflows",
        lambda: assert_windows_public_support_contract(
            windows_contract_source,
            install_ps1.replace(
                "# ── Cleanup ",
                "& $KinExe setup\n# ── Cleanup ",
                1,
            ),
            windows_public_surfaces,
            compatibility_mcp_readme,
        ),
    )
    quickstart_drift = dict(windows_public_surfaces)
    quickstart_drift[QUICKSTART_DOC] = quickstart.replace(
        "because the install proof does not yet cover MCP or review workflows there",
        "while admission is unsupported",
        1,
    )
    expect_assertion(
        "the quickstart restores the refusal-era reason for skipping setup",
        "found stale claim",
        lambda: assert_windows_public_support_contract(
            windows_contract_source,
            install_ps1,
            quickstart_drift,
            compatibility_mcp_readme,
        ),
    )

    expect_assertion(
        "the contract script counts stages where one can never appear",
        "reachable Windows stage-leak check",
        lambda: assert_windows_contract_stage_check_is_reachable(
            windows_contract_source.replace(
                'staged="$(count_matching "$parent"',
                'staged="$(count_matching "$dir"',
                1,
            )
        ),
    )
    expect_assertion(
        "the install proof counts stages where one can never appear",
        "shipped Windows admission contract proof",
        lambda: assert_install_proof_windows_admission_contract(
            windows_admission.replace(
                'staged="$(count_matching "$parent"',
                'staged="$(count_matching "$2"',
                1,
            ),
            windows_contract,
        ),
    )
    expect_assertion(
        "the contract script's non-empty refusal wording drifts from the install proof",
        "drifted from",
        lambda: assert_install_proof_windows_admission_contract(
            windows_admission,
            {**windows_contract, "NON_EMPTY_REFUSAL": "requires an empty folder"},
        ),
    )
    for label, active_line in (
        (
            "the non-empty Windows refusal may publish a repository anyway",
            'if [ -e "$2/.kin" ]; then',
        ),
        (
            "a Windows admission may leave its unpublished stage behind",
            "staged=\"$(count_matching \"$parent\" '.kin.init-*')\"",
        ),
        (
            "exact Git stops having to succeed",
            'require_admitted "Windows exact-Git admission" "$git_boundary" "$git_log"',
        ),
        (
            "native-empty bootstrap stops having to succeed",
            'require_admitted "Windows native-unborn bootstrap" "$native_boundary" "$native_log"',
        ),
        (
            "the non-empty boundary stops being refused",
            'require_refused "Windows non-empty native boundary" "$populated_boundary" "$populated_log"',
        ),
        (
            "the non-empty boundary stops naming its safety reason",
            'require_text "$1" "$NON_EMPTY_REFUSAL" "$3"',
        ),
    ):
        expect_assertion(
            label,
            "shipped Windows admission contract proof",
            lambda mutated=windows_admission.replace(
                active_line, f"# {active_line}", 1
            ): assert_install_proof_windows_admission_contract(
                mutated, windows_contract
            ),
        )

    assert_install_proof_repo_steps_cover_windows(install_proof)
    for repo_step in (
        "First-run repository, daemon, and setup proof",
        "Graph query and MCP tool-call proof",
        "Validate installed capability proof",
    ):
        expect_assertion(
            f"the native Windows release proof loses {repo_step}",
            "lost repository coverage",
            lambda mutated=install_proof.replace(
                f"      - name: {repo_step}\n",
                f"      - name: {repo_step}\n        if: runner.os != 'Windows'\n",
                1,
            ): assert_install_proof_repo_steps_cover_windows(mutated),
        )
        expect_assertion(
            f"an alternate Linux-only expression removes {repo_step} from Windows",
            "lost repository coverage",
            lambda mutated=install_proof.replace(
                f"      - name: {repo_step}\n",
                f"      - name: {repo_step}\n        if: runner.os == 'Linux'\n",
                1,
            ): assert_install_proof_repo_steps_cover_windows(mutated),
        )

    for label, original, mutation, expected in (
        (
            "a job-level condition removes the Windows install proof",
            "    name: ${{ matrix.os }}\n",
            "    name: ${{ matrix.os }}\n    if: runner.os != 'Windows'\n",
            "job-level condition",
        ),
        (
            "the install proof stops using its OS matrix runner",
            "    runs-on: ${{ matrix.os }}",
            "    runs-on: ubuntu-latest",
            "reviewed OS matrix",
        ),
        (
            "the Windows matrix row disappears",
            ',{"os":"windows-latest","setup-shell":"powershell"}',
            "",
            "windows-latest row",
        ),
        (
            "a matrix exclusion removes Windows after retaining its include row",
            "        include: ${{ fromJSON(",
            "        exclude:\n          - os: windows-latest\n"
            "        include: ${{ fromJSON(",
            "must not exclude",
        ),
    ):
        if original not in install_proof:
            raise AssertionError(
                f"Windows install-proof falsification lost fixture for {label}: {original}"
            )
        expect_assertion(
            label,
            expected,
            lambda mutated=install_proof.replace(original, mutation, 1): (
                assert_install_proof_repo_steps_cover_windows(mutated)
            ),
        )

    assert_install_proof_every_leg_gates_the_release(install_proof)
    for label, original, mutation, expected in (
        (
            "the Windows waiver returns as a matrix flag",
            '{"os":"windows-latest","setup-shell":"powershell"}',
            '{"os":"windows-latest","setup-shell":"powershell","experimental":true}',
            "admit no experimental",
        ),
        (
            "the waiver returns on a Unix row instead",
            '{"os":"ubuntu-latest","setup-shell":"bash"}',
            '{"os":"ubuntu-latest","setup-shell":"bash","experimental":true}',
            "admit no experimental",
        ),
        (
            "the install proof tolerates every leg unconditionally",
            "    strategy:\n",
            "    continue-on-error: true\n    strategy:\n",
            "no job-level continue-on-error",
        ),
        (
            "the matrix-guard spelling of the waiver returns",
            "    strategy:\n",
            "    continue-on-error: ${{ matrix.experimental == true }}\n    strategy:\n",
            "no job-level continue-on-error",
        ),
        (
            "a step-level tolerance spares every leg below the job header",
            "      - name: Public install (Unix)\n",
            "      - name: Public install (Unix)\n"
            "        continue-on-error: true\n",
            "no continue-on-error at all",
        ),
        (
            "a quoted-key tolerance hides on a step",
            "      - name: Public install (Unix)\n",
            "      - name: Public install (Unix)\n"
            "        \"continue-on-error\": true\n",
            "no continue-on-error at all",
        ),
        (
            "a reviewed platform is dropped from the gating matrix",
            ',{"os":"macos-15-intel","setup-shell":"zsh"}',
            "",
            "must gate exactly",
        ),
    ):
        if original not in install_proof:
            raise AssertionError(
                "install-proof gating posture falsification lost fixture for "
                f"{label}: {original!r}"
            )
        expect_assertion(
            label,
            expected,
            lambda mutated=install_proof.replace(original, mutation, 1): (
                assert_install_proof_every_leg_gates_the_release(mutated)
            ),
        )

    assert_install_proof_runs_on_pull_requests(ci_workflow, install_proof)
    pull_request_gate = workflow_job_blocks(ci_workflow)["install-proof-pr-gate"]
    for label, source, original, mutation, expected in (
        (
            "the pull-request install proof gate is deleted outright",
            ci_workflow,
            pull_request_gate,
            "",
            "CI lost",
        ),
        (
            "the pull-request proof calls a lookalike workflow",
            ci_workflow,
            "uses: ./.github/workflows/install-proof.yml",
            "uses: ./.github/workflows/daemon-smoke.yml",
            "reviewed reusable",
        ),
        (
            "the pull-request proof installs a released archive instead",
            ci_workflow,
            f"      local_artifact: {INSTALL_PROOF_PULL_REQUEST_ARTIFACT}\n",
            '      local_artifact: ""\n',
            "reviewed reusable",
        ),
        (
            "the built binaries are uploaded under another name",
            ci_workflow,
            f"          name: {INSTALL_PROOF_PULL_REQUEST_ARTIFACT}\n",
            "          name: install-proof-pr-other\n",
            "built by this pull request",
        ),
        (
            "the proof stops building the release target",
            ci_workflow,
            "--target x86_64-unknown-linux-musl -p kin-cli -p kin-daemon",
            "-p kin-cli -p kin-daemon",
            "built by this pull request",
        ),
        (
            "the archive is no longer judged by the release shape contract",
            ci_workflow,
            "            assertReleaseArchiveMemberPaths(listing, {\n",
            "            void listing && ((_) => {})({\n",
            "built by this pull request",
        ),
        (
            "the proof is moved off the pull request the way a slow leg was",
            ci_workflow,
            "  install-proof-pr-gate:\n    name: Install Proof (PR) Gate\n",
            "  install-proof-pr-gate:\n    name: Install Proof (PR) Gate\n"
            "    if: ${{ github.event_name != 'pull_request' }}\n",
            "must not exclude an event",
        ),
        (
            "the gate stops failing on a proof that did not pass",
            ci_workflow,
            '          if [ "$PROOF_RESULT" != "success" ]; then\n',
            '          if false; then\n',
            "fail closed",
        ),
        (
            "the semantic retrieval proof becomes release-only",
            install_proof,
            "      - name: Unix embedding and semantic retrieval proof\n"
            "        if: runner.os != 'Windows'\n",
            "      - name: Unix embedding and semantic retrieval proof\n"
            "        if: runner.os != 'Windows' && inputs.local_artifact == ''\n",
            "exactly the Unix condition",
        ),
        (
            "the locate capture the validator reads disappears",
            install_proof,
            '          kin locate hello --json --explain --max-files 5 '
            '| tee "$captures/kin-semantic-locate.json"\n',
            "",
            "lost the locate capture",
        ),
    ):
        if original not in source:
            raise AssertionError(
                "pull-request install proof falsification lost fixture for "
                f"{label}: {original!r}"
            )
        mutated_ci = ci_workflow
        mutated_proof = install_proof
        if source is ci_workflow:
            mutated_ci = ci_workflow.replace(original, mutation, 1)
        else:
            mutated_proof = install_proof.replace(original, mutation, 1)
        expect_assertion(
            label,
            expected,
            lambda ci=mutated_ci, proof=mutated_proof: (
                assert_install_proof_runs_on_pull_requests(ci, proof)
            ),
        )

    repo_free = install_proof_step(
        install_proof, "Windows repo-free provenance and setup proof"
    )
    assert_install_proof_repo_free_windows_proof(repo_free)
    assert_node_validator_rejects_missing_proof(
        repo_free, "repo-free Windows install proof"
    )
    assert_windows_node_validator_behavior(repo_free)
    selective_windows_required_bypass = replace_exactly_once(
        repo_free,
        "          if (actual !== expected) {\n",
        '          if (id !== "kin_binary" && actual !== expected) {\n',
        "Windows selective required-check bypass",
    )
    expect_assertion(
        "the Windows validator selectively skips the kin_binary requirement",
        "accepted a behaviorally invalid proof fixture",
        lambda: assert_windows_node_validator_behavior(
            selective_windows_required_bypass
        ),
    )
    windows_mcp_only_claude = replace_exactly_once(
        repo_free,
        "          for (const configPath of jsonConfigs) {\n",
        "          for (const configPath of jsonConfigs.slice(0, 1)) {\n",
        "Windows selective MCP-config bypass",
    )
    expect_assertion(
        "the Windows validator checks MCP values only in Claude's config",
        "accepted a behaviorally invalid proof fixture",
        lambda: assert_windows_node_validator_behavior(windows_mcp_only_claude),
    )
    blocked_repo_free = repo_free.replace(
        '          const fs = require("fs");\n',
        '          /*\n          const fs = require("fs");\n',
        1,
    ).replace('          NODE\n', '          */\n          NODE\n', 1)
    expect_assertion(
        "a JavaScript block comment disables the entire Windows validator",
        "repo-free Windows install proof",
        lambda: assert_install_proof_repo_free_windows_proof(blocked_repo_free),
    )
    false_branch_repo_free = repo_free.replace(
        '          const fs = require("fs");\n',
        '          if (false) {\n          const fs = require("fs");\n',
        1,
    ).replace('          NODE\n', '          }\n          NODE\n', 1)
    expect_assertion(
        "a false branch disables the entire Windows validator",
        "validator is not runtime-falsifiable",
        lambda: assert_node_validator_rejects_missing_proof(
            false_branch_repo_free, "repo-free Windows install proof"
        ),
    )
    partial_false_branch_repo_free = repo_free.replace(
        '          const expectedCommit = fs.readFileSync("expected-commit.txt", "utf8").trim();\n',
        '          const expectedCommit = fs.readFileSync("expected-commit.txt", "utf8").trim();\n'
        '          if (false) {\n',
        1,
    ).replace('          NODE\n', '          }\n          NODE\n', 1)
    expect_assertion(
        "a false branch after expected-commit disables the substantive Windows validator",
        "accepted an expected-commit-only proof tree",
        lambda: assert_node_validator_rejects_missing_proof(
            partial_false_branch_repo_free, "repo-free Windows install proof"
        ),
    )
    for label, original, mutation in (
        (
            "the Windows leg stops binding installed provenance to the release tag",
            "meta.kin_commit !== expectedCommit",
            'meta.kin_commit !== "0000000000000000000000000000000000000000"',
        ),
        (
            "the Windows leg stops proving the release Cargo.lock provenance",
            "meta.dependency_provenance !== expectedLock",
            'meta.dependency_provenance !== ""',
        ),
        (
            "the Windows leg stops proving its vector feature contract",
            "meta.embeddings?.vector_enabled !== true",
            "meta.embeddings?.vector_enabled !== false",
        ),
        (
            "the Windows registry-authority repair negative control disappears",
            "if kin registry authority --fix > kin-windows-registry-fix.txt 2>&1; then",
            "if false; then",
        ),
        (
            "the repo-free posture stops requiring the no-repository answer",
            '["repo_init", "unsupported"]',
            '["repo_init", "healthy"]',
        ),
        (
            "the repo-free posture stops proving the agent-client MCP writers",
            '["mcp_client_windsurf", "healthy"]',
            "",
        ),
        (
            "a repo-free posture pin is commented out in the heredoc it lives in",
            '["repo_init", "unsupported"]',
            '// ["repo_init", "unsupported"]',
        ),
    ):
        expect_assertion(
            label,
            "repo-free Windows install proof",
            lambda mutated=repo_free.replace(
                original, mutation, 1
            ): assert_install_proof_repo_free_windows_proof(mutated),
        )
    assert_install_proof_status_contract(first_run, graph_query, embedding, validation)
    assert_node_validator_rejects_missing_proof(
        validation, "released-byte Unix install proof"
    )
    assert_unix_node_validator_behavior(validation)
    selective_unix_required_bypass = replace_exactly_once(
        validation,
        "          if (actual !== expected) {\n",
        '          if (id !== "kin_binary" && actual !== expected) {\n',
        "Unix selective required-check bypass",
    )
    expect_assertion(
        "the Unix validator selectively skips the kin_binary requirement",
        "accepted a behaviorally invalid proof fixture",
        lambda: assert_unix_node_validator_behavior(selective_unix_required_bypass),
    )
    unix_mcp_only_claude = replace_exactly_once(
        validation,
        "          for (const expected of mcpConfigs) {\n",
        "          for (const expected of mcpConfigs.slice(0, 1)) {\n",
        "Unix selective MCP-config bypass",
    )
    expect_assertion(
        "the Unix validator checks MCP values only in Claude's config",
        "accepted a behaviorally invalid proof fixture",
        lambda: assert_unix_node_validator_behavior(unix_mcp_only_claude),
    )
    unix_full_sha_bypass = replace_exactly_once(
        validation,
        '          if (!fullSha.test(build.sha ?? "")) {\n',
        '          if (false && !fullSha.test(build.sha ?? "")) {\n',
        "Unix full-commit-SHA bypass",
    )
    expect_assertion(
        "the Unix validator disables the full commit SHA comparison",
        "accepted a behaviorally invalid proof fixture",
        lambda: assert_unix_node_validator_behavior(unix_full_sha_bypass),
    )
    unix_lock_sha_bypass = replace_exactly_once(
        validation,
        '          if (!lockSha.test(build.dependencyProvenance ?? "")) {\n',
        '          if (false && !lockSha.test(build.dependencyProvenance ?? "")) {\n',
        "Unix lock-SHA bypass",
    )
    expect_assertion(
        "the Unix validator disables the lock SHA comparison",
        "accepted a behaviorally invalid proof fixture",
        lambda: assert_unix_node_validator_behavior(unix_lock_sha_bypass),
    )
    blocked_validation = validation.replace(
        '          const fs = require("fs");\n',
        '          /*\n          const fs = require("fs");\n',
        1,
    ).replace('          NODE\n', '          */\n          NODE\n', 1)
    expect_assertion(
        "a JavaScript block comment disables the entire Unix validator",
        "released-byte status and build proof contract",
        lambda: assert_install_proof_status_contract(
            first_run,
            graph_query,
            embedding,
            blocked_validation,
        ),
    )
    false_branch_validation = validation.replace(
        '          const fs = require("fs");\n',
        '          if (false) {\n          const fs = require("fs");\n',
        1,
    ).replace('          NODE\n', '          }\n          NODE\n', 1)
    expect_assertion(
        "a false branch disables the entire Unix validator",
        "validator is not runtime-falsifiable",
        lambda: assert_node_validator_rejects_missing_proof(
            false_branch_validation, "released-byte Unix install proof"
        ),
    )
    partial_false_branch_validation = validation.replace(
        '          const expectedCommit = fs.readFileSync("../expected-commit.txt", "utf8").trim();\n',
        '          const expectedCommit = fs.readFileSync("../expected-commit.txt", "utf8").trim();\n'
        '          if (false) {\n',
        1,
    ).replace('          NODE\n', '          }\n          NODE\n', 1)
    expect_assertion(
        "a false branch after expected-commit disables the substantive Unix validator",
        "accepted an expected-commit-only proof tree",
        lambda: assert_node_validator_rejects_missing_proof(
            partial_false_branch_validation, "released-byte Unix install proof"
        ),
    )
    expect_assertion(
        "install proof stops capturing CLI build metadata",
        "installed CLI provenance capture",
        lambda: assert_install_proof_status_contract(
            first_run.replace(
                'kin bench-meta --json > "$captures/kin-build-meta.json"',
                'kin --version > "$captures/kin-build-meta.json"',
                1,
            ),
            graph_query,
            embedding,
            validation,
        ),
    )
    expect_assertion(
        "install proof reads daemon endpoint before a daemon-starting query",
        "must start the daemon through a graph query",
        lambda: assert_install_proof_status_contract(
            first_run,
            graph_query.replace(
                'kin search hello --json > "$captures/kin-search.json"',
                "# graph query moved below daemon provenance capture",
                1,
            ).replace(
                'cat "$captures/kin-daemon-health.json"',
                'cat "$captures/kin-daemon-health.json"\n          kin search hello --json > "$captures/kin-search.json"',
                1,
            ),
            embedding,
            validation,
        ),
    )
    expect_assertion(
        "a commented-out daemon-starting query cannot satisfy the proof contract",
        "installed daemon startup and health capture",
        lambda: assert_install_proof_status_contract(
            first_run,
            graph_query.replace(
                'kin search hello --json > "$captures/kin-search.json"',
                '# kin search hello --json > "$captures/kin-search.json"',
                1,
            ),
            embedding,
            validation,
        ),
    )
    expect_assertion(
        "a daemon-starting query is piped again",
        "must redirect a daemon-starting query rather than pipe it",
        lambda: assert_install_proof_status_contract(
            first_run,
            graph_query.replace(
                'kin search hello --json > "$captures/kin-search.json"\n'
                '          cat "$captures/kin-search.json"',
                'kin search hello --json | tee "$captures/kin-search.json"',
                1,
            ),
            embedding,
            validation,
        ),
    )
    expect_assertion(
        "the second daemon-starting query is piped again",
        "must redirect a daemon-starting query rather than pipe it",
        lambda: assert_install_proof_status_contract(
            first_run,
            graph_query.replace(
                "kin locate hello --json --explain --max-files 5 > "
                '"$captures/kin-locate.json"\n'
                '          cat "$captures/kin-locate.json"',
                "kin locate hello --json --explain --max-files 5 | tee "
                '"$captures/kin-locate.json"',
                1,
            ),
            embedding,
            validation,
        ),
    )
    expect_assertion(
        "setup health is captured before the daemon-starting query",
        "must start the daemon through a graph query",
        lambda: assert_install_proof_status_contract(
            first_run,
            graph_query.replace(
                'kin setup status --json | tee "$captures/kin-health.json"',
                "# setup health moved above daemon startup",
                1,
            )
            .replace(
                'kin doctor --json | tee "$captures/kin-doctor.json"',
                "# doctor health moved above daemon startup",
                1,
            )
            .replace(
                'kin search hello --json > "$captures/kin-search.json"',
                'kin setup status --json | tee "$captures/kin-health.json"\n'
                '          kin doctor --json | tee "$captures/kin-doctor.json"\n'
                '          kin search hello --json > "$captures/kin-search.json"',
                1,
            ),
            embedding,
            validation,
        ),
    )
    expect_assertion(
        "install proof reads build provenance from repository status again",
        "does not emit: status.build",
        lambda: assert_install_proof_status_contract(
            first_run,
            graph_query,
            embedding,
            validation.replace("const builds = new Map([", "const stale = status.build;\n          const builds = new Map([", 1),
        ),
    )
    expect_assertion(
        "install proof accepts the pre-coverage status schema",
        "released-byte status and build proof contract",
        lambda: assert_install_proof_status_contract(
            first_run,
            graph_query,
            embedding,
            validation.replace("kin.status.v3", "kin.status.v2"),
        ),
    )
    expect_assertion(
        "install proof reads locate coverage from repository status again",
        "does not emit: status.semantic_coverage",
        lambda: assert_install_proof_status_contract(
            first_run,
            graph_query,
            embedding,
            validation.replace(
                "status.embedding_coverage",
                "status.semantic_coverage",
                1,
            ),
        ),
    )
    for policy in (
        "PROOF_SHELL: ${{ matrix.setup-shell }}",
        'case "$PROOF_SHELL" in',
        "unset PSModulePath PSVersionTable",
        "export SHELL=/bin/bash",
        "export SHELL=/bin/zsh",
    ):
        require(embedding, policy, "embedded-health shell reset")
    # A health failure has to name the rows it failed on. It used to name every
    # row that was not `healthy`, which on a fresh Windows install is 21 rows of
    # which 19 are `unsupported` and irrelevant, so the message buried its own
    # cause. These needles are the replacement: the rows that were NOT tolerated
    # first, then the verdict, then the full attention list (FIR-2919).
    for policy in (
        "rows needing attention that a fresh repo-free install does not expect:",
        "rows needing attention that a fresh install does not expect:",
        "verdict=${report.verdict}",
        "every row needing attention: ${attentionRows(report)}",
    ):
        require(install_proof, policy, "actionable install-proof health failure")
    require(
        install_proof,
        "manifest.schema_version === 2",
        "aggregate release-provenance schema accepted by install proof",
    )
    require(
        install_proof,
        '["mcp_client_codex", "healthy"]',
        "repo-bound Codex MCP install proof",
    )
    for policy in (
        'fs.writeFileSync("installed-kin-command.txt", `${installedKin}\\n`)',
        "execFileSync(installedKin, [\"--version\"]",
        "for agent in claude cursor codex gemini windsurf agy; do",
        "spawn(entry.command, entry.args",
    ):
        require(install_proof, policy, "installed MCP executable and writer proof")
    for policy in (
        "evaluate_mcp_client(&client.path, client.id)",
        "McpLauncherTopology::Native",
        "McpLauncherTopology::CanonicalNpm",
        "CANONICAL_NPM_MCP_COMMAND",
        "CANONICAL_NPM_MCP_PACKAGE",
        "mcp_argument_vector_matches(entry, client_id, topology)",
        '"codex" | "antigravity" | "antigravity_workspace"',
        "configured_mcp_launcher()",
    ):
        require(health, policy, "product-owned exact MCP entry health validation")
    require(
        health,
        "evaluate_codex_binding(&client.path)",
        "product-owned Codex MCP binding validation",
    )
    require(
        health,
        "super::setup::codex_entry_has_exact_repo_binding(&content, expected_repo)",
        "shared TOML parser for Codex MCP binding validation",
    )
    for policy in (
        "CANONICAL_NPM_MCP_PACKAGE",
        'args[0].as_str() == Some("-y")',
        'args[2].as_str() == Some("mcp")',
        'args[4].as_str() == Some("--repo")',
    ):
        require(setup, policy, "canonical npm Codex repository binding")

    ordinary_repair_start = setup.index(
        "pub(crate) fn remerge_existing_mcp_configs_detailed()"
    )
    ordinary_repair_end = setup.index(
        "#[cfg(all(test, unix))]", ordinary_repair_start
    )
    ordinary_repair = setup[ordinary_repair_start:ordinary_repair_end]
    require(
        ordinary_repair,
        "configured_mcp_launcher",
        "doctor repair uses the configured installation launcher",
    )
    updater_repair_start = setup.index(
        "pub(crate) fn remerge_mcp_targets_exact_with_topology_and_finalizer"
    )
    updater_repair_end = setup.index(
        "fn validate_mcp_repair_precondition", updater_repair_start
    )
    updater_repair = setup[updater_repair_start:updater_repair_end]
    require(
        updater_repair,
        "let command = managed_mcp_launcher()?;",
        "updater repair stays pinned to the managed launcher",
    )
    if "configured_mcp_launcher" in updater_repair:
        raise AssertionError(
            "updater MCP repair must not accept the ordinary configured launcher resolver"
        )

    for path, source in (
        (QUICKSTART_DOC, quickstart),
        (MCP_TOOLS_DOC, mcp_tools),
        (NPM_CANONICAL_README, npm_canonical_readme),
    ):
        if '"command": "kin"' in "\n".join(active_lines(source)):
            raise AssertionError(
                f"{path.relative_to(ROOT)} must not document a PATH-dependent bare Kin MCP launcher"
            )
    for source, label in (
        (quickstart, "quickstart canonical npm MCP launcher"),
        (npm_canonical_readme, "canonical npm package MCP launcher"),
    ):
        require(source, '"command": "npx"', label)
        require(
            source,
            '"args": ["-y", "@kinlab/kin", "mcp", "start"]',
            label,
        )
    for source, label in (
        (quickstart, "quickstart native MCP launcher"),
        (mcp_tools, "MCP tools native launcher"),
    ):
        require(source, '"command": "/absolute/path/to/kin"', label)
    if "JSON.parse(codexArgsMatch[1])" in install_proof:
        raise AssertionError(
            "install proof must not parse TOML as JSON; the product health check owns Codex binding validation"
        )

    for policy in (
        "Graph-backed VFS projection proof",
        'probe_bin="$RUNNER_TEMP/vfs-open-probe"',
        "fstat(STDOUT_FILENO, &stdout_stat)",
        "chmod 000 probe.py",
        "KIN_VFS_STRICT=1 kin-vfs exec --workspace .",
        'cmp -s "$captures/vfs-expected.txt" "$captures/vfs-graph-read.txt"',
        "installed VFS did not return the exact graph-owned probe.py bytes",
        "release-provenance-attestation.json",
        "installed-vfs-provenance.json",
        "installed ${component.name} differs from the attested public archive",
        '--signer-digest "$expected_commit"',
        'if [ "$negative_status" -ne 4 ]',
        "negative control did not fail with the expected raw-disk permission error",
        "installed kin-vfs socket remained after shutdown",
        'process_state="$(ps -o stat= -p "$vfs_pid" 2>/dev/null || true)"',
        "process_state=\"$(printf '%s' \"$process_state\" | tr -d '[:space:]')\"",
        "trap 'on_vfs_signal 130' INT",
        "trap 'on_vfs_signal 143' TERM",
    ):
        require(install_proof, policy, "public VFS and installed-artifact proof")
    cleanup_start = install_proof.index("          cleanup_vfs() {")
    signal_start = install_proof.index("          on_vfs_signal() {", cleanup_start)
    cleanup_vfs = install_proof[cleanup_start:signal_start]
    require(cleanup_vfs, 'vfs_pid=""', "idempotent public VFS cleanup")
    if 'ps -o stat= -p "$vfs_pid" 2>/dev/null | tr' in cleanup_vfs:
        raise AssertionError(
            "public VFS cleanup must treat a disappeared daemon PID as the "
            "expected successful-stop state under set -euo pipefail"
        )
    require(
        install_proof,
        "          trap - EXIT\n          cleanup_vfs\n          trap - INT TERM",
        "non-reentrant public VFS normal cleanup",
    )
    if "kin-vfs-open-probe" in install_proof:
        raise AssertionError(
            "public VFS probe must not use a Kin-family basename; the shipped "
            "shim intentionally bypasses basenames beginning with 'kin-'"
        )
    proof_upload = install_proof[
        install_proof.index("- name: Preserve proof reports") :
    ]
    for report in (
        "release-provenance.json",
        "release-provenance.json.sha256",
        "release-provenance-attestation.json",
        "installed-vfs-provenance.json",
        # The Windows leg's whole evidence trail. Its admission logs are the
        # only record of what each refusal actually said, and the v0.4.5
        # incident was diagnosed from exactly this kind of uploaded log.
        "kin-windows-bench-meta.json",
        "kin-windows-registry-authority.json",
        "kin-windows-registry-fix.txt",
        "kin-windows-setup.txt",
        "kin-windows-health.json",
        "kin-windows-doctor.json",
        "kin-windows-admission/*.txt",
    ):
        require(proof_upload, report, "preserved installed-artifact proof report")

    vfs_checkout_count = len(
        re.findall(r"repository:\s*firelock-ai/kin-vfs\s*$", release, re.MULTILINE)
    )
    vfs_checkout_refs = re.findall(
        r"repository:\s*firelock-ai/kin-vfs\s*$"
        r"(?:(?!^\s+- name:).)*?^\s+ref:\s*([^\s#]+)",
        release,
        re.MULTILINE | re.DOTALL,
    )
    if len(vfs_checkout_refs) != vfs_checkout_count or any(
        re.fullmatch(r"[0-9a-f]{40}", ref) is None for ref in vfs_checkout_refs
    ):
        raise AssertionError(
            "every kin-vfs release checkout must declare a full immutable commit; "
            f"checkouts={vfs_checkout_count}, refs={vfs_checkout_refs}"
        )
    vfs_refs = set(vfs_checkout_refs)
    vfs_expected = set(re.findall(r"EXPECTED_VFS_COMMIT:\s*([0-9a-f]{40})", release))
    install_proof_vfs_expected = set(
        re.findall(r"expected_vfs_commit:\s*([0-9a-f]{40})", release)
    )
    if len(vfs_refs) != 1 or vfs_expected != vfs_refs:
        raise AssertionError(
            "release workflow must use one immutable kin-vfs commit for build "
            f"and provenance verification; refs={sorted(vfs_refs)}, "
            f"expected={sorted(vfs_expected)}"
        )
    if install_proof_vfs_expected != vfs_refs:
        raise AssertionError(
            "install proof must bind the same immutable kin-vfs commit as the "
            f"release workflow; release={sorted(vfs_refs)}, "
            f"install-proof={sorted(install_proof_vfs_expected)}"
        )
    for policy in (
        "Verified Kin/kin-vfs release compatibility at kin-vfs-core",
        'pkg.name === "kin-vfs-core" && pkg.source?.startsWith("sparse+")',
        'pkg.name === "kin-vfs-core" && pkg.source === null',
        "update the immutable kin-vfs pin",
    ):
        require(release, policy, "Kin and pinned kin-vfs release compatibility gate")

    # What Windows admission does is stated once and asserted from one script.
    # The installer leg proves it on the landing push, which is the commit
    # release proof reads. The authority job proves the same assertions against
    # the same command on every pull request and merge group, which is the only
    # place an admission change is still reviewable. Pin both invocations and
    # the assertions themselves: dropping the pull-request half restores a
    # behavior change no one can see until it fails a required check on a
    # release commit, and letting the two legs carry their own copies restores
    # the drift that made the copies disagree.
    #
    # Exact Git and native-empty admission are supported. The contract pins
    # both successes, zero transaction residue, and the retained non-empty
    # boundary refusal.
    windows_admission = (ROOT / "scripts" / "assert-windows-init-contract.sh").read_text(
        encoding="utf-8"
    )
    for policy in (
        '"$kin_bin" init',
        'NON_EMPTY_REFUSAL="requires an empty directory"',
        'require_admitted "Windows exact-Git admission" "$git_boundary" "$git_log"',
        'require_admitted "Windows native-unborn bootstrap" "$native_boundary" "$native_log"',
        'require_non_empty_refused',
        'if [ ! -d "$dir/.kin" ]; then',
        'fail "$label unexpectedly succeeded" "$log"',
        'if [ -e "$dir/.kin" ]; then',
        'if [ "$staged" != "0" ]; then',
        "'.kin.init-*'",
    ):
        require(windows_admission, policy, "Windows admission contract assertions")

    ci_jobs = workflow_job_blocks(ci_workflow)
    windows_npm_proof = WINDOWS_NPM_PROOF.read_text(encoding="utf-8")
    assert_windows_npm_first_run_proof(
        ci_jobs["windows-authority-tests"], windows_npm_proof
    )
    assert_windows_daemon_sibling_build(ci_jobs["windows-authority-runtime-tests"])
    windows_job = ci_jobs["windows-authority-runtime-tests"]
    sibling_build_start = windows_job.index(WINDOWS_DAEMON_SIBLING_BUILD)
    sibling_build_end = windows_job.index(
        "      - name: Compile and run native Windows runtime authority tests"
    )
    sibling_build_block = windows_job[sibling_build_start:sibling_build_end]
    for label, mutated_job, expected in (
        (
            "the Windows leg stops building the daemon its lifecycle test drives",
            windows_job.replace(sibling_build_block, "", 1),
            "native Windows daemon lifecycle prerequisite",
        ),
        (
            "the sibling daemon build drifts back after the tests that read it",
            windows_job.replace(sibling_build_block, "", 1) + sibling_build_block,
            "before the lifecycle test reads it",
        ),
    ):
        expect_assertion(
            label,
            expected,
            lambda mutated_job=mutated_job: assert_windows_daemon_sibling_build(
                mutated_job
            ),
        )
    canonical_npm_provision = CANONICAL_NPM_PROVISION.read_text(encoding="utf-8")
    canonical_npm_provision_test = CANONICAL_NPM_PROVISION_TEST.read_text(
        encoding="utf-8"
    )
    compat_npm_provision = COMPAT_NPM_PROVISION.read_text(encoding="utf-8")
    compat_npm_provision_test = COMPAT_NPM_PROVISION_TEST.read_text(
        encoding="utf-8"
    )
    assert_windows_npm_archive_authority(
        canonical_npm_provision,
        canonical_npm_provision_test,
        compat_npm_provision,
        compat_npm_provision_test,
    )
    for label, canonical_source, canonical_test, compat_source, compat_test, expected in (
        (
            "canonical npm Windows extraction falls back to PATH tar",
            canonical_npm_provision.replace(
                "path.win32.join(systemRoot, 'System32', 'tar.exe')", "'tar'", 1
            ),
            canonical_npm_provision_test,
            compat_npm_provision,
            compat_npm_provision_test,
            "absolute System32 extraction authority",
        ),
        (
            "compatibility npm Windows extraction falls back to PATH tar",
            canonical_npm_provision,
            canonical_npm_provision_test,
            compat_npm_provision.replace(
                "path.win32.join(systemRoot, 'System32', 'tar.exe')", "'tar'", 1
            ),
            compat_npm_provision_test,
            "absolute System32 extraction authority",
        ),
        (
            "canonical npm Windows fixture stops proving real ZIP bytes",
            canonical_npm_provision,
            canonical_npm_provision_test.replace("'504b0304'", "'00000000'", 1),
            compat_npm_provision,
            compat_npm_provision_test,
            "genuine Windows ZIP regression",
        ),
        (
            "compatibility npm Windows fixture stops proving real ZIP bytes",
            canonical_npm_provision,
            canonical_npm_provision_test,
            compat_npm_provision,
            compat_npm_provision_test.replace("'504b0304'", "'00000000'", 1),
            "genuine Windows ZIP regression",
        ),
        (
            "canonical npm ZIP proof loses its hostile PATH",
            canonical_npm_provision,
            canonical_npm_provision_test.replace(
                "env.PATH = [hostileBin, originalPath]",
                "env.PATH = originalPath",
                1,
            ),
            compat_npm_provision,
            compat_npm_provision_test,
            "genuine Windows ZIP regression",
        ),
        (
            "compatibility npm ZIP proof loses its hostile PATH",
            canonical_npm_provision,
            canonical_npm_provision_test,
            compat_npm_provision,
            compat_npm_provision_test.replace(
                "env.PATH = [hostileBin, originalPath]",
                "env.PATH = originalPath",
                1,
            ),
            "genuine Windows ZIP regression",
        ),
    ):
        expect_assertion(
            label,
            expected,
            lambda canonical_source=canonical_source,
            canonical_test=canonical_test,
            compat_source=compat_source,
            compat_test=compat_test: assert_windows_npm_archive_authority(
                canonical_source,
                canonical_test,
                compat_source,
                compat_test,
            ),
        )
    for label, mutated_job, mutated_proof, expected in (
        (
            "canonical npm tests disappear from native Windows",
            ci_jobs["windows-authority-tests"].replace(
                "          npm test --prefix ./packages/kin\n", "", 1
            ),
            windows_npm_proof,
            "native Windows npm first-run CI proof",
        ),
        (
            "MCP sibling daemon discovery is compiled but never executed on Windows",
            ci_jobs["windows-authority-tests"].replace(
                "          run_required_exact \"MCP Windows sibling daemon discovery\" \\\n"
                "            \"daemon_delegate::tests::windows_daemon_discovery_finds_platform_sibling_without_path\" \\\n"
                "            --locked --target x86_64-pc-windows-msvc \\\n"
                "            -p kin-mcp --no-default-features --lib\n",
                "",
                1,
            ),
            windows_npm_proof,
            "native Windows npm first-run CI proof",
        ),
        (
            "canonical runtime regains a KIN_DAEMON_BIN rescue",
            ci_jobs["windows-authority-tests"],
            windows_npm_proof.replace(
                "  deleteEnv(env, 'KIN_DAEMON_BIN');\n"
                "  assert.equal(readEnv(env, 'KIN_DAEMON_BIN'), undefined);\n"
                "  assertPathExcludes(env, path.dirname(managedKin), '@kinlab/kin');\n",
                "  setEnv(env, 'KIN_DAEMON_BIN', managedDaemon);\n"
                "  assertPathExcludes(env, path.dirname(managedKin), '@kinlab/kin');\n",
                1,
            ),
            "must not inject KIN_DAEMON_BIN",
        ),
        (
            "canonical runtime stops proving daemon-backed status",
            ci_jobs["windows-authority-tests"],
            windows_npm_proof.replace(
                "[canonicalKinLauncher, 'status', '--json']",
                "[canonicalKinLauncher, '--version']",
                1,
            ),
            "native Windows npm first-run harness",
        ),
        (
            "compatibility wrapper is inferred from the canonical MCP entrypoint",
            ci_jobs["windows-authority-tests"],
            windows_npm_proof.replace(
                "launcher: compatibilityMcpLauncher",
                "launcher: canonicalMcpLauncher",
                1,
            ),
            "native Windows npm first-run harness",
        ),
    ):
        expect_assertion(
            label,
            expected,
            lambda mutated_job=mutated_job, mutated_proof=mutated_proof: (
                assert_windows_npm_first_run_proof(mutated_job, mutated_proof)
            ),
        )
    for job_id in ("windows-authority-tests", "windows-installer"):
        for policy in (
            "- name: Assert the Windows admission contract",
            "bash ./scripts/assert-windows-init-contract.sh",
        ):
            require(ci_jobs[job_id], policy, f"shared Windows admission proof in {job_id}")
        if ci_jobs[job_id].count("run: ./scripts/test-install-checksum.ps1") != 2:
            raise AssertionError(
                f"{job_id} must execute the installer warning/checksum contract "
                "once under PowerShell 7 and once under Windows PowerShell 5.1"
            )
        for shell in ("shell: pwsh", "shell: powershell"):
            require(
                ci_jobs[job_id],
                shell,
                f"dual-engine Windows installer authority in {job_id}",
            )
    # The Windows arm of the config writer shares no code with the Unix one, so
    # a leg that never runs its cases proves nothing about the transaction
    # `kin init` depends on.
    require(
        ci_jobs["windows-authority-tests"],
        "config::capability_owned_config_replacement_tests",
        "native Windows config replacement proof",
    )
    # The retained directory handle's exclusion is a Windows sharing-rule
    # property. The module doc claims it, so the leg has to keep proving it, or
    # the claim reverts to an assertion nobody checks.
    require(
        ci_jobs["windows-authority-tests"],
        "config::windows::capability_exclusion_tests",
        "native retained-capability exclusion proof",
    )
    # `kin init` is what the admission script drives, and it lives two steps
    # later behind a build. When it refuses, the script reports one line naming
    # a path that both the config writer and the metadata seal report against,
    # so the end-to-end leg cannot say which component refused. Running
    # admission in process here names a test instead. This is required rather
    # than merely present because `init.rs` carried no native Windows coverage
    # at all until it was added, which is how a refusal in it stayed unlocated
    # across repeated attempts.
    require(
        ci_jobs["windows-authority-tests"],
        "init::tests",
        "native repository initialization proof",
    )
    require(
        ci_jobs["windows-authority-tests"],
        "target/x86_64-pc-windows-msvc/debug/kin.exe",
        "pull-request Windows admission proof",
    )
    for policy in (
        "- name: Test both public npm surfaces on native Windows",
        "npm test --prefix ./packages/kin-mcp",
        "npm run lint --prefix ./packages/kin-mcp",
    ):
        require(
            ci_jobs["windows-authority-tests"],
            policy,
            "native Windows npm MCP provisioning proof",
        )
    require(
        ci_jobs["windows-installer"],
        "target/x86_64-pc-windows-msvc/release/kin.exe",
        "landing-push Windows admission proof",
    )
    assert_windows_authority_split(ci_jobs)
    for label, job_id, mutated_block, expected in (
        (
            "a native Windows leg is dropped in the split",
            "windows-authority-cli-tests",
            ci_jobs["windows-authority-cli-tests"].replace(
                '"native managed-daemon ownership scan"', '"renamed leg"', 1
            ),
            "exactly once",
        ),
        (
            "two Windows jobs both claim the same leg",
            "windows-authority-runtime-tests",
            ci_jobs["windows-authority-runtime-tests"].replace(
                '"daemon isolation support"', '"kin-git library"', 1
            ),
            "exactly once",
        ),
        (
            "a Windows authority job is taken off the merge queue",
            "windows-authority-runtime-tests",
            ci_jobs["windows-authority-runtime-tests"].replace(
                "    runs-on: windows-latest",
                "    if: github.event_name != 'merge_group'\n    runs-on: windows-latest",
                1,
            ),
            "must stay on the merge queue",
        ),
        (
            "a Windows authority job takes an unreviewed job-level condition",
            "windows-authority-runtime-tests",
            ci_jobs["windows-authority-runtime-tests"].replace(
                f"    if: {WINDOWS_AUTHORITY_ADMITTED_IF}\n", "    if: ${{ false }}\n", 1
            ),
            "The only reviewed condition is",
        ),
        (
            "the reviewed condition is widened to exclude the push as well",
            "windows-authority-runtime-tests",
            ci_jobs["windows-authority-runtime-tests"].replace(
                f"    if: {WINDOWS_AUTHORITY_ADMITTED_IF}\n",
                "    if: ${{ github.event_name != 'pull_request'"
                " && github.event_name != 'push' }}\n",
                1,
            ),
            "The only reviewed condition is",
        ),
        (
            "a Windows authority job stops sourcing the shared leg helpers",
            "windows-authority-cli-tests",
            ci_jobs["windows-authority-cli-tests"].replace(
                f"          {WINDOWS_AUTHORITY_LEG_HELPERS}\n", "", 1
            ),
            "shared leg helpers",
        ),
        (
            "the step budgets grow past the job cap they must fire before",
            "windows-authority-cli-tests",
            ci_jobs["windows-authority-cli-tests"].replace(
                "    timeout-minutes: 45", "    timeout-minutes: 30", 1
            ),
            "failing loudly",
        ),
        (
            "a Windows authority job budgets no step at all",
            "windows-authority-cli-tests",
            re.sub(
                r"(?m)^        timeout-minutes: \d+\n",
                "",
                ci_jobs["windows-authority-cli-tests"],
            ),
            "must budget its long steps",
        ),
    ):
        expect_assertion(
            label,
            expected,
            lambda job_id=job_id, mutated_block=mutated_block: (
                assert_windows_authority_split({**ci_jobs, job_id: mutated_block})
            ),
        )

    # The Linux release artifacts are the only musl compilation Kin performs,
    # and until this guard existed no required context compiled for that target.
    # A target_env cfg is invisible to a glibc build, so a dependency resolving
    # a glibc-only libc entry point passed every check, reached a tag, and then
    # failed the release run, where the only remedy is another version cut. Pin
    # the guard to the release matrix so it cannot drift off the target whose
    # artifacts it protects, and pin its package set so it cannot shrink below
    # what the release builds. It lives in the required Check & Test job on
    # purpose: a guard in a context no ruleset requires cannot refuse a merge.
    release_musl_targets = {
        match.group("target")
        for match in re.finditer(
            r"(?m)^\s+target: (?P<target>\S+-linux-musl)$",
            workflow_job_blocks(release)["build"],
        )
    }
    if not release_musl_targets:
        raise AssertionError(
            "the release build matrix must name at least one musl target for "
            "the pull-request release-target compile guard to protect"
        )
    for policy in (
        "- name: Check the Linux release target (musl)",
        "musl-tools",
        "-p kin-cli -p kin-daemon",
    ):
        require(ci_jobs["check"], policy, "pull-request Linux release-target compile guard")
    # Every musl target the release workflow ships must compile before a merge,
    # not first inside the tagged release run. Deriving the requirement from the
    # release matrix rather than naming one target keeps the two from drifting
    # apart in the direction that costs a version cut: a release target that no
    # required context compiles. The aarch64 leg needs a C compiler for the same
    # dependency build scripts, and Ubuntu carries no aarch64 musl one, so it
    # compiles those C sources with the aarch64 glibc cross toolchain and proves
    # the Rust half exactly; the native ubuntu-24.04-arm release leg is what
    # proves the C half against musl.
    for target in sorted(release_musl_targets):
        for policy in (
            f"rustup target add {target}",
            f"cargo check --locked --target {target}",
        ):
            require(
                ci_jobs["check"],
                policy,
                f"pull-request compile guard coverage of release musl target {target}",
            )
    if "aarch64-unknown-linux-musl" in release_musl_targets:
        require(
            ci_jobs["check"],
            "gcc-aarch64-linux-gnu",
            "aarch64 release-target compile guard C toolchain",
        )
    for package in ("-p kin-cli", "-p kin-daemon"):
        require(
            workflow_job_blocks(release)["build"],
            package,
            "release core binary package set the compile guard mirrors",
        )

    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    # P3-4's content landed without a guard, so a deliberate deletion of the
    # index refresh was invisible to the suite. The refresh now lives in the
    # bounded apt helper every apt site in the check job calls, so the guard
    # follows it there: the aarch64 leg must call the helper for its cross
    # toolchain, and the helper must still refresh the index before installing,
    # under a timeout, or a stalled mirror holds the job to its one-hour bound
    # and the merge queue ejects the entry without marking the pull request.
    require(
        ci_jobs["check"],
        "scripts/ci-apt-install.sh gcc-aarch64-linux-gnu",
        "aarch64 release-target compile guard apt install",
    )
    ci_apt_install = CI_APT_INSTALL.read_text(encoding="utf-8")
    for policy in (
        'timeout "$UPDATE_BOUND" sudo apt-get "${APT_OPTS[@]}" update',
        'timeout "$INSTALL_BOUND" sudo apt-get "${APT_OPTS[@]}" install --yes "$@"',
        "-o Acquire::http::Timeout=30",
        "-o Acquire::Retries=3",
    ):
        require(
            ci_apt_install,
            policy,
            "bounded apt helper index refresh and install",
        )
    if "sudo apt-get" in ci_jobs["check"]:
        raise AssertionError(
            "the check job must reach apt only through scripts/ci-apt-install.sh, "
            "so every apt call stays bounded"
        )

    base_image_pins = BASE_IMAGE_PINS.read_text(encoding="utf-8")
    assert_pin_prover_cannot_refuse_a_release(base_image_pins)
    expect_assertion(
        "the pin prover step loses its explicit errexit-free shell",
        "must declare its shell explicitly",
        lambda: assert_pin_prover_cannot_refuse_a_release(
            re.sub(r"(?m)^\s+shell: bash --noprofile --norc \{0\}\n", "", base_image_pins)
        ),
    )
    expect_assertion(
        "the pin prover step's shell is given errexit back",
        "must not carry errexit",
        lambda: assert_pin_prover_cannot_refuse_a_release(
            base_image_pins.replace(
                "shell: bash --noprofile --norc {0}",
                "shell: bash --noprofile --norc -e {0}",
            )
        ),
    )
    expect_assertion(
        "the pin prover step stops disarming errexit in its own body",
        "missing required policy: set +e",
        lambda: assert_pin_prover_cannot_refuse_a_release(
            base_image_pins.replace("          set +e\n", "")
        ),
    )
    expect_assertion(
        "the pin prover step stops forcing a green conclusion",
        "missing required policy: exit 0",
        lambda: assert_pin_prover_cannot_refuse_a_release(
            base_image_pins.replace("          exit 0\n", "")
        ),
    )
    expect_assertion(
        "a failed checkout is allowed to fail the pin prover job",
        "missing required policy: continue-on-error: true",
        lambda: assert_pin_prover_cannot_refuse_a_release(
            base_image_pins.replace(
                "      - name: Checkout\n        continue-on-error: true\n",
                "      - name: Checkout\n",
            )
        ),
    )

    assert_container_base_image_authority(dockerfile, docker_workflow, release)
    expect_assertion(
        "a floating base image tag reaches the release container",
        "must be pinned by digest",
        lambda: assert_container_base_image_authority(
            re.sub(r"@sha256:[0-9a-f]{64}", "", dockerfile, count=1),
            docker_workflow,
            release,
        ),
    )
    expect_assertion(
        "a base image with no registry escapes the reviewed mirror rewrite",
        "must name their registry",
        lambda: assert_container_base_image_authority(
            dockerfile.replace(f"FROM {BASE_IMAGE_REGISTRY}/", "FROM ", 1),
            docker_workflow,
            release,
        ),
    )
    expect_assertion(
        "the pull-request image build loses its second registry",
        "docker.yml:build-image base image mirror",
        lambda: assert_container_base_image_authority(
            dockerfile,
            docker_workflow.replace(BASE_IMAGE_MIRROR, ""),
            release,
        ),
    )
    expect_assertion(
        "the released image build loses its second registry",
        "release.yml:build_daemon_image base image mirror",
        lambda: assert_container_base_image_authority(
            dockerfile,
            docker_workflow,
            release.replace(BASE_IMAGE_MIRROR, ""),
        ),
    )
    # Deleting the string is the one mutation shape a raw-text assertion always
    # catches, so it proves the least. These comment the config out instead and
    # leave the strings in the file, which is what a debugging session actually
    # leaves behind, and which a raw-text assertion passes.
    for label, mutated_docker, mutated_release in (
        (
            "the pull-request image build's mirror is commented out",
            comment_out_mirror_input(docker_workflow),
            release,
        ),
        (
            "the released image build's mirror is commented out",
            docker_workflow,
            comment_out_mirror_input(release),
        ),
    ):
        expect_assertion(
            label,
            f"base image mirror is missing required policy: {BASE_IMAGE_MIRROR_INPUT}",
            lambda docker=mutated_docker, source=mutated_release: (
                assert_container_base_image_authority(dockerfile, docker, source)
            ),
        )

    for policy in (
        'workflows: ["Release"]',
        "types: [completed]",
        "actions: read",
        "contents: read",
        "vars.RELEASE_FOLLOWUP_READY == 'true'",
        "github.event.workflow_run.status == 'completed'",
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "startsWith(github.event.workflow_run.head_branch, 'v')",
        "!contains(github.event.workflow_run.head_branch, '-')",
        "environment: release-followups",
        "timeout-minutes: 30",
        "SOURCE_RUN_ID: ${{ github.event.workflow_run.id }}",
        "KIN_TAG: ${{ github.event.workflow_run.head_branch }}",
        "KIN_SHA: ${{ github.event.workflow_run.head_sha }}",
        "Require current callback authority without blocking unrelated main progress",
        '"repos/${GITHUB_REPOSITORY}/compare/${GITHUB_SHA}...${current}"',
        '[ "$ancestry" = ahead ] || [ "$ancestry" = identical ]',
        "authority_paths=(",
        ".github/workflows/publish-release-installers.yml",
        "scripts/verify-homebrew-formula.sh",
        "scripts/validate-homebrew-formula.py",
        "scripts/verify_installer_parity.py",
        '"repos/${GITHUB_REPOSITORY}/contents/${path}?ref=${GITHUB_SHA}"',
        '"repos/${GITHUB_REPOSITORY}/contents/${path}?ref=${current}"',
        "callback authority changed on main after this event",
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${SOURCE_RUN_ID}"',
        'assert_field "source run status" "$(jq -r .status <<< "$run")" completed',
        'assert_field "source run conclusion" "$(jq -r .conclusion <<< "$run")" success',
        'assert_field "source run workflow" "$(jq -r .path <<< "$run")" .github/workflows/release.yml',
        'assert_field "release tag target sha" "$peeled" "$KIN_SHA"',
        'gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${KIN_TAG}"',
        'gh api "repos/${GITHUB_REPOSITORY}/releases/latest"',
        "ref: ${{ env.KIN_SHA }}",
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "secrets.KIN_RELEASE_APP_ID",
        "secrets.KIN_RELEASE_APP_PRIVATE_KEY",
        "repositories: |",
        "homebrew-kin",
        "kin-infra",
        "permission-actions: read",
        "permission-contents: write",
        'event_type:"kin-release"',
        "https://api.github.com/repos/firelock-ai/homebrew-kin/dispatches",
        "Update formula ${KIN_TAG} from Kin run ${SOURCE_RUN_ID}",
        "actions/workflows/update-formula.yml/runs?event=repository_dispatch",
        'bash scripts/verify-homebrew-formula.sh "$KIN_TAG"',
        'event_type:"publish-install"',
        "schema_version:1",
        "release_workflow_run_id:$run_id",
        "install_sha256:$install_sha256",
        "install_ps1_sha256:$install_ps1_sha256",
        "Publish installers ${KIN_TAG} from Kin run ${SOURCE_RUN_ID}",
        "actions/workflows/publish-install.yml/runs?event=repository_dispatch",
        "the workflow may still be disabled",
        'python3 scripts/verify_installer_parity.py "$KIN_TAG" --expected-sha "$KIN_SHA"',
    ):
        require(installer_callback, policy, "completed-release follow-up callback")

    if '[ "$current" = "$GITHUB_SHA" ]' in installer_callback:
        raise AssertionError(
            "the callback must tolerate unrelated forward progress on main while "
            "pinning its runtime authority blobs"
        )

    for policy in (
        "`firelock-ai/homebrew-kin` and `firelock-ai/kin-infra`",
        "`KIN_RELEASE_APP_ID`",
        "`KIN_RELEASE_APP_PRIVATE_KEY`",
        "`RELEASE_FOLLOWUP_READY`",
        "Contents write permission",
        "Actions read",
    ):
        require(update_trust, policy, "release follow-up trust documentation")

    callback_admission_start = installer_callback.index("    if: >-")
    callback_admission_end = installer_callback.index(
        "    runs-on:", callback_admission_start
    )
    callback_admission = installer_callback[
        callback_admission_start:callback_admission_end
    ]
    require(
        callback_admission,
        "!contains(github.event.workflow_run.head_branch, '-')",
        "stable-only installer callback admission",
    )

    for forbidden in (
        "workflow_dispatch:",
        "push:",
        "pull_request:",
        "gcloud",
        "WIF_INSTALLER_PROVIDER",
        "WIF_INSTALLER_SERVICE_ACCOUNT",
    ):
        if forbidden in installer_callback:
            raise AssertionError(
                f"completed-release installer callback contains forbidden authority: {forbidden}"
            )
    for permission in ("contents", "id-token", "packages", "attestations"):
        if re.search(
            rf"(?m)^\s+{re.escape(permission)}:\s*write\s*$", installer_callback
        ):
            raise AssertionError(
                "completed-release installer callback grants its workflow token "
                f"forbidden {permission}:write authority"
            )

    for policy in (
        "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
        "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
        "Keep polling the bounded log authority even",
        "cache-from: type=gha",
        "cache-to: ${{ github.ref == 'refs/heads/main' && 'type=gha,mode=max' || '' }}",
    ):
        require(docker_workflow, policy, "Docker CI authority and smoke gate")

    image_start = release.index("  build_daemon_image:")
    image_end = release.index("\n  attest_daemon_image:", image_start)
    image_job = release[image_start:image_end]
    for policy in (
        "needs: config",
        "environment: release",
        "packages: write",
        "ghcr.io/firelock-ai/kin",
        "verify-container-build-info.sh",
        "docker buildx build",
    ):
        require(image_job, policy, "release daemon image build job")

    for forbidden in (
        "id-token: write",
        "attestations: write",
        "actions/attest@",
    ):
        if forbidden in image_job:
            raise AssertionError(
                f"release daemon image build job contains attestation authority: {forbidden}"
            )

    attestation_start = release.index("  attest_daemon_image:")
    attestation_end = release.index("\n  build:", attestation_start)
    attestation_job = release[attestation_start:attestation_end]
    for policy in (
        "needs: [config, build_daemon_image]",
        "always()",
        "needs.config.result == 'success'",
        "needs.build_daemon_image.result == 'success'",
        "environment: release",
        "packages: write",
        "id-token: write",
        "attestations: write",
        "EXPECTED_COMMIT: ${{ needs.build_daemon_image.outputs.commit }}",
        "EXPECTED_DIGEST: ${{ needs.build_daemon_image.outputs.digest }}",
        'git rev-parse "${GITHUB_REF_NAME}^{commit}"',
        'reference="${IMAGE}:${COMMIT}"',
        "docker buildx imagetools inspect",
        "^sha256:[0-9a-f]{64}$",
        'if [ "$digest" != "$EXPECTED_DIGEST" ]',
        '"${IMAGE}@${digest}" "$COMMIT"',
        "Attest immutable daemon image",
        "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
        "subject-name: ghcr.io/firelock-ai/kin",
        "subject-digest: ${{ steps.subject.outputs.digest }}",
        "push-to-registry: true",
        "create-storage-record: false",
        "Verify immutable daemon image attestation",
        '"oci://ghcr.io/firelock-ai/kin@${DIGEST}"',
        "--bundle-from-oci",
        "--predicate-type https://slsa.dev/provenance/v1",
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',
        '--signer-digest "$COMMIT"',
        '--source-digest "$COMMIT"',
        '--source-ref "$GITHUB_REF"',
        "--deny-self-hosted-runners",
    ):
        require(attestation_job, policy, "release daemon image attestation job")

    if "docker buildx build" in attestation_job or re.search(
        r"(?m)^\s*docker\s+build\s", attestation_job
    ):
        raise AssertionError(
            "release daemon attestation job must not rebuild the image"
        )
    if image_job.count("docker buildx build") != 1:
        raise AssertionError(
            "release daemon path must contain exactly one image build command"
        )

    finalize_start = release.index("  finalize_release:")
    latest_promotion_start = release.index("  promote_ghcr_latest:")
    boundary_publish_start = release.index("  publish_boundary_contracts:")
    if not finalize_start < latest_promotion_start < boundary_publish_start:
        raise AssertionError(
            "GHCR latest promotion must be a separate job after release finalization"
        )
    latest_promotion_job = release[latest_promotion_start:boundary_publish_start]
    for policy in (
        "needs: [config, finalize_release, version_tag_image, build_daemon_image, attest_daemon_image]",
        "always()",
        "needs.config.result == 'success'",
        "needs.finalize_release.result == 'success'",
        "needs.version_tag_image.result == 'success'",
        "needs.build_daemon_image.result == 'success'",
        "needs.attest_daemon_image.result == 'success'",
        "needs.config.outputs.release_channel == 'latest'",
        "startsWith(github.ref, 'refs/tags/v')",
        "!contains(github.ref_name, '-')",
        "environment: release",
        "contents: read",
        "packages: write",
        "attestations: read",
        "persist-credentials: false",
        "fetch-depth: 0",
        "docker/login-action@dbcb813823bdd20940b903addbd779551569679f",
        "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
        "EXPECTED_COMMIT: ${{ needs.build_daemon_image.outputs.commit }}",
        "EXPECTED_SOURCE_DIGEST: ${{ needs.build_daemon_image.outputs.digest }}",
        "is not an exact stable release tag",
        'if [ "$GITHUB_REF" != "refs/tags/${GITHUB_REF_NAME}" ]',
        'channel="$(node scripts/release-order.mjs channel "$VERSION")"',
        'git rev-parse "${GITHUB_REF_NAME}^{commit}"',
        'if [ "$COMMIT" != "$EXPECTED_COMMIT" ]',
        'SRC="${IMAGE}:${COMMIT}"',
        'VERSION_TAG="${IMAGE}:${VERSION}"',
        'V_VERSION_TAG="${IMAGE}:${GITHUB_REF_NAME}"',
        'LATEST="${IMAGE}:latest"',
        "inspect_digest()",
        "resolve_required_digest()",
        "wait_for_expected_digest()",
        "for attempt in $(seq 1 12)",
        "matching_reads=$((matching_reads + 1))",
        'if [ "$matching_reads" -eq 2 ]',
        "did not converge to $expected",
        "verify_stable_release_authority()",
        '"repos/${GITHUB_REPOSITORY}/releases/latest"',
        '"repos/${GITHUB_REPOSITORY}/releases/tags/${GITHUB_REF_NAME}"',
        "GitHub Latest moved to",
        "verify_immutable_authority()",
        "scripts/verify-container-build-info.sh",
        "verify_attestation()",
        '"oci://${IMAGE}@${digest}"',
        "--bundle-from-oci",
        "--predicate-type https://slsa.dev/provenance/v1",
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',
        '--signer-digest "$COMMIT"',
        '--source-digest "$COMMIT"',
        '--source-ref "$GITHUB_REF"',
        "--deny-self-hosted-runners",
        "initial_latest_state=missing",
        "mutation_required=true",
        'if [ "$initial_latest_digest" = "$EXPECTED_SOURCE_DIGEST" ]',
        "GHCR offers no atomic",
        'verify_immutable_authority "pre-write"',
        "prewrite_latest_state=missing",
        'if [ "$prewrite_latest_digest" = "$EXPECTED_SOURCE_DIGEST" ]',
        'action="Verified concurrent"',
        "changed from ${initial_latest_state}:${initial_latest_digest:-<missing>}",
        'prewrite_source_digest="$(resolve_required_digest "$SRC" "pre-write source recheck")"',
        "final_prewrite_latest_state=missing",
        'if [ "$final_prewrite_latest_digest" = "$EXPECTED_SOURCE_DIGEST" ]',
        "during final admission",
        "docker buildx imagetools create",
        "--prefer-index=false",
        '--tag "$LATEST"',
        '"${IMAGE}@${EXPECTED_SOURCE_DIGEST}"',
        'verify_immutable_authority "post-write"',
        'actual_latest_digest="$(wait_for_expected_digest',
        '"$LATEST" "$EXPECTED_SOURCE_DIGEST" "post-write latest")"',
        'scripts/verify-container-build-info.sh "$LATEST" "$COMMIT"',
        'verify_attestation "$actual_latest_digest"',
        '"$LATEST" "$EXPECTED_SOURCE_DIGEST" "final latest readback"',
    ):
        require(latest_promotion_job, policy, "stable GHCR latest promotion")

    if latest_promotion_job.count("docker buildx imagetools create") != 1:
        raise AssertionError(
            "stable GHCR latest promotion must contain exactly one registry mutation"
        )
    for forbidden in (
        "contents: write",
        "id-token: write",
        "attestations: write",
        "artifact-metadata: write",
        "actions/attest@",
        "docker buildx build",
        "docker push",
        "gh release edit",
        "continue-on-error",
        "!failure()",
        "!cancelled()",
        "|| true",
        "WIF_PROVIDER",
        "WIF_SERVICE_ACCOUNT",
        "us-central1-docker.pkg.dev",
    ):
        if forbidden in latest_promotion_job:
            raise AssertionError(
                "stable GHCR latest promotion contains forbidden authority or "
                f"fail-open behavior: {forbidden}"
            )

    publish_start = release.index("  publish:")
    publish_end = release.index("\n  install_proof:", publish_start)
    publish_job = release[publish_start:publish_end]
    for policy in (
        "needs: [config, build, notarize_linux, attest_daemon_image]",
        "always()",
        "needs.config.result == 'success'",
        "needs.build.result == 'success'",
        "needs.attest_daemon_image.result == 'success'",
        "needs.config.outputs.notarize_on_linux == 'true'",
        "needs.notarize_linux.result == 'success'",
        "needs.config.outputs.notarize_on_linux == 'false'",
        "needs.notarize_linux.result == 'skipped'",
    ):
        require(publish_job, policy, "first GitHub Release write admission")
    for forbidden in ("!failure()", "!cancelled()"):
        if forbidden in publish_job:
            raise AssertionError(
                "first GitHub Release write must use exact direct-needs results, "
                f"not permissive aggregate state: {forbidden}"
            )
    require(
        release,
        "needs: [publish, install_proof, build_daemon_image, attest_daemon_image]",
        "version image daemon attestation gate",
    )
    require(
        release,
        "EXPECTED_SOURCE_DIGEST: ${{ needs.build_daemon_image.outputs.digest }}",
        "release daemon image promotion",
    )

    build_start = release.index("  build:")
    build_end = release.index("\n  notarize_linux:", build_start)
    build_job = release[build_start:build_end]
    windows_bytes = build_job.index("      - name: Preserve tracked bytes on Windows")
    checkout = build_job.index("      - name: Checkout\n")
    vfs_checkout = build_job.index("      - name: Checkout kin-vfs")
    lock_assertion = build_job.index(
        "      - name: Verify canonical release input bytes"
    )
    first_compile = build_job.index("      - name: Build kin-cli + kin-daemon (native)")
    if not windows_bytes < checkout < vfs_checkout < lock_assertion < first_compile:
        raise AssertionError(
            "release build must disable Windows conversion before checkout and verify "
            "both tracked lockfiles before compilation"
        )
    for policy in (
        "if: runner.os == 'Windows'",
        "git config --global core.autocrlf false",
        '["cat-file", "blob", "HEAD:Cargo.lock"]',
        '[["Kin", process.cwd()], ["kin-vfs", path.join(process.cwd(), "kin-vfs")]]',
        "if (!working.equals(tracked))",
        "refusing platform-specific release provenance",
    ):
        require(build_job, policy, "cross-platform release lockfile authority")

    for policy in (
        'require("./scripts/read-update-build-identity.cjs")',
        "record.build_identity = readUpdateBuildIdentity(file)",
        "schema_version: 2",
        "static build identity does not match the tagged release source",
        "CLI and daemon graph snapshot identities disagree",
    ):
        require(build_job, policy, "static release build identity generation")

    for policy in (
        "manifest.schema_version === 2",
        "const identity = readUpdateBuildIdentity(file)",
        "record?.build_identity === undefined",
        "static build source is not clean and known",
        "static dependency provenance mismatch",
    ):
        require(publish_job, policy, "static release build identity aggregation")
    require(
        ci_workflow,
        "./scripts/read-update-build-identity.test.cjs",
        "static release build identity parser regression",
    )

    # The archive that carries the release and the manifest that describes it are
    # produced by one job and judged by another. Both must decide what a release
    # archive is allowed to contain from the same rules, or a shape one side
    # emits is a shape the other refuses at publish time.
    for policy in (
        'require("./scripts/release-archive-shape.cjs")',
        "classifyReleaseArchiveRoot(artifact, { target })",
    ):
        require(build_job, policy, "sanctioned release archive shape at packaging")
    for policy in (
        'require("./scripts/release-archive-shape.cjs")',
        "assertReleaseArchiveMemberPaths(",
        "classifyReleaseArchiveRoot(contentRoot, {",
    ):
        require(publish_job, policy, "sanctioned release archive shape at publish")
    for forbidden in (
        "entries.every((entry) => entry.isFile())",
        ".filter((entry) => entry.isFile())",
    ):
        if forbidden in publish_job or forbidden in build_job:
            raise AssertionError(
                "release archive shape must be judged by the shared classifier, not by "
                f"an inline entry-type filter: {forbidden}"
            )
    member_path_check = publish_job.index("assertReleaseArchiveMemberPaths(")
    archive_extraction = publish_job.index("fs.mkdtempSync(path.join(os.tmpdir()")
    if member_path_check >= archive_extraction:
        raise AssertionError(
            "release archive member paths must be judged before extraction, because a "
            "member that escapes the extraction root has already been written by then"
        )
    if 'tar tzf "${ARTIFACT}.tar.gz" | grep' in build_job:
        raise AssertionError(
            "release packaging must read the archive listing from a file: piping it into "
            "grep lets an early grep exit fail the pipeline under pipefail, which is "
            "indistinguishable from the member being absent"
        )
    require(
        ci_workflow,
        "./scripts/release-archive-shape.test.cjs",
        "release archive shape regression",
    )

    # The release build decides which files may sit at an archive root; the
    # updater decides which names it is willing to stage. `kin update` aborts a
    # whole staging on the first name it does not manage, so a name sanctioned
    # here that the updater has never heard of publishes cleanly and then stops
    # every update on that platform until a later release replaces the archive.
    # Pin the two sets against each other instead of trusting them to be edited
    # together. Only one direction is required: the updater deliberately manages
    # names the release no longer ships, so that it can delete a stale copy.
    archive_shape = (ROOT / "scripts" / "release-archive-shape.cjs").read_text(
        encoding="utf-8"
    )
    for policy in (
        "holds unexpected file",
        "declares unexpected file",
        "has no component list for target",
    ):
        require(archive_shape, policy, "sanctioned release archive root file names")
    updater = (ROOT / "crates" / "kin-cli" / "src" / "commands" / "update.rs").read_text(
        encoding="utf-8"
    )

    def between(content: str, start: str, end: str, label: str) -> str:
        try:
            begin = content.index(start) + len(start)
            return content[begin : content.index(end, begin)]
        except ValueError as error:
            raise AssertionError(
                f"cannot read {label}: anchor moved, so this check would compare "
                "two empty sets and pass without judging anything"
            ) from error

    for family, spec, cli in (
        ("darwin", "MACOS_COMPONENTS", "kin"),
        ("linux", "LINUX_COMPONENTS", "kin"),
        ("windows", "WINDOWS_COMPONENTS", "kin.exe"),
    ):
        sanctioned = set(
            re.findall(
                r'"([^"]+)"',
                between(
                    archive_shape,
                    f"  {family}: Object.freeze([",
                    "]),",
                    f"the {family} release archive root file names",
                ),
            )
        )
        managed = set(
            re.findall(
                r'name: "([^"]+)"',
                between(
                    updater,
                    f"const {spec}: &[ComponentSpec] = &[",
                    "\n];",
                    f"the updater's {spec} list",
                ),
            )
        )
        # Both extractions have to have found the CLI, or an anchor drifted and
        # the subset below is comparing nothing against nothing.
        for names, source in ((sanctioned, family), (managed, spec)):
            if cli not in names:
                raise AssertionError(
                    f"{source} component names do not include {cli}, so the release "
                    "archive and updater component sets were not actually read"
                )
        unmanaged = sorted(sanctioned - managed)
        if unmanaged:
            raise AssertionError(
                f"release archive root files {unmanaged} are sanctioned for {family} "
                f"but are not in the updater's {spec}, so an archive carrying them "
                "would publish and then abort every update on that platform"
            )
    archive_attestation_start = publish_job.index(
        "      - name: Attest final release archives and provenance"
    )
    release_creation_start = publish_job.index(
        "      - name: Create GitHub Release", archive_attestation_start
    )
    if archive_attestation_start >= release_creation_start:
        raise AssertionError(
            "final release archives must be attested before the first GitHub Release write"
        )
    archive_attestation_step = publish_job[
        archive_attestation_start:release_creation_start
    ]
    for policy in (
        "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
        "subject-path: |",
        "kin-linux-x86_64.tar.gz",
        "kin-linux-aarch64.tar.gz",
        "kin-macos-x86_64.tar.gz",
        "kin-macos-aarch64.tar.gz",
        "kin-windows-x86_64.zip",
        "kin-windows-x86_64.tar.gz",
        "release-provenance.json",
        "Fail closed",
    ):
        require(
            archive_attestation_step,
            policy,
            "final platform-archive attestation authority",
        )
    for policy in (
        "--expect-version",
        "--expect-sha",
        "--expect-archive-sha256",
        "gh attestation verify",
        "firelock-ai/kin/.github/workflows/release.yml",
        "sourceRepositoryDigest",
        "opens the install lock or performs local mutation",
        "selection and drift evidence only",
        "does not authenticate archive bytes",
    ):
        require(update_trust, policy, "pinned updater external byte-authority contract")
    parser = (ROOT / "scripts" / "read-update-build-identity.cjs").read_text(
        encoding="utf-8"
    )
    for policy in (
        "MAX_COMPONENT_BYTES = 256 * 1024 * 1024",
        "bytes.length > MAX_COMPONENT_BYTES",
        "expected exactly one",
        "static build identity end marker is invalid",
        "graph snapshot version must be nonzero",
    ):
        require(parser, policy, "bounded static build identity parser")

    aggregate_start = publish_job.index(
        "      - name: Aggregate per-artifact checksums"
    )
    aggregate_end = publish_job.index(
        "      - name: Verify complete release asset inventory", aggregate_start
    )
    aggregate_step = publish_job[aggregate_start:aggregate_end]
    for policy in (
        "set -euo pipefail",
        "tr -d '\\r' < \"$f\" >> checksums-sha256.txt",
        "grep -q $'\\r' checksums-sha256.txt",
        "aggregate checksum file still contains carriage returns",
    ):
        require(aggregate_step, policy, "cross-platform checksum aggregate")
    if 'cat "$f" >> checksums-sha256.txt' in aggregate_step:
        raise AssertionError(
            "release checksum aggregation must not preserve Windows CRLF bytes"
        )

    windows_start = ci_workflow.index("  windows-installer:")
    windows_end = ci_workflow.index("\n  check:", windows_start)
    windows_job = ci_workflow[windows_start:windows_end]
    ci_windows_bytes = windows_job.index(
        "      - name: Preserve tracked bytes on Windows"
    )
    ci_checkout = windows_job.index("      - uses: actions/checkout@v7")
    if ci_windows_bytes >= ci_checkout:
        raise AssertionError(
            "Windows CI must disable line-ending conversion before checkout"
        )
    for policy in (
        "git config --global core.autocrlf false",
        '["cat-file", "blob", "HEAD:Cargo.lock"]',
        "if (!workingLock.equals(trackedLock))",
        "meta.dependency_provenance !== expectedLock",
        "does not match tracked Git bytes",
    ):
        require(windows_job, policy, "Windows exact lockfile provenance regression")

    # The Windows installer leg is off the pull-request path, so the only
    # places it can prove anything are the queue's build and the landing push.
    # The only reason that is safe is that release-tag.yml refuses to mint a
    # tag unless this exact check is present and green on the release sha. Pin
    # every half together: dropping one silently turns a required release gate
    # into a job that never runs on the commit being released.
    #
    # The merge-queue half is load-bearing now rather than optional. The mint
    # keys off the merge-group-proven sha, and this leg is the one required
    # context the queue used to skip, so a build that skips it is a build the
    # mint must refuse. Restoring a merge_group exclusion here would make the
    # queue's proof incomplete for exactly the platform that has been killing
    # tags, and the mint would refuse every release until someone noticed.
    installer_start = ci_workflow.index("  windows-installer:")
    installer_end = ci_workflow.index("\n  changes:", installer_start)
    installer_job = ci_workflow[installer_start:installer_end]
    for policy in (
        "name: Windows installer + vector release build",
        "github.event_name != 'pull_request'",
        "needs.changes.outputs.docs_only != 'true'",
    ):
        require(installer_job, policy, "main-only Windows installer admission")
    if "github.event_name != 'merge_group'" in installer_job:
        raise AssertionError(
            "the Windows installer leg must run inside the merge queue: the "
            "release mint keys off the queue-proven sha and refuses a build "
            "that skipped this required context"
        )
    require(
        ci_workflow,
        "  push:\n    branches: [main]",
        "Windows installer proof still reaching every main commit",
    )
    require(
        ci_workflow,
        "  merge_group:",
        "Windows installer proof reaching the queue build the mint keys off",
    )

    # Main's classifier must keep reporting false so the release-critical
    # installer actually runs. The release-tag gate independently requires an
    # exact success conclusion, but preserving both controls keeps a main push
    # from silently losing the proof and discovering that only at tag time.
    # Enforce the classifier as a closed form at the whole-job boundary. The
    # reviewed shell is meaningless without its checkout, output, id, event,
    # SHA, shell, and startup-environment bindings, so those are one authority
    # contract rather than independently mutable text.
    # The span ends at the next job header rather than at a named sibling. It
    # used to name `check-docs-only`, which put this reader one job rename or
    # one inserted job away from a ValueError that reads like a missing
    # classifier rather than like a moved neighbour.
    classifier_start = ci_workflow.index("  changes:")
    next_job = re.search(
        r"(?m)^  [A-Za-z0-9_.-]+:$", ci_workflow[classifier_start + len("  changes:") :]
    )
    if next_job is None:
        raise AssertionError("the classifier job must be followed by another job")
    classifier_end = classifier_start + len("  changes:") + next_job.start()
    classifier = ci_workflow[classifier_start:classifier_end].rstrip("\n")
    assert_docs_only_classifier_guard(ci_workflow)
    assert_assertion_reachability_gate_wired(ci_workflow)
    toolchain_action = RUST_TOOLCHAIN_ACTION.read_text(encoding="utf-8")
    assert_toolchain_prune_is_wired(toolchain_action)
    assert_toolchain_prune_behavior()
    for label, original, replacement, expected in (
        (
            "the prune step is dropped, so the image decides the cache key",
            "    - name: Prune toolchains this repository never named",
            "    - name: Prune nothing at all",
            "must declare exactly one step named",
        ),
        (
            "the image set is recorded after the install, where it cannot tell them apart",
            "    - name: Record the toolchains the runner image shipped",
            "    - name: Recorded too late",
            "must declare exactly one step named",
        ),
        (
            "the prune stops calling the script the behavioral cases drive",
            'bash "$GITHUB_ACTION_PATH/prune-image-toolchains.sh" \\',
            "true \\",
            "must call prune-image-toolchains.sh",
        ),
    ):
        mutant = replace_exactly_once(toolchain_action, original, replacement, label)
        expect_assertion(
            label,
            expected,
            lambda mutant=mutant: assert_toolchain_prune_is_wired(mutant),
        )
    assert_cargo_deny_reads_every_advisory(sast)
    assert_advisory_sweep_authority(advisory_sweep, release_train)
    for label, source, original, replacement, expected, check in (
        (
            "the gate stops running the whole default check set",
            sast,
            f"{CARGO_DENY_FULL_CHECK}; then",
            f"{CARGO_DENY_FULL_CHECK} advisories; then",
            "must run the whole default check set",
            "sast",
        ),
        (
            "a merge group narrows the check set back to the refused subset",
            sast,
            "            --annotate-merge-group\n",
            "            --annotate-merge-group\n"
            f"          {CARGO_DENY_FULL_CHECK} bans licenses sources\n",
            "must not narrow its check set",
            "sast",
        ),
        (
            "a merge-group failure stops naming the advisory that caused it",
            sast,
            "--annotate-merge-group",
            "--dry-run",
            "must name the advisory and its bump command",
            "sast",
        ),
        (
            "a merge-group advisory failure is downgraded to a pass",
            sast,
            "            --annotate-merge-group\n          exit 1\n",
            "            --annotate-merge-group\n          exit 0\n",
            "must still fail",
            "sast",
        ),
        (
            "the sweep loses its schedule and runs only when asked",
            advisory_sweep,
            "on:\n  schedule:\n",
            "on:\n  # schedule removed\n",
            "must run on a schedule",
            "sweep",
        ),
        (
            "the sweep's manual path stops being pinned to one dispatch action",
            advisory_sweep,
            "types: [advisory-sweep]",
            "types: [anything]",
            "pinned to one action",
            "sweep",
        ),
        (
            "the sweep stops gating its manual path on the reviewed actors",
            advisory_sweep,
            "ALLOWED_ACTORS: |",
            "UNUSED_ACTORS: |",
            "gated to the reviewed actor set",
            "sweep",
        ),
        (
            "the sweep stops proving the hand-written lock is coherent",
            advisory_sweep,
            "cargo metadata --locked",
            "cargo metadata",
            "prove the hand-written lock",
            "sweep",
        ),
        (
            "the sweep stops proving the advisory it bumped for is gone",
            advisory_sweep,
            "--all-features check advisories\n\n      - name: Publish",
            "--all-features check\n\n      - name: Publish",
            "prove the advisory the bump exists for is actually gone",
            "sweep",
        ),
        (
            "the sweep stops refusing a bump that escaped the lockfile",
            advisory_sweep,
            'if [ "$changed" != "Cargo.lock" ]',
            'if [ "$changed" = "never" ]',
            "refuse a bump that touched anything but the lock",
            "sweep",
        ),
        (
            "a clean sweep opens a pull request anyway",
            advisory_sweep,
            "      - name: Arm protected auto-merge\n        if: steps.plan.outputs.bumps != '0'\n",
            "      - name: Arm protected auto-merge\n        if: always()\n",
            "must be gated on steps.plan.outputs.bumps != '0'",
            "sweep",
        ),
        (
            "an unfixable advisory opens a pull request instead of an issue",
            advisory_sweep,
            "      - name: Open or update the unfixable-advisory issue\n        if: steps.plan.outputs.unfixable != '0'\n",
            "      - name: Open or update the unfixable-advisory issue\n        if: always()\n",
            "must be gated on steps.plan.outputs.unfixable != '0'",
            "sweep",
        ),
    ):
        mutant = replace_exactly_once(source, original, replacement, label)
        if check == "sast":
            expect_assertion(
                label,
                expected,
                lambda mutant=mutant: assert_cargo_deny_reads_every_advisory(mutant),
            )
        else:
            expect_assertion(
                label,
                expected,
                lambda mutant=mutant: assert_advisory_sweep_authority(mutant, release_train),
            )
    assert_kin_vfs_compat_gate_wired(ci_workflow)
    assert_glibc_floor_guard_wired(ci_workflow, release)
    assert_kin_vfs_mount_features_built(release)
    expect_assertion(
        "macOS kin-vfs built without the nfs feature",
        "--features nfs",
        lambda: assert_kin_vfs_mount_features_built(
            release.replace(
                '-p kin-vfs-cli --features nfs',
                '-p kin-vfs-cli',
            )
        ),
    )
    expect_assertion(
        "Linux kin-vfs built without the fuse feature",
        "--features fuse",
        lambda: assert_kin_vfs_mount_features_built(
            release.replace(
                '-p kin-vfs-cli --features fuse',
                '-p kin-vfs-cli',
            )
        ),
    )
    expect_assertion(
        "release.yml stops reading the glibc floor off the packaged binaries",
        "release.yml must run",
        lambda: assert_glibc_floor_guard_wired(
            ci_workflow,
            release.replace(GLIBC_FLOOR_RELEASE_CHECK, "run: true"),
        ),
    )
    expect_assertion(
        "the floor check survives only as a commented-out release.yml step",
        "release.yml must run",
        lambda: assert_glibc_floor_guard_wired(
            ci_workflow,
            release.replace(
                GLIBC_FLOOR_RELEASE_CHECK,
                GLIBC_FLOOR_RELEASE_CHECK.replace("run: ", "run: # "),
            ),
        ),
    )
    expect_assertion(
        "the release build stops reading the floor from the guard that enforces it",
        "must read the glibc floor",
        lambda: assert_glibc_floor_guard_wired(
            ci_workflow,
            release.replace(GLIBC_FLOOR_BUILD_READ, 'floor="2.31"'),
        ),
    )
    expect_assertion(
        "the Linux kin-vfs build reverts to taking its floor from the runner image",
        "must build the Linux kin-vfs binaries against the pinned floor",
        lambda: assert_glibc_floor_guard_wired(
            ci_workflow,
            release.replace(
                'cargo zigbuild --locked --release --target "${VFS_TARGET}.${floor}"',
                'cargo build --locked --release --target "$VFS_TARGET"',
            ),
        ),
    )
    expect_assertion(
        "ci.yml keeps the floor guard but drops the tests proving its parse",
        "ci.yml must run",
        lambda: assert_glibc_floor_guard_wired(
            ci_workflow.replace(GLIBC_FLOOR_TEST_POLICY, "scripts/absent.test.mjs"),
            release,
        ),
    )
    expect_assertion(
        "ci.yml drops the pull-request Kin/kin-vfs compatibility gate",
        "ci.yml must run",
        lambda: assert_kin_vfs_compat_gate_wired(
            ci_workflow.replace(f"run: node {KIN_VFS_COMPAT_GUARD_POLICY}", "run: true")
        ),
    )
    expect_assertion(
        "the Kin/kin-vfs gate survives only as a commented-out ci.yml step",
        "ci.yml must run",
        lambda: assert_kin_vfs_compat_gate_wired(
            ci_workflow.replace(
                f"run: node {KIN_VFS_COMPAT_GUARD_POLICY}",
                f"run: # node {KIN_VFS_COMPAT_GUARD_POLICY}",
            )
        ),
    )
    expect_assertion(
        "ci.yml keeps the Kin/kin-vfs gate but drops the tests proving its parse",
        "ci.yml must run",
        lambda: assert_kin_vfs_compat_gate_wired(
            ci_workflow.replace(KIN_VFS_COMPAT_TEST_POLICY, "scripts/absent.test.mjs")
        ),
    )
    assert_installer_asset_guard_wired(ci_workflow, release)
    expect_assertion(
        "ci.yml drops the guard that installer asset names are published",
        "ci.yml must run",
        lambda: assert_installer_asset_guard_wired(
            ci_workflow.replace(INSTALLER_ASSET_GUARD_POLICY, "scripts/absent.py"),
            release,
        ),
    )
    expect_assertion(
        "ci.yml keeps the guard but drops its falsification",
        "ci.yml must run",
        lambda: assert_installer_asset_guard_wired(
            ci_workflow.replace(INSTALLER_ASSET_FALSIFIER_POLICY, "scripts/absent.py"),
            release,
        ),
    )
    expect_assertion(
        "the release stops checking installer asset names against its own assets",
        "must run",
        lambda: assert_installer_asset_guard_wired(
            ci_workflow,
            release.replace(f"./{INSTALLER_ASSET_GUARD_POLICY} --assets-dir .", "true"),
        ),
    )
    assert_installer_archive_binary_guard_wired(ci_workflow)
    expect_assertion(
        "ci.yml drops the guard that installer binary names match the archive",
        "ci.yml must run",
        lambda: assert_installer_archive_binary_guard_wired(
            ci_workflow.replace(INSTALLER_BINARY_GUARD_POLICY, "scripts/absent.py")
        ),
    )
    expect_assertion(
        "ci.yml keeps the binary-name guard but drops its falsification",
        "ci.yml must run",
        lambda: assert_installer_archive_binary_guard_wired(
            ci_workflow.replace(INSTALLER_BINARY_FALSIFIER_POLICY, "scripts/absent.py")
        ),
    )
    assert_active_lines_cannot_span_unrelated_shell(workflow_sources)
    assert_release_version_gate_wired(ci_workflow)
    expect_assertion(
        "ci.yml drops the job that runs the version gate on a release PR",
        "ci.yml must run the release version gate on pull requests",
        lambda: assert_release_version_gate_wired(
            ci_workflow.replace("  release-version:\n", "  release-version-disabled:\n")
        ),
    )
    expect_assertion(
        "the version gate job survives with its command commented out",
        "missing `run: node",
        lambda: assert_release_version_gate_wired(
            ci_workflow.replace(
                f"run: node {RELEASE_VERSION_GUARD_POLICY}",
                f"run: # node {RELEASE_VERSION_GUARD_POLICY}",
            )
        ),
    )
    expect_assertion(
        "the version gate stops reading the release PR's own base commit",
        "missing `BASE_SHA",
        lambda: assert_release_version_gate_wired(
            ci_workflow.replace(
                "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
                "BASE_SHA: ''",
            )
        ),
    )
    expect_assertion(
        "the version gate loses the deep fetch its base manifest needs",
        "missing `fetch-depth: 0`",
        lambda: assert_release_version_gate_wired(
            ci_workflow.replace(
                "          # The gate reads Cargo.toml out of the base commit. A shallow\n"
                "          # pull-request checkout does not carry it, and `git show` would fail\n"
                "          # in a way that reads like a broken gate rather than a missing fetch.\n"
                "          fetch-depth: 0\n",
                "",
            )
        ),
    )
    expect_assertion(
        "the version gate stops being scoped to the release branch",
        "missing `(github.head_ref",
        lambda: assert_release_version_gate_wired(
            ci_workflow.replace(
                "      (github.head_ref == 'automation/release-next' ||\n"
                "      contains(github.event.pull_request.labels.*.name, 'release:automated'))\n",
                "      true\n",
            )
        ),
    )
    expect_assertion(
        "ci.yml keeps both version guards but drops their falsification",
        "ci.yml must run",
        lambda: assert_release_version_gate_wired(
            ci_workflow.replace(
                RELEASE_VERSION_FALSIFIER_POLICY, "scripts/absent.py"
            )
        ),
    )
    expect_assertion(
        "ci.yml stops running the release-intent gate's own suite",
        "ci.yml must run",
        lambda: assert_release_version_gate_wired(
            ci_workflow.replace(RELEASE_INTENT_SUITE_POLICY, "scripts/absent.test.mjs")
        ),
    )
    expect_assertion(
        "ci.yml stops running the version gate's own suite",
        "ci.yml must run",
        lambda: assert_release_version_gate_wired(
            ci_workflow.replace(RELEASE_VERSION_SUITE_POLICY, "scripts/absent.test.mjs")
        ),
    )
    expect_assertion(
        "ci.yml drops the step that proves every assertion still runs",
        "ci.yml must run",
        lambda: assert_assertion_reachability_gate_wired(
            ci_workflow.replace(ASSERTION_REACHABILITY_POLICY, "scripts/absent.py")
        ),
    )
    expect_assertion(
        "the reachability gate survives only as a commented-out ci.yml step",
        "ci.yml must run",
        lambda: assert_assertion_reachability_gate_wired(
            ci_workflow.replace(
                f"run: python3 {ASSERTION_REACHABILITY_POLICY}",
                f"# run: python3 {ASSERTION_REACHABILITY_POLICY}",
            )
        ),
    )
    expect_assertion(
        "the reachability step keeps its path but comments out the command",
        "ci.yml must run",
        lambda: assert_assertion_reachability_gate_wired(
            ci_workflow.replace(
                f"run: python3 {ASSERTION_REACHABILITY_POLICY}",
                f"run: # python3 {ASSERTION_REACHABILITY_POLICY}",
            )
        ),
    )
    assert_check_consumer_authority(ci_workflow)
    assert_macos_shard_authority(ci_workflow)
    assert_ubuntu_shard_authority(ci_workflow)
    assert_fast_gate_authority(ci_workflow)
    fast_gate_blocks = workflow_job_blocks(ci_workflow)
    for label, owner, old, new, expected in (
        (
            "the aggregate stops always running, so a pull request waits on a "
            "context nothing will report",
            "fast-gate-tests-aggregate",
            f"    {FAST_GATE_AGGREGATE_ALWAYS_RUNS}",
            "    if: ${{ !cancelled() && github.event_name != 'pull_request' }}",
            "must run on every event",
        ),
        (
            "the aggregate accepts a shard result that is not success",
            "fast-gate-tests-aggregate",
            FAST_GATE_AGGREGATE_SUCCESS_GATE,
            'if [ "$SHARDS" = "failure" ]; then',
            "admit only `success`",
        ),
        (
            "the aggregate stops waiting on the shards it grades",
            "fast-gate-tests-aggregate",
            f"    {FAST_GATE_AGGREGATE_NEEDS}",
            "    needs: changes",
            "must wait on the shards",
        ),
        (
            "the shards stop asserting the selection lists any test",
            "fast-gate-tests",
            'print("::error title=Empty test selection::the scope lists zero tests")',
            "pass",
            "sharded half must keep running",
        ),
        (
            "the scope selector is dropped and the shards test whatever is left",
            "fast-gate-tests",
            "python3 scripts/changed-crate-scope.py",
            "true scripts/changed-crate-scope-disabled.py",
            "sharded half must keep running",
        ),
        (
            "one red shard is allowed to cancel its passing siblings",
            "fast-gate-tests",
            f"      {FAST_GATE_SHARD_INDEPENDENT_LEGS}",
            "      fail-fast: true",
            "shards must keep",
        ),
        (
            "the quarantine clock stops running in the admission core",
            "fast-gate-lint",
            "        run: python3 scripts/check-quarantine.py\n",
            "        run: true\n",
            "lint and policy half must keep running",
        ),
    ):
        # Scoped to the owning job block rather than the whole file: two jobs
        # carry `if: ${{ !cancelled() }}`, and a whole-file replace would mutate
        # whichever came first and grade a job this assertion is not about.
        block = fast_gate_blocks[owner]
        if block.count(old) != 1:
            raise AssertionError(
                f"admission core falsification could not identify {label}"
            )
        mutant_workflow = ci_workflow.replace(block, block.replace(old, new, 1), 1)
        expect_assertion(
            label,
            expected,
            lambda mutant=mutant_workflow: assert_fast_gate_authority(mutant),
        )
    assert_shared_cache_key_jobs_declare_one_environment(ci_workflow)
    consumer_blocks = workflow_job_blocks(ci_workflow)
    stub_check = consumer_blocks["check-pr-fast-path"]
    real_check = consumer_blocks["check"]
    macos_shards = consumer_blocks["check-macos"]
    macos_aggregate = consumer_blocks["check-macos-aggregate"]

    for label, old, new in (
        (
            "the aggregate accepts a shard result that is not success",
            'if [ "$SHARDS" != "success" ]; then',
            'if [ "$SHARDS" = "failure" ]; then',
        ),
        (
            "the aggregate loses the matrix that keeps a skip from expanding",
            "        os: [macos-latest]",
            "        os: []",
        ),
        (
            "the aggregate stops waiting on the shards",
            "    needs: [changes, check-macos]",
            "    needs: changes",
        ),
        (
            "the aggregate takes the display name of the shard job",
            "    name: Check & Test",
            "    name: Check & Test macOS aggregate",
        ),
    ):
        if macos_aggregate.count(old) != 1:
            raise AssertionError(
                f"macOS shard falsification could not identify {label}"
            )
        mutant_workflow = ci_workflow.replace(
            macos_aggregate, macos_aggregate.replace(old, new, 1), 1
        )
        expect_assertion(
            label,
            "macOS shard authority",
            lambda mutant_workflow=mutant_workflow: assert_macos_shard_authority(
                mutant_workflow
            ),
        )

    for label, old, new in (
        (
            "a shard stops partitioning and both legs run the whole suite",
            "        run: cargo nextest run --locked "
            "--partition count:${{ matrix.shard }}/2",
            "        run: cargo nextest run --locked",
        ),
        (
            "the doctest pass nextest cannot run disappears",
            "        run: cargo test --doc --locked",
            "        run: echo doctests skipped",
        ),
        (
            "one red shard is allowed to cancel its passing sibling",
            "      fail-fast: false",
            "      fail-fast: true",
        ),
        (
            "the shards leave macOS",
            "    runs-on: macos-latest",
            "    runs-on: ubuntu-latest",
        ),
        (
            "the shard count changes without the partition denominator",
            "        shard: [1, 2]",
            "        shard: [1, 2, 3]",
        ),
    ):
        if macos_shards.count(old) != 1:
            raise AssertionError(
                f"macOS shard falsification could not identify {label}"
            )
        mutant_workflow = ci_workflow.replace(
            macos_shards, macos_shards.replace(old, new, 1), 1
        )
        expect_assertion(
            label,
            "macOS shard authority",
            lambda mutant_workflow=mutant_workflow: assert_macos_shard_authority(
                mutant_workflow
            ),
        )

    ubuntu_shards = consumer_blocks["check"]
    ubuntu_aggregate = consumer_blocks["check-aggregate"]

    for label, old, new in (
        (
            "the ubuntu aggregate accepts a shard result that is not success",
            'if [ "$SHARDS" != "success" ]; then',
            'if [ "$SHARDS" = "failure" ]; then',
        ),
        (
            "the ubuntu aggregate loses the matrix that keeps a skip from expanding",
            "        os: [ubuntu-latest]",
            "        os: []",
        ),
        (
            "the ubuntu aggregate stops waiting on the shards",
            "    needs: [changes, check]",
            "    needs: changes",
        ),
        (
            "the ubuntu aggregate takes the display name of the shard job",
            "    name: Check & Test",
            "    name: Check & Test ubuntu aggregate",
        ),
    ):
        if ubuntu_aggregate.count(old) != 1:
            raise AssertionError(
                f"ubuntu shard falsification could not identify {label}"
            )
        mutant_workflow = ci_workflow.replace(
            ubuntu_aggregate, ubuntu_aggregate.replace(old, new, 1), 1
        )
        expect_assertion(
            label,
            "ubuntu shard authority",
            lambda mutant_workflow=mutant_workflow: assert_ubuntu_shard_authority(
                mutant_workflow
            ),
        )

    for label, old, new in (
        (
            "a shard stops partitioning and both legs run the whole suite",
            "        run: cargo nextest run --locked "
            "--partition count:${{ matrix.shard }}/2",
            "        run: cargo nextest run --locked",
        ),
        (
            "the doctest pass nextest cannot run disappears",
            "        run: cargo test --doc --locked",
            "        run: echo doctests skipped",
        ),
        (
            "one red ubuntu shard is allowed to cancel its passing sibling",
            "      fail-fast: false",
            "      fail-fast: true",
        ),
        (
            # The shards no longer run on ubuntu-latest, so mutating away from it
            # stopped identifying anything the day the runner moved. What the arm
            # has always meant is "the shards leave their pinned runner", so it
            # names the pinned value rather than the historical one.
            "the ubuntu shards leave their pinned runner",
            "    runs-on: kin-16core",
            "    runs-on: macos-latest",
        ),
        (
            "the ubuntu shard count changes without the partition denominator",
            "        shard: [1, 2]",
            "        shard: [1, 2, 3]",
        ),
        # The two that a count of steps cannot see, and the reason the gate list
        # above is a list of names. A gate that loses its pin runs on both legs
        # and pays macOS-shaped minutes twice for one source read; a gate that is
        # renamed off the list runs nowhere, and both arrive as a faster green.
        (
            "a source-reading gate loses its shard pin and runs on both legs",
            "      - name: Clippy\n        if: matrix.shard == 1\n",
            "      - name: Clippy\n",
        ),
        (
            "a source-reading gate is renamed off the pinned list",
            "      - name: Check Runtime Boundaries\n",
            "      - name: Check Runtime Boundaries (moved)\n",
        ),
        # The mirror image: a step a partition consumes is not optional on either
        # leg, and a shard that skipped its own build never ran a partition.
        (
            "a step the partition consumes is pinned to one shard",
            "      - name: Build\n        run: cargo build --all-targets --locked\n",
            "      - name: Build\n        if: matrix.shard == 1\n"
            "        run: cargo build --all-targets --locked\n",
        ),
        (
            "a step the partition consumes leaves the job",
            "      - name: Install nextest\n",
            "      - name: Install nextest (moved)\n",
        ),
    ):
        if ubuntu_shards.count(old) != 1:
            raise AssertionError(
                f"ubuntu shard falsification could not identify {label}"
            )
        mutant_workflow = ci_workflow.replace(
            ubuntu_shards, ubuntu_shards.replace(old, new, 1), 1
        )
        expect_assertion(
            label,
            "ubuntu shard authority",
            lambda mutant_workflow=mutant_workflow: assert_ubuntu_shard_authority(
                mutant_workflow
            ),
        )

    # FIR-2744's guard, driven in every direction it can fail.
    for label, old, new in (
        (
            "a cache step lets the runner's toolchain set back into the key",
            "          add-rust-environment-hash-key: false",
            "          add-rust-environment-hash-key: true",
        ),
        (
            "the shared-key expression stops naming a job, so nothing shares",
            "          shared-key: ${{ matrix.os == 'macos-latest' "
            "&& 'check-macos' || 'check' }}",
            "          shared-key: unshared-by-anything",
        ),
        (
            "the action is renamed, so the extraction silently finds no cache step",
            "uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4",
            "uses: Renamed/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4",
        ),
    ):
        if ci_workflow.count(old) < 1:
            raise AssertionError(
                f"shared cache-key falsification could not identify {label}"
            )
        expect_assertion(
            label,
            "shared cache-key authority",
            lambda mutant=ci_workflow.replace(
                old, new
            ): assert_shared_cache_key_jobs_declare_one_environment(mutant),
        )

    # The one that matters most, because it is the collision the guard exists
    # for and the only one nothing else in this repository would notice.
    feature_tests = consumer_blocks["feature-tests"]
    diverged_env = feature_tests.replace(
        '      CARGO_PROFILE_TEST_DEBUG: "0"',
        '      CARGO_PROFILE_TEST_DEBUG: "2"',
        1,
    )
    if diverged_env == feature_tests:
        raise AssertionError(
            "shared cache-key falsification could not diverge a sharing job's "
            "environment"
        )
    expect_assertion(
        "a job sharing the cargo cache key declares a different environment",
        "shared cache-key authority",
        lambda mutant=ci_workflow.replace(
            feature_tests, diverged_env, 1
        ): assert_shared_cache_key_jobs_declare_one_environment(mutant),
    )

    stub_condition = (
        "    if: ${{ !cancelled() && github.event_name == 'pull_request' }}"
    )
    real_check_condition = (
        "    if: >-\n"
        "      ${{ !cancelled()\n"
        "      && needs.changes.outputs.docs_only != 'true'\n"
        "      && github.event_name != 'pull_request' }}"
    )
    swapped_stub_check = stub_check.replace(
        stub_condition,
        real_check_condition,
        1,
    )
    swapped_real_check = real_check.replace(
        real_check_condition,
        stub_condition,
        1,
    )
    swapped_consumers = ci_workflow.replace(
        stub_check,
        swapped_stub_check,
        1,
    ).replace(
        real_check,
        swapped_real_check,
        1,
    )
    expect_assertion(
        "stub and real Check & Test conditions swapped",
        "Check & Test consumer authority",
        lambda: assert_check_consumer_authority(swapped_consumers),
    )

    for label, old, new in (
        (
            "pull-request Check & Test job identity changed",
            "  check-pr-fast-path:",
            "  check-context-spoof:",
        ),
        (
            "pull-request Check & Test display name changed",
            "    name: Check & Test",
            "    name: Documentation shortcut",
        ),
        (
            "pull-request Check & Test gained a dependency it must not wait on",
            "    runs-on: ubuntu-latest",
            "    needs: changes\n    runs-on: ubuntu-latest",
        ),
        (
            "pull-request Check & Test runner changed",
            "    runs-on: ubuntu-latest",
            "    runs-on: ${{ matrix.os }}",
        ),
        (
            "pull-request Check & Test matrix changed",
            "        os: [ubuntu-latest, macos-latest]",
            "        os: [ubuntu-latest]",
        ),
        (
            "pull-request Check & Test inert step changed",
            '          echo "Admission is the fast gate; '
            'see .github/workflows/ci.yml."',
            '          echo "unreviewed shortcut"',
        ),
        (
            # The one that matters most after FIR-2815: narrowing this back to
            # documentation-only diffs leaves every ordinary pull request with
            # no producer of either expanded `Check & Test` name at all, which
            # is a silent hang rather than a failure.
            "pull-request Check & Test narrowed back to documentation diffs",
            "    if: ${{ !cancelled() && github.event_name == 'pull_request' }}",
            "    if: ${{ !cancelled() && "
            "needs.changes.outputs.docs_only == 'true' }}",
        ),
    ):
        if stub_check.count(old) != 1:
            raise AssertionError(
                f"Check & Test consumer falsification could not identify {label}"
            )
        mutant_job = stub_check.replace(old, new, 1)
        mutant_workflow = ci_workflow.replace(stub_check, mutant_job, 1)
        expect_assertion(
            label,
            "Check & Test consumer authority",
            lambda mutant_workflow=mutant_workflow: assert_check_consumer_authority(
                mutant_workflow
            ),
        )

    for label, old, new in (
        (
            # The sharp regression now that the aggregate owns the required
            # name: a shard claiming `Check & Test` publishes
            # `Check & Test (ubuntu-latest, 1)` and `(2)`, and its bare name
            # collides with the aggregate's on a skip.
            "real Check & Test display name changed",
            "    name: Check & Test ubuntu shard",
            "    name: Check & Test",
        ),
        (
            "real Check & Test dependency changed",
            "    needs: changes",
            "    needs: dco",
        ),
        (
            # The real check job moved to the larger runner; the pull-request
            # stub above did not, which is why only this arm changes and the
            # stub's two arms still name ubuntu-latest.
            "real Check & Test runner detached from its shard matrix",
            "    runs-on: kin-16core",
            "    runs-on: ${{ matrix.os }}",
        ),
        (
            # Restoring a platform matrix is the specific regression to catch:
            # `check` would publish expanded platform names again, beside the
            # aggregates', and put two check runs under one required context
            # name.
            "real Check & Test matrix changed",
            "        shard: [1, 2]",
            "        os: [ubuntu-latest, macos-latest]",
        ),
    ):
        if real_check.count(old) != 1:
            raise AssertionError(
                f"Check & Test consumer falsification could not identify {label}"
            )
        mutant_job = real_check.replace(old, new, 1)
        mutant_workflow = ci_workflow.replace(real_check, mutant_job, 1)
        expect_assertion(
            label,
            "Check & Test consumer authority",
            lambda mutant_workflow=mutant_workflow: assert_check_consumer_authority(
                mutant_workflow
            ),
        )

    coverage_job = consumer_blocks["coverage"]
    if coverage_job.count("    name: Code Coverage") != 1:
        raise AssertionError(
            "Check & Test consumer falsification could not identify coverage name"
        )
    duplicate_context = ci_workflow.replace(
        coverage_job,
        coverage_job.replace(
            "    name: Code Coverage",
            "    name: Check & Test",
            1,
        ),
        1,
    )
    expect_assertion(
        "unrelated job spoofs the Check & Test display context",
        "Check & Test consumer authority",
        lambda: assert_check_consumer_authority(duplicate_context),
    )

    for label, old, new in (
        (
            "classifier job output remapped to a constant",
            "      docs_only: ${{ steps.classify.outputs.docs_only }}",
            '      docs_only: "true"',
        ),
        (
            "classifier checkout pin changed to a moving ref",
            "      - uses: actions/checkout@"
            "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            "      - uses: actions/checkout@v7",
        ),
        (
            "classifier checkout depth changed",
            "          fetch-depth: 0",
            "          fetch-depth: 1",
        ),
        (
            "classifier step id changed",
            "        id: classify",
            "        id: classify_mutant",
        ),
    ):
        if classifier.count(old) != 1:
            raise AssertionError(
                f"diff classifier falsification could not identify {label}"
            )
        mutant = classifier.replace(old, new, 1)
        mutant_workflow = ci_workflow.replace(classifier, mutant, 1)
        expect_assertion(
            label,
            "exactly match the closed-form docs_only authority contract",
            lambda mutant_workflow=mutant_workflow: assert_docs_only_classifier_guard(
                mutant_workflow
            ),
        )

    workflow_environment_needle = '  RUSTFLAGS: "-D warnings"'
    if ci_workflow.count(workflow_environment_needle) != 1:
        raise AssertionError(
            "diff classifier falsification could not identify workflow environment"
        )
    workflow_environment_attacks = (
        (
            "workflow PATH resolves Git from a checked-out executable",
            "  PATH: ${{ github.workspace }}/attack:/usr/local/bin:/usr/bin:/bin",
        ),
        (
            "workflow Git repository and index authority redirected",
            "  GIT_DIR: ${{ github.workspace }}/attack/decoy.git\n"
            "  GIT_WORK_TREE: ${{ github.workspace }}/attack\n"
            "  GIT_INDEX_FILE: ${{ github.workspace }}/attack/index",
        ),
        (
            "workflow Git configuration and external diff authority injected",
            '  GIT_CONFIG_NOSYSTEM: "0"\n'
            "  GIT_CONFIG_GLOBAL: ${{ github.workspace }}/attack/gitconfig\n"
            '  GIT_CONFIG_COUNT: "1"\n'
            "  GIT_CONFIG_KEY_0: diff.external\n"
            "  GIT_CONFIG_VALUE_0: ${{ github.workspace }}/attack/external-diff\n"
            "  GIT_EXTERNAL_DIFF: ${{ github.workspace }}/attack/external-diff",
        ),
        (
            "workflow Git object, replacement, and executable authority injected",
            "  GIT_OBJECT_DIRECTORY: ${{ github.workspace }}/attack/objects\n"
            "  GIT_ALTERNATE_OBJECT_DIRECTORIES: "
            "${{ github.workspace }}/attack/alternate-objects\n"
            "  GIT_EXEC_PATH: ${{ github.workspace }}/attack\n"
            "  GIT_REPLACE_REF_BASE: refs/replace",
        ),
    )
    path_attack_workflow = ""
    for label, injected_environment in workflow_environment_attacks:
        mutant_workflow = ci_workflow.replace(
            workflow_environment_needle,
            f"{workflow_environment_needle}\n{injected_environment}",
            1,
        )
        if not path_attack_workflow:
            path_attack_workflow = mutant_workflow
        expect_assertion(
            label,
            "workflow header must exactly match the closed-form",
            lambda mutant_workflow=mutant_workflow: assert_docs_only_classifier_guard(
                mutant_workflow
            ),
        )

    # The exact PATH attack remains a structurally valid member of the old
    # census/cache/consumer contracts. Only the workflow-level process contract
    # should reject it, and the runtime proof below must remain safe if that
    # header defense is accidentally bypassed.
    path_attack_sources = dict(workflow_sources)
    path_attack_sources[WORKFLOWS / "ci.yml"] = path_attack_workflow
    assert_workflow_job_census(path_attack_sources)
    assert_rust_cache_steps(path_attack_sources)
    assert_check_consumer_authority(path_attack_workflow)
    with tempfile.TemporaryDirectory() as directory:
        (
            fixture,
            code_base_sha,
            code_head_sha,
            hostile_environment,
            execution_markers,
        ) = create_classifier_authority_attack_fixture(
            Path(directory),
            ci_workflow,
            path_attack_workflow,
        )
        fake_git = subprocess.run(
            ["git", "diff", "--name-only", f"{code_base_sha}...{code_head_sha}"],
            cwd=fixture,
            env={"PATH": hostile_environment["PATH"]},
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if fake_git.returncode != 0 or fake_git.stdout.splitlines() != [
            "docs/decoy.md"
        ]:
            raise AssertionError(
                "workflow PATH attack fixture did not substitute its executable: "
                f"{fake_git.stdout}{fake_git.stderr}"
            )

        result, outputs = execute_docs_only_classifier(
            classifier,
            cwd=fixture,
            environment_overrides={
                **hostile_environment,
                "EVENT_NAME": "pull_request",
                "BASE_SHA": code_base_sha,
                "HEAD_SHA": code_head_sha,
                "WORKSPACE": str(fixture),
            },
        )
        assert_classifier_execution_code_bearing(
            "absolute environment-clean Git rejects workflow PATH and Git authority",
            result,
            outputs,
            changed_paths=(".github/workflows/ci.yml", "src/lib.rs"),
        )
        executed_markers = [marker for marker in execution_markers if marker.exists()]
        if executed_markers:
            raise AssertionError(
                "classifier executed an inherited external diff or textconv: "
                f"{executed_markers}"
            )

    environment_binding = (
        "          PATH: /usr/bin:/bin\n"
        '          BASH_ENV: ""\n'
        '          ENV: ""\n'
        '          LD_AUDIT: ""\n'
        "          LD_LIBRARY_PATH: /dev/null\n"
        '          LD_PRELOAD: ""\n'
        "          WORKSPACE: ${{ github.workspace }}\n"
        "          EVENT_NAME: ${{ github.event_name }}\n"
        "          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n"
        "          HEAD_SHA: ${{ github.event.pull_request.head.sha }}"
    )
    if classifier.count(environment_binding) != 1:
        raise AssertionError(
            "diff classifier falsification could not identify its environment binding"
        )
    with tempfile.TemporaryDirectory() as directory:
        fixture, base_sha, head_sha = create_docs_only_git_fixture(Path(directory))
        fixed_range_binding = (
            "          PATH: /usr/bin:/bin\n"
            '          BASH_ENV: ""\n'
            '          ENV: ""\n'
            '          LD_AUDIT: ""\n'
            "          LD_LIBRARY_PATH: /dev/null\n"
            '          LD_PRELOAD: ""\n'
            f"          WORKSPACE: {fixture!s}\n"
            "          EVENT_NAME: pull_request\n"
            f"          BASE_SHA: {base_sha}\n"
            f"          HEAD_SHA: {head_sha}"
        )
        fixed_range = classifier.replace(
            environment_binding,
            fixed_range_binding,
            1,
        )
        expect_assertion(
            "push classifier bound to a fixed historical docs-only range",
            "exactly match the closed-form docs_only authority contract",
            lambda: assert_docs_only_classifier_guard(
                ci_workflow.replace(classifier, fixed_range, 1)
            ),
        )
        result, outputs = execute_docs_only_classifier(
            fixed_range,
            cwd=fixture,
            environment_overrides={
                "EVENT_NAME": "pull_request",
                "BASE_SHA": base_sha,
                "HEAD_SHA": head_sha,
                "WORKSPACE": str(fixture),
            },
        )
        assert_classifier_execution_won(
            "push classifier bound to a fixed historical docs-only range",
            result,
            outputs,
            changed_path="docs/release-bot.md",
        )

        hostile_bash_env = Path(directory) / "hostile-bash-env"
        hostile_bash_env.write_text(
            f"EVENT_NAME=pull_request\nBASE_SHA={base_sha}\nHEAD_SHA={head_sha}\n",
            encoding="utf-8",
        )
        bash_env_mutant = classifier.replace(
            '          BASH_ENV: ""',
            f'          BASH_ENV: "{hostile_bash_env}"',
            1,
        )
        expect_assertion(
            "classifier shell startup overridden through BASH_ENV",
            "exactly match the closed-form docs_only authority contract",
            lambda: assert_docs_only_classifier_guard(
                ci_workflow.replace(classifier, bash_env_mutant, 1)
            ),
        )
        result, outputs = execute_docs_only_classifier(
            bash_env_mutant,
            cwd=fixture,
            environment_overrides={"BASH_ENV": str(hostile_bash_env)},
        )
        assert_classifier_execution_failed_closed(
            "privileged classifier shell ignores BASH_ENV startup injection",
            result,
            outputs,
        )

        shell_line = (
            "        shell: /usr/bin/bash --noprofile --norc -p -e -u -o pipefail {0}"
        )
        unprivileged_shell = classifier.replace(
            shell_line,
            "        shell: /usr/bin/bash --noprofile --norc -e -u -o pipefail {0}",
            1,
        )
        expect_assertion(
            "classifier shell drops privileged startup",
            "exactly match the closed-form docs_only authority contract",
            lambda: assert_docs_only_classifier_guard(
                ci_workflow.replace(classifier, unprivileged_shell, 1)
            ),
        )
        hostile_functions = {
            "BASH_FUNC_echo%%": (
                '() { builtin echo "docs_only=true" >> "$GITHUB_OUTPUT"; }'
            ),
        }
        result, outputs = execute_docs_only_classifier(
            classifier,
            cwd=fixture,
            environment_overrides=hostile_functions,
        )
        assert_classifier_execution_failed_closed(
            "privileged classifier rejects an inherited output function",
            result,
            outputs,
        )
        result, outputs = execute_docs_only_classifier(
            unprivileged_shell,
            cwd=fixture,
            environment_overrides=hostile_functions,
            privileged=False,
        )
        assert_classifier_execution_won(
            "unprivileged classifier imports a hostile output function",
            result,
            outputs,
        )

        hostile_shell = classifier.replace(
            shell_line,
            "        shell: bash --noprofile --norc -c "
            "'exec env EVENT_NAME=pull_request "
            f"BASE_SHA={base_sha} HEAD_SHA={head_sha} BASH_ENV= "
            '/usr/bin/bash --noprofile --norc "$1"\' wrapper {0}',
            1,
        )
        expect_assertion(
            "classifier custom shell overrides event and SHA authority",
            "exactly match the closed-form docs_only authority contract",
            lambda: assert_docs_only_classifier_guard(
                ci_workflow.replace(classifier, hostile_shell, 1)
            ),
        )
        result, outputs = execute_docs_only_classifier(
            hostile_shell,
            cwd=fixture,
            environment_overrides={
                "FIXED_BASE_SHA": base_sha,
                "FIXED_HEAD_SHA": head_sha,
            },
            shell_wrapper=(
                'exec env EVENT_NAME=pull_request BASE_SHA="$FIXED_BASE_SHA" '
                'HEAD_SHA="$FIXED_HEAD_SHA" BASH_ENV= '
                'bash --noprofile --norc "$1"'
            ),
        )
        assert_classifier_execution_won(
            "classifier custom shell overrides event and SHA authority",
            result,
            outputs,
            changed_path="docs/release-bot.md",
        )

    classifier_falsification_needle = (
        '          fi\n          echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"'
    )
    if classifier.count(classifier_falsification_needle) != 1:
        raise AssertionError(
            "diff classifier falsification could not identify the outer guard boundary"
        )
    truthy_after_guard = classifier.replace(
        classifier_falsification_needle,
        "          fi\n"
        "          docs_only=true\n"
        '          echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"',
        1,
    )
    assert_classifier_bypass_rejected(
        "docs_only=true after the matching pull_request fi",
        ci_workflow.replace(classifier, truthy_after_guard, 1),
    )
    for label, command in (
        ("single-quoted docs_only assignment", "docs_only='true'"),
        ("double-quoted docs_only assignment", 'docs_only="true"'),
        ("indirect printf docs_only assignment", "printf -v docs_only true"),
        (
            "computed-name docs_only assignment",
            'name=docs_$(printf only); printf -v "$name" true',
        ),
        ("eval-computed docs_only assignment", "eval 'docs_'only=true"),
        ("quoted-hash docs_only assignment", "printf '#'; docs_only=true"),
    ):
        bypass = classifier.replace(
            classifier_falsification_needle,
            f"          fi\n          {command}\n"
            '          echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"',
            1,
        )
        assert_classifier_bypass_rejected(
            label,
            ci_workflow.replace(classifier, bypass, 1),
        )
    nameref_bypass = classifier.replace(
        classifier_falsification_needle,
        "          fi\n"
        '          name=docs_only; declare -n ref="$name"; ref=true\n'
        '          echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"',
        1,
    )
    assert_classifier_bypass_rejected(
        "nameref docs_only assignment",
        ci_workflow.replace(classifier, nameref_bypass, 1),
        execute=bash_supports_nameref(),
    )
    duplicate_computed_output = classifier.replace(
        classifier_falsification_needle,
        "          fi\n"
        '          echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"\n'
        "          name=docs_$(printf only); "
        'printf \'%s=true\\n\' "$name" >> "$GITHUB_OUTPUT"',
        1,
    )
    assert_classifier_bypass_rejected(
        "duplicate computed docs_only output",
        ci_workflow.replace(classifier, duplicate_computed_output, 1),
    )
    comment_only = classifier.replace(
        classifier_falsification_needle,
        "          fi\n"
        "          # docs_only='true' is intentionally ignored in comments\n"
        '          echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"',
        1,
    )
    assert_docs_only_classifier_guard(ci_workflow.replace(classifier, comment_only, 1))

    release_tag = RELEASE_TAG.read_text(encoding="utf-8")
    release_tag_header = release_tag.split("\njobs:", 1)[0]
    require(
        release_tag_header,
        "permissions:\n  contents: read\n  checks: read\n  actions: read",
        "release-tag read-only check and workflow provenance access",
    )
    for forbidden_permission in (
        "contents: write",
        "checks: write",
        "actions: write",
    ):
        if forbidden_permission in release_tag_header:
            raise AssertionError(
                "release-tag workflow token must remain read-only: "
                f"{forbidden_permission}"
            )
    for policy in (
        "REQUIRED_CHECKS: |",
        "Check & Test (ubuntu-latest)",
        "Check & Test (macos-latest)",
        "DCO Sign-off",
        "cargo-deny",
        "gitleaks (full history)",
        "Windows installer + vector release build",
        "missing required check: {name}",
        "required check not green: {name}",
        "ambiguous required check: {name}",
        "required check workflow provenance mismatch: {name}",
        "actions: read",
        "filter=all",
        'app_slug: (.app.slug // "")',
        "head_branch: .head_branch",
        "check_suite_id: .check_suite.id",
        "workflow_id: .workflow_id",
        "head_sha: .head_sha",
        "workflow_runs.ndjson",
        "current_run.json",
    ):
        require(release_tag, policy, "release tag required-check gate")
    for policy in (
        'skippable_required = {"DCO Sign-off"}',
        'non_failing_optional = {"success", "skipped", "neutral"}',
        "if name in skippable_required",
        'else {"success"}',
        'run["conclusion"] not in allowed_conclusions',
    ):
        require(release_tag, policy, "per-check release conclusion policy")

    release_gate = release_check_gate_source(release_tag)
    positive_fixture = execute_release_check_gate(release_gate, {})
    if positive_fixture.returncode != 0:
        raise AssertionError(
            "current release check provenance fixture was rejected: "
            f"{positive_fixture.stdout}{positive_fixture.stderr}"
        )
    for accepted_conclusion in ("success", "skipped"):
        assert_release_check_accepted(
            release_gate,
            "DCO Sign-off",
            accepted_conclusion,
        )
    for check_name in REQUIRED_RELEASE_CHECKS:
        if check_name == "DCO Sign-off":
            continue
        for rejected_conclusion in ("skipped", "neutral"):
            assert_release_check_rejected(
                release_gate,
                check_name,
                rejected_conclusion,
            )
    assert_release_check_rejected(
        release_gate,
        "DCO Sign-off",
        "neutral",
    )

    def required_check_fixture(
        check_runs: list[dict[str, object]],
        name: str,
    ) -> dict[str, object]:
        matches = [run for run in check_runs if run["name"] == name]
        if len(matches) != 1:
            raise AssertionError(
                f"release gate fixture requires one {name} check, got {len(matches)}"
            )
        return matches[0]

    def workflow_fixture(
        workflow_runs: list[dict[str, object]],
        suite_id: object,
    ) -> dict[str, object]:
        matches = [run for run in workflow_runs if run["check_suite_id"] == suite_id]
        if len(matches) != 1:
            raise AssertionError(
                "release gate fixture requires one workflow for suite "
                f"{suite_id}, got {len(matches)}"
            )
        return matches[0]

    def add_prior_release_tag_refusal(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        workflow_runs.append(
            {
                "id": 8_000,
                "workflow_id": RELEASE_TAG_WORKFLOW_ID,
                "path": ".github/workflows/release-tag.yml",
                "event": "repository_dispatch",
                "head_branch": "main",
                "head_sha": RELEASE_GATE_FIXTURE_SHA,
                "status": "completed",
                "conclusion": "failure",
                "check_suite_id": 105,
            }
        )
        check_runs.append(
            {
                "name": "Mint release tag",
                "status": "completed",
                "conclusion": "failure",
                "id": 8_001,
                "app_id": GITHUB_ACTIONS_APP_ID,
                "app_slug": "github-actions",
                "check_suite_id": 105,
                "head_sha": RELEASE_GATE_FIXTURE_SHA,
            }
        )

    retry_fixture = execute_release_check_gate(
        release_gate,
        {},
        mutate_fixture=add_prior_release_tag_refusal,
    )
    if retry_fixture.returncode != 0:
        raise AssertionError(
            "prior refusal from the exact release-tag workflow blocked a retry: "
            f"{retry_fixture.stdout}{retry_fixture.stderr}"
        )

    def add_external_mint_failure(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        workflow_runs.append(
            {
                "id": 8_100,
                "workflow_id": 999,
                "path": ".github/workflows/mint-name-spoof.yml",
                "event": "push",
                "head_branch": "main",
                "head_sha": RELEASE_GATE_FIXTURE_SHA,
                "status": "completed",
                "conclusion": "failure",
                "check_suite_id": 106,
            }
        )
        check_runs.append(
            {
                "name": "Mint release tag",
                "status": "completed",
                "conclusion": "failure",
                "id": 8_101,
                "app_id": GITHUB_ACTIONS_APP_ID,
                "app_slug": "github-actions",
                "check_suite_id": 106,
                "head_sha": RELEASE_GATE_FIXTURE_SHA,
            }
        )

    assert_release_gate_fixture_rejected(
        release_gate,
        "same-name tag check from another workflow is not self-excluded",
        "release-tag job name claimed by another producer: Mint release tag",
        add_external_mint_failure,
    )

    def add_external_mint_success(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        current_run: dict[str, object],
    ) -> None:
        """A green namesake is the same authority conflict as a red one."""

        add_external_mint_failure(check_runs, workflow_runs, current_run)
        for run in check_runs:
            if run["name"] == "Mint release tag" and run["id"] == 8_101:
                run["conclusion"] = "success"

    assert_release_gate_fixture_rejected(
        release_gate,
        "green same-name tag check from another workflow is admitted",
        "release-tag job name claimed by another producer: Mint release tag",
        add_external_mint_success,
    )

    def add_higher_id_success_collision(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        real = required_check_fixture(
            check_runs,
            "Check & Test (ubuntu-latest)",
        )
        real["conclusion"] = "failure"
        spoof = real.copy()
        spoof.update(
            {
                "id": 10_000,
                "conclusion": "success",
                "check_suite_id": 999,
            }
        )
        check_runs.append(spoof)
        workflow_runs.append(
            {
                "id": 9_999,
                "workflow_id": 999,
                "path": ".github/workflows/required-context-spoof.yaml",
                "event": "push",
                "head_branch": "main",
                "head_sha": RELEASE_GATE_FIXTURE_SHA,
                "status": "completed",
                "conclusion": "success",
                "check_suite_id": 999,
            }
        )

    assert_release_gate_fixture_rejected(
        release_gate,
        "higher-ID same-name success masks a failed required producer",
        (
            "required check workflow provenance mismatch: "
            "Check & Test (ubuntu-latest)"
        ),
        add_higher_id_success_collision,
    )

    def add_duplicate_success(
        check_runs: list[dict[str, object]],
        _workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        duplicate = required_check_fixture(check_runs, "cargo-deny").copy()
        duplicate["id"] = 10_001
        check_runs.append(duplicate)

    assert_release_gate_fixture_rejected(
        release_gate,
        "two successful check-runs claim one required context",
        "ambiguous required check: cargo-deny (2 check-runs under one provenance)",
        add_duplicate_success,
    )

    def add_landing_push_producer(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """The landing push republishes every context the queue already proved.

        Both builds carry the same sha because the queue's speculative commit
        IS the squash that lands. Crediting both would make every context
        ambiguous, so the queue build is the authority and this one is
        corroboration: judged when it has concluded, never waited for.
        """

        for path, suite in (
            (".github/workflows/ci.yml", 301),
            (".github/workflows/sast.yml", 302),
            (".github/workflows/secret-scan.yml", 303),
        ):
            source = workflow_fixture(
                workflow_runs,
                next(
                    run["check_suite_id"]
                    for run in workflow_runs
                    if run.get("path") == path
                ),
            ).copy()
            source.update(
                {
                    "id": suite * 10,
                    "event": "push",
                    "head_branch": "main",
                    "check_suite_id": suite,
                }
            )
            workflow_runs.append(source)
        for name in REQUIRED_RELEASE_CHECKS:
            _, workflow_path, _ = REQUIRED_RELEASE_CHECK_PROVENANCE[name]
            push_copy = required_check_fixture(check_runs, name).copy()
            push_copy.update(
                {
                    "id": 20_000 + len(check_runs),
                    "check_suite_id": {
                        ".github/workflows/ci.yml": 301,
                        ".github/workflows/sast.yml": 302,
                        ".github/workflows/secret-scan.yml": 303,
                    }[workflow_path],
                }
            )
            check_runs.append(push_copy)

    merge_queue_fixture = execute_release_check_gate(
        release_gate,
        {},
        mutate_fixture=add_landing_push_producer,
    )
    if merge_queue_fixture.returncode != 0:
        raise AssertionError(
            "a merge-queue landing's duplicate contexts blocked the release: "
            f"{merge_queue_fixture.stdout}{merge_queue_fixture.stderr}"
        )
    if "corroborated by the other admitted build" not in (
        merge_queue_fixture.stdout + merge_queue_fixture.stderr
    ):
        raise AssertionError(
            "the landing push's verdict on an already-proven tree was neither "
            "judged nor reported: "
            f"{merge_queue_fixture.stdout}{merge_queue_fixture.stderr}"
        )

    def red_landing_push_corroboration(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        current_run: dict[str, object],
    ) -> None:
        """The other build of this exact tree failed the same required context."""

        add_landing_push_producer(check_runs, workflow_runs, current_run)
        for run in check_runs:
            if run["name"] == "cargo-deny" and run["check_suite_id"] == 302:
                run["conclusion"] = "failure"

    assert_release_gate_fixture_rejected(
        release_gate,
        "the landing push failed a context the queue passed",
        "corroborating required check not green: cargo-deny (conclusion=failure",
        red_landing_push_corroboration,
    )

    def unfinished_landing_push_corroboration(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        current_run: dict[str, object],
    ) -> None:
        """The usual case: the landing push is still running when the mint fires."""

        add_landing_push_producer(check_runs, workflow_runs, current_run)
        workflow_fixture(workflow_runs, 301).update(
            {"status": "in_progress", "conclusion": None}
        )
        for run in check_runs:
            if run["check_suite_id"] == 301:
                run.update({"status": "in_progress", "conclusion": None})

    assert_release_gate_admits(
        release_gate,
        "the landing push is still running when the queue's proof is complete",
        (
            "not waiting for the other admitted build of a required context: "
            "Check & Test (ubuntu-latest) (status=in_progress",
        ),
        unfinished_landing_push_corroboration,
    )

    def skipped_queue_leg(
        check_runs: list[dict[str, object]],
        _workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """The queue build skipped a leg the mint now keys off.

        This is the pre-rekey shape of the merge_group build, and it is the
        defect the rekey would reintroduce if the Windows leg were admitted as
        proof while the queue kept skipping it.
        """

        required_check_fixture(
            check_runs,
            "Windows installer + vector release build",
        )["conclusion"] = "skipped"

    assert_release_gate_fixture_rejected(
        release_gate,
        "the queue's skipped Windows leg is admitted as release evidence",
        (
            "required check not green: Windows installer + vector release build "
            "(conclusion=skipped)"
        ),
        skipped_queue_leg,
    )

    def absent_queue_leg(
        check_runs: list[dict[str, object]],
        _workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """The queue build published no such context at all."""

        check_runs[:] = [
            run
            for run in check_runs
            if run["name"] != "Windows installer + vector release build"
        ]

    absent_leg_fixture = execute_release_check_gate(
        release_gate,
        {},
        mutate_fixture=absent_queue_leg,
    )
    if absent_leg_fixture.returncode != 2:
        raise AssertionError(
            "a required context the admitted build never published no longer "
            "holds the mint for retry: "
            f"rc={absent_leg_fixture.returncode} "
            f"{absent_leg_fixture.stdout}{absent_leg_fixture.stderr}"
        )
    if "missing required check: Windows installer + vector release build" not in (
        absent_leg_fixture.stdout + absent_leg_fixture.stderr
    ):
        raise AssertionError(
            "absent queue evidence was held without naming the missing "
            f"producer: {absent_leg_fixture.stdout}{absent_leg_fixture.stderr}"
        )

    def queue_ref_names_another_base(
        _check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """The queue built a tree whose parent is not this release's parent."""

        workflow_fixture(workflow_runs, 101)["head_branch"] = (
            "gh-readonly-queue/main/pr-958-" + "9" * 40
        )

    assert_release_gate_fixture_rejected(
        release_gate,
        "the queue build credited to this release was built on another base",
        "merge-group evidence proved a different tree",
        queue_ref_names_another_base,
    )

    # The other half of that equality, mutated on the git side. The parent is
    # read from the protected history this job checked out rather than from the
    # endpoint being judged, so this proves the assertion consults it at all
    # instead of comparing the API's answer with itself.
    wrong_parent_fixture = execute_release_check_gate(
        release_gate,
        {},
        parent_sha="9" * 40,
    )
    if wrong_parent_fixture.returncode == 0:
        raise AssertionError(
            "a queue build was credited to a release whose first parent is not "
            "the base that build was made on"
        )
    if "merge-group evidence proved a different tree" not in (
        wrong_parent_fixture.stdout + wrong_parent_fixture.stderr
    ):
        raise AssertionError(
            "the sha-identity refusal fired for the wrong reason: "
            f"{wrong_parent_fixture.stdout}{wrong_parent_fixture.stderr}"
        )

    def queue_build_proved_another_sha(
        _check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        workflow_fixture(workflow_runs, 101)["head_sha"] = "7" * 40

    assert_release_gate_fixture_rejected(
        release_gate,
        "the queue build credited to this release proved another sha",
        "merge-group evidence sha mismatch",
        queue_build_proved_another_sha,
    )

    def queue_ref_is_an_ordinary_branch(
        _check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """A branch that merely looks like queue evidence cannot nominate itself."""

        workflow_fixture(workflow_runs, 101)["head_branch"] = "attacker/queue-lookalike"

    assert_release_gate_fixture_rejected(
        release_gate,
        "an ordinary branch claims to be the queue build",
        "merge-group evidence is not on a merge-queue ref",
        queue_ref_is_an_ordinary_branch,
    )

    def two_uncancelled_queue_builds(
        _check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        rebuild = workflow_fixture(workflow_runs, 101).copy()
        rebuild.update({"id": 1_101, "check_suite_id": 401})
        workflow_runs.append(rebuild)

    assert_release_gate_fixture_rejected(
        release_gate,
        "two uncancelled queue builds of one sha are collapsed by recency",
        "ambiguous merge-group evidence",
        two_uncancelled_queue_builds,
    )

    def superseded_queue_build(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """A speculative group the queue cancelled and rebatched gated nothing."""

        cancelled = workflow_fixture(workflow_runs, 101).copy()
        cancelled.update(
            {"id": 1_102, "check_suite_id": 402, "conclusion": "cancelled"}
        )
        workflow_runs.append(cancelled)
        check_runs.append(
            {
                "name": "Check & Test (ubuntu-latest)",
                "status": "completed",
                "conclusion": "cancelled",
                "id": 40_201,
                "app_id": GITHUB_ACTIONS_APP_ID,
                "app_slug": "github-actions",
                "check_suite_id": 402,
                "head_sha": RELEASE_GATE_FIXTURE_SHA,
            }
        )

    superseded_fixture = execute_release_check_gate(
        release_gate,
        {},
        mutate_fixture=superseded_queue_build,
    )
    if superseded_fixture.returncode != 0:
        raise AssertionError(
            "a cancelled superseded queue group was read as a competing "
            f"authority: {superseded_fixture.stdout}{superseded_fixture.stderr}"
        )

    def no_queue_build_at_all(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        current_run: dict[str, object],
    ) -> None:
        """A commit that reached main without a queue build is still releasable.

        The landing push is the fallback authority, which is exactly the
        evidence the mint used before it was rekeyed. Removing that path would
        make one queue outage an unreleasable repository.
        """

        add_landing_push_producer(check_runs, workflow_runs, current_run)
        queue_suites = {101, 102, 103, 107}
        check_runs[:] = [
            run for run in check_runs if run["check_suite_id"] not in queue_suites
        ]
        workflow_runs[:] = [
            run
            for run in workflow_runs
            if run.get("check_suite_id") not in queue_suites
        ]

    assert_release_gate_admits(
        release_gate,
        "a landing with no queue build at all",
        (
            "admitting on landing-push evidence: no merge-group build exists at",
        ),
        no_queue_build_at_all,
    )

    def ruleset_context_nothing_publishes(
        check_runs: list[dict[str, object]],
        _workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """Ruleset 19746451 still gates a context no producer publishes.

        Nothing in this repository can read that ruleset, and the queue's own
        symptom is a wait with every visible check green, so the mint reading
        its reviewed mirror against the sha is the only place this becomes a
        stated failure.
        """

        check_runs[:] = [
            run for run in check_runs if run["name"] != "PR text hygiene"
        ]

    assert_release_gate_fixture_rejected(
        release_gate,
        "a ruleset-gated context that no admitted build published",
        "ruleset-required context has no admitted build at this sha: PR text hygiene",
        ruleset_context_nothing_publishes,
    )

    def ruleset_context_is_red(
        check_runs: list[dict[str, object]],
        _workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        required_check_fixture(check_runs, "PR text hygiene")["conclusion"] = "failure"

    assert_release_gate_fixture_rejected(
        release_gate,
        "a ruleset-gated context that the admitted build failed",
        "ruleset-required context not green: PR text hygiene (conclusion=failure)",
        ruleset_context_is_red,
    )

    def non_required_check(
        name: str,
        suite_id: int,
        check_id: int,
        *,
        status: str = "completed",
        conclusion: str | None = "failure",
    ) -> dict[str, object]:
        return {
            "name": name,
            "status": status,
            "conclusion": conclusion,
            "id": check_id,
            "app_id": GITHUB_ACTIONS_APP_ID,
            "app_slug": "github-actions",
            "check_suite_id": suite_id,
            "head_sha": RELEASE_GATE_FIXTURE_SHA,
        }

    def add_red_advisory_in_the_queue_build(
        check_runs: list[dict[str, object]],
        _workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """An advisory job reds inside the build the mint now keys off.

        Before the rekey this was discounted, because a merge_group job the
        queue never waited for concluded after the merge having gated nothing.
        The queue's build is now this release's evidence, so a red in it is
        the same class of fact as a red in the landing push: admitted over,
        and announced. The disclosure got wider here rather than darker, which
        is the property the rekey had to preserve.
        """

        check_runs.append(
            non_required_check("Windows authority tests", 101, 30_001)
        )

    assert_release_gate_admits(
        release_gate,
        "an advisory job reds inside the admitted queue build",
        (
            "admitting over a red check no required context covers: "
            "Windows authority tests (conclusion=failure",
        ),
        add_red_advisory_in_the_queue_build,
    )

    def add_red_queue_only_job(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """A red job from another queue entry's build of this same sha."""

        workflow_runs.append(
            {
                "id": 30_100,
                "workflow_id": 400_200,
                "path": ".github/workflows/queue-only.yml",
                "event": "merge_group",
                "head_branch": "gh-readonly-queue/main/pr-2-" + "0" * 40,
                "head_sha": RELEASE_GATE_FIXTURE_SHA,
                "status": "completed",
                "conclusion": "failure",
                "check_suite_id": 302,
            }
        )
        check_runs.append(non_required_check("Queue-only smoke", 302, 30_101))

    assert_release_gate_admits(
        release_gate,
        "a red job from a build neither tier admits",
        (
            "discounting a red check that is not this release's evidence: "
            "Queue-only smoke",
            "it has no admitted build at this sha",
        ),
        add_red_queue_only_job,
    )

    def add_red_non_required_push_job(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """A registry blip reds a landing-push job no ruleset requires."""

        workflow_runs.append(
            {
                "id": 31_000,
                "workflow_id": 400_300,
                "path": ".github/workflows/docker.yml",
                "event": "push",
                "head_branch": "main",
                "head_sha": RELEASE_GATE_FIXTURE_SHA,
                "status": "completed",
                "conclusion": "failure",
                "check_suite_id": 303,
            }
        )
        check_runs.append(
            non_required_check("Docker Image Build (no push)", 303, 31_001)
        )

    assert_release_gate_admits(
        release_gate,
        "a red landing-push check that no required context covers",
        (
            "admitting over a red check no required context covers: "
            "Docker Image Build (no push) (conclusion=failure",
        ),
        add_red_non_required_push_job,
    )

    def red_non_required_job_inside_required_producer(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """A red advisory job turns its whole required producer's run red."""

        ci_suite = required_check_fixture(
            check_runs,
            "Check & Test (ubuntu-latest)",
        )["check_suite_id"]
        workflow_fixture(workflow_runs, ci_suite)["conclusion"] = "failure"
        check_runs.append(non_required_check("Code Coverage", ci_suite, 32_001))

    assert_release_gate_admits(
        release_gate,
        "a red advisory job inside the workflow that produces required contexts",
        (
            "admitting over a producing run that concluded failure: "
            ".github/workflows/ci.yml run 1001",
            "admitting over a red check no required context covers: "
            "Code Coverage (conclusion=failure",
        ),
        red_non_required_job_inside_required_producer,
    )

    def unfinished_non_required_check(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """An advisory job still running when every required context is green."""

        ci_suite = required_check_fixture(
            check_runs,
            "Check & Test (ubuntu-latest)",
        )["check_suite_id"]
        # This coupling is mandatory in the real Actions API: while any sibling
        # job is in progress, its producer workflow cannot be completed/success.
        # Leaving the fixture completed creates an impossible state and lets the
        # gate keep waiting on the aggregate without the test noticing.
        workflow_fixture(workflow_runs, ci_suite).update(
            {"status": "in_progress", "conclusion": None}
        )
        check_runs.append(
            non_required_check(
                "npm launcher tests",
                ci_suite,
                33_001,
                status="in_progress",
                conclusion=None,
            )
        )

    assert_release_gate_admits(
        release_gate,
        "an unfinished advisory check no required context covers",
        (
            "admitting over a producing run that is still in_progress: "
            ".github/workflows/ci.yml run 1001",
            "not waiting for a check no required context covers: "
            "npm launcher tests (status=in_progress)",
        ),
        unfinished_non_required_check,
    )

    def unfinished_required_check(
        check_runs: list[dict[str, object]],
        _workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        required_check_fixture(check_runs, "cargo-deny").update(
            {"status": "in_progress", "conclusion": None}
        )

    unfinished_required_fixture = execute_release_check_gate(
        release_gate,
        {},
        mutate_fixture=unfinished_required_check,
    )
    if unfinished_required_fixture.returncode != 2:
        raise AssertionError(
            "an unfinished required context no longer holds the mint for retry: "
            f"rc={unfinished_required_fixture.returncode} "
            f"{unfinished_required_fixture.stdout}"
            f"{unfinished_required_fixture.stderr}"
        )

    def change_required_workflow_path(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        check = required_check_fixture(check_runs, "cargo-deny")
        workflow = workflow_fixture(workflow_runs, check["check_suite_id"])
        workflow["path"] = ".github/workflows/required-context-spoof.yaml"

    assert_release_gate_fixture_rejected(
        release_gate,
        "required check comes from the wrong workflow path",
        "required check workflow provenance mismatch: cargo-deny",
        change_required_workflow_path,
    )

    def change_required_workflow_id(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        check = required_check_fixture(check_runs, "cargo-deny")
        workflow = workflow_fixture(workflow_runs, check["check_suite_id"])
        workflow["workflow_id"] = 999

    assert_release_gate_fixture_rejected(
        release_gate,
        "required check comes from the wrong workflow identity",
        "required check workflow provenance mismatch: cargo-deny",
        change_required_workflow_id,
    )

    def change_required_workflow_event(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        check = required_check_fixture(
            check_runs,
            "gitleaks (full history)",
        )
        workflow = workflow_fixture(workflow_runs, check["check_suite_id"])
        workflow["event"] = "workflow_run"

    assert_release_gate_fixture_rejected(
        release_gate,
        "required check comes from the wrong workflow event",
        "required check workflow provenance mismatch: gitleaks (full history)",
        change_required_workflow_event,
    )

    def change_required_check_head(
        check_runs: list[dict[str, object]],
        _workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        check = required_check_fixture(
            check_runs,
            "Windows installer + vector release build",
        )
        check["head_sha"] = "2" * 40

    assert_release_gate_fixture_rejected(
        release_gate,
        "required check is attached to the wrong head sha",
        (
            "required check has wrong head sha: "
            "Windows installer + vector release build"
        ),
        change_required_check_head,
    )

    def change_required_workflow_head(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        # Deliberately not a ci.yml context. ci.yml's run is the queue anchor,
        # and moving its head sha is refused earlier and more specifically by
        # the sha-identity assertion, which `queue_build_proved_another_sha`
        # covers. This case is the per-context provenance path, which every
        # non-anchor producer still has to be judged against.
        check = required_check_fixture(check_runs, "cargo-deny")
        workflow = workflow_fixture(workflow_runs, check["check_suite_id"])
        workflow["head_sha"] = "3" * 40

    assert_release_gate_fixture_rejected(
        release_gate,
        "required workflow run is attached to the wrong head sha",
        "required check workflow provenance mismatch: cargo-deny",
        change_required_workflow_head,
    )

    def change_required_check_app(
        check_runs: list[dict[str, object]],
        _workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        check = required_check_fixture(check_runs, "DCO Sign-off")
        check["app_slug"] = "unreviewed-checks-app"

    assert_release_gate_fixture_rejected(
        release_gate,
        "required check comes from a different checks app",
        "required check name claimed by another app: DCO Sign-off",
        change_required_check_app,
    )

    # Cargo caches are restore-anywhere, save-from-main-only, so one reusable
    # warm entry per job stays alive under the repository cache budget instead
    # of being evicted by per-pull-request entries no other run can read.
    #
    # The justification is budget, NOT trust. A run on refs/heads/main can only
    # restore entries scoped to refs/heads/main, so GitHub already prevents a
    # fork or pull request from planting a cache a trusted run would restore;
    # save-if does not create that boundary. Do not reason about a related
    # change as though it did.
    #
    # Scope: this covers Swatinem/rust-cache uses only. Three actions/cache
    # uses remain deliberately outside it: the windows-installer and coverage
    # jobs are admitted only from main, while fuzz may still write a cache on a
    # qualifying pull request. This is not a repository-wide no-PR-writes
    # invariant.
    assert_rust_cache_steps(workflow_sources)
    assert_required_context_action_pins(workflow_sources)
    assert_tag_readback_retries(release_tag)
    assert_required_check_set_is_single_sourced(release_tag)
    assert_ruleset_mirror_stays_a_superset(release_tag)
    for label, old_name, new_name in (
        (
            "the mirror is synced down to a thinned live ruleset",
            "            Falsify guards\n            Feature permutation tests (ubuntu-latest)\n",
            "",
        ),
        (
            "one name is dropped from the mirror alone",
            "            Windows installer + vector release build\n            PR text hygiene\n",
            "            PR text hygiene\n",
        ),
    ):
        mirror_start = release_tag.index("          RULESET_REQUIRED_CHECKS: |")
        head, mirror = release_tag[:mirror_start], release_tag[mirror_start:]
        if mirror.count(old_name) != 1:
            raise AssertionError(
                f"ruleset mirror falsification could not identify {label}"
            )
        expect_assertion(
            label,
            "must stay a superset",
            lambda mutant=head + mirror.replace(old_name, new_name, 1): (
                assert_ruleset_mirror_stays_a_superset(mutant)
            ),
        )
    assert_soft_decline_is_legible(release_tag)
    assert_recovery_escalation_classifies(
        RELEASE_RECOVERY.read_text(encoding="utf-8")
    )
    assert_recovery_stops_on_repeated_signature(
        RELEASE_RECOVERY.read_text(encoding="utf-8")
    )
    assert_mint_trigger_survives_advisory_flakes(release_tag)
    assert_release_pr_ci_scope_cannot_widen(ci_workflow)
    # This guard has to be able to fail before it is worth carrying, and it
    # currently constrains nothing in the tree, so falsify it against the two
    # shapes a loose carve-out actually takes.
    release_pr_job_start = ci_workflow.index("  npm-launchers:")
    release_pr_job_end = ci_workflow.index("\n  windows-authority-tests:")
    release_pr_job = ci_workflow[release_pr_job_start:release_pr_job_end]
    for label, condition, expected in (
        (
            "a release-PR carve-out written against github.ref",
            "    if: >-\n      ${{ github.ref != 'refs/heads/automation/release-next' }}\n",
            "other than github.head_ref",
        ),
        (
            "a release-PR carve-out that never pins the pull_request event",
            "    if: >-\n      ${{ github.head_ref != 'automation/release-next' }}\n",
            "without pinning the pull_request event",
        ),
    ):
        mutated_ci = (
            ci_workflow[:release_pr_job_start]
            + release_pr_job.replace(
                "    name: npm launcher tests\n",
                "    name: npm launcher tests\n" + condition,
                1,
            )
            + ci_workflow[release_pr_job_end:]
        )
        expect_assertion(
            label,
            expected,
            lambda source=mutated_ci: assert_release_pr_ci_scope_cannot_widen(source),
        )

    with tempfile.TemporaryDirectory() as directory:
        fixture_directory = Path(directory)
        for name in ("recognized.yml", "recognized.yaml", "ignored.txt"):
            (fixture_directory / name).write_text("fixture\n", encoding="utf-8")
        enumerated = [path.name for path in workflow_paths(fixture_directory)]
        if enumerated != ["recognized.yaml", "recognized.yml"]:
            raise AssertionError(
                "workflow enumeration must include both .yml and .yaml files"
            )

    ci_path = WORKFLOWS / "ci.yml"
    check_start = ci_workflow.index("\n  check:")
    # The slice has to stop at the very next job. `check-macos` follows `check`
    # and caches too, and `falsify-guards` and `feature-tests` follow that, so
    # slicing to any of them would hand this falsification several jobs and count
    # save lines that are not the check job's.
    check_end = ci_workflow.index("\n  check-macos:", check_start)
    check_job = ci_workflow[check_start:check_end]
    save_line = f"          {MAIN_ONLY_CACHE_SAVE}\n"
    if check_job.count(save_line) != 1:
        raise AssertionError(
            "cache falsification could not identify the check job's main-only save"
        )
    check_without_save = check_job.replace(save_line, "", 1)
    unbound_ci = (
        ci_workflow[:check_start] + check_without_save + ci_workflow[check_end:]
    )

    comment_compensation = dict(workflow_sources)
    comment_compensation[ci_path] = unbound_ci
    fuzz_path = WORKFLOWS / "fuzz.yml"
    comment_compensation[fuzz_path] += f"\n# {MAIN_ONLY_CACHE_SAVE}\n"
    expect_assertion(
        "missing rust-cache save-if compensated by a comment",
        "with mapping and one main-only save-if",
        lambda: assert_rust_cache_steps(comment_compensation),
    )

    field_compensation = dict(workflow_sources)
    field_compensation[ci_path] = unbound_ci
    # Matched by prefix, not by the whole line. What this falsification needs is
    # an active field on an unrelated cache step; which inputs the fuzz key
    # happens to hash, and whether it carries a toolchain pin, is incidental to
    # that and changes whenever the fuzz job is retuned. Pinning the exact text
    # here would fail the release-authority suite for an unrelated edit. The
    # `key:` prefix still distinguishes it from the `restore-keys:` entries,
    # which are indented further and carry no field name.
    fuzz_key_prefix = "          key: ${{ runner.os }}-parser-fuzz-"
    fuzz_key_matches = [
        line
        for line in field_compensation[fuzz_path].splitlines(keepends=True)
        if line.startswith(fuzz_key_prefix)
    ]
    if len(fuzz_key_matches) != 1:
        raise AssertionError(
            "cache falsification could not identify the unrelated fuzz cache step"
        )
    fuzz_key = fuzz_key_matches[0]
    field_compensation[fuzz_path] = field_compensation[fuzz_path].replace(
        fuzz_key,
        fuzz_key + f"          {MAIN_ONLY_CACHE_SAVE}\n",
        1,
    )
    expect_assertion(
        "missing rust-cache save-if compensated by an unrelated active field",
        "with mapping and one main-only save-if",
        lambda: assert_rust_cache_steps(field_compensation),
    )

    same_step_field = dict(workflow_sources)
    same_step_field[ci_path] = (
        ci_workflow[:check_start]
        + check_job.replace(
            save_line,
            f"        env:\n          {MAIN_ONLY_CACHE_SAVE}\n",
            1,
        )
        + ci_workflow[check_end:]
    )
    expect_assertion(
        "rust-cache save-if moved from with to an env field in the same step",
        "one canonical with mapping and one main-only save-if",
        lambda: assert_rust_cache_steps(same_step_field),
    )

    pinned_use = f"uses: {RUST_CACHE_ACTION}"
    if workflow_sources[ci_path].count(pinned_use) < 1:
        raise AssertionError(
            "cache falsification could not identify a pinned rust-cache use"
        )
    quoted_pinned = dict(workflow_sources)
    quoted_pinned[ci_path] = quoted_pinned[ci_path].replace(
        pinned_use,
        f'uses: "{RUST_CACHE_ACTION}"',
        1,
    )
    assert_rust_cache_steps(quoted_pinned)

    single_quoted_pinned = dict(workflow_sources)
    single_quoted_pinned[ci_path] = single_quoted_pinned[ci_path].replace(
        pinned_use,
        f"uses: '{RUST_CACHE_ACTION}'",
        1,
    )
    assert_rust_cache_steps(single_quoted_pinned)

    quoted_unpinned = dict(workflow_sources)
    quoted_unpinned[ci_path] = quoted_unpinned[ci_path].replace(
        pinned_use,
        'uses: "Swatinem/rust-cache@v2"',
        1,
    )
    expect_assertion(
        "quoted rust-cache use at a moving ref",
        "uses rust-cache at an unpinned ref",
        lambda: assert_rust_cache_steps(quoted_unpinned),
    )

    yaml_unpinned = dict(workflow_sources)
    yaml_unpinned[WORKFLOWS / "adversarial-cache.yaml"] = f"""\
jobs:
  adversarial:
    steps:
      - uses: "Swatinem/rust-cache@v2"
        with:
          {MAIN_ONLY_CACHE_SAVE}
"""
    expect_assertion(
        ".yaml workflow containing a moving rust-cache ref",
        "uses rust-cache at an unpinned ref",
        lambda: assert_rust_cache_steps(yaml_unpinned),
    )

    for label, escaped_action in (
        ("hex-escaped rust-cache separator", r"Swatinem/rust-cache\x40v2"),
        ("unicode-escaped rust-cache separator", r"Swatinem/rust-cache\u0040v2"),
        ("unicode-escaped rust-cache repository", r"Swatinem/rust-ca\u0063he@v2"),
    ):
        escaped_use = dict(workflow_sources)
        escaped_use[ci_path] = escaped_use[ci_path].replace(
            pinned_use,
            f'uses: "{escaped_action}"',
            1,
        )
        expect_assertion(
            label,
            "must not contain YAML escape sequences",
            lambda escaped_use=escaped_use: assert_rust_cache_steps(escaped_use),
        )

    for index, (label, expected_error, fixture) in enumerate(
        CACHE_AUTHORITY_ADVERSARIAL_WORKFLOWS,
        start=1,
    ):
        adversarial = dict(workflow_sources)
        adversarial[WORKFLOWS / f"cache-authority-adversarial-{index}.yml"] = (
            textwrap.dedent(fixture).lstrip()
        )
        expect_assertion(
            label,
            expected_error,
            lambda adversarial=adversarial: assert_rust_cache_steps(adversarial),
        )

    non_action_text = dict(workflow_sources)
    non_action_text[ci_path] = non_action_text[ci_path].replace(
        "jobs:\n",
        f"env:\n  UNACCOUNTED_CACHE_ACTION: {RUST_CACHE_ACTION}\n\njobs:\n",
        1,
    )
    assert_rust_cache_steps(non_action_text)

    for obsolete in (
        ROOT / "scripts" / "promote-npm-release.sh",
        ROOT / "scripts" / "test-promote-npm-release.py",
        ROOT / "scripts" / "stage-npm-release.sh",
        ROOT / "scripts" / "wait-npm-approval.sh",
        ROOT / "scripts" / "test-npm-staged-release.py",
    ):
        if obsolete.exists():
            raise AssertionError(
                f"obsolete npm release helper still exists: {obsolete}"
            )

    preflight_start = release.index("  npm_publish_preflight:")
    preflight_end = release.index("\n  publish_npm_compatibility:", preflight_start)
    npm_preflight = release[preflight_start:preflight_end]
    for policy in (
        "needs: [publish, install_proof]",
        "needs.publish.result == 'success'",
        "needs.install_proof.result == 'success'",
        "npm test --prefix ./packages/kin",
        "npm test --prefix ./packages/kin-mcp",
        "for package_dir in ./packages/kin ./packages/kin-mcp",
        "bash scripts/publish-npm-release.sh --preflight",
        '"$package_dir" "$GITHUB_REF" "$(git rev-parse HEAD)"',
        "npm@11.15.0",
    ):
        require(npm_preflight, policy, "two-package npm preflight")
    for forbidden in ("environment: release", "id-token: write", "npm publish"):
        if forbidden in npm_preflight:
            raise AssertionError(
                f"npm preflight has mutation authority before both packages pass: {forbidden}"
            )

    for job, next_job, package_dir in (
        ("publish_npm_compatibility", "publish_npm_canonical", "./packages/kin-mcp"),
        ("publish_npm_canonical", "verify_npm_published", "./packages/kin"),
    ):
        start = release.index(f"  {job}:")
        end = release.index(f"\n  {next_job}:", start + 3)
        publish_job = release[start:end]
        for policy in (
            "needs: [publish, install_proof, npm_publish_preflight]",
            "needs.publish.result == 'success'",
            "needs.install_proof.result == 'success'",
            "needs.npm_publish_preflight.result == 'success'",
            "environment: release",
            "id-token: write",
            "npm@11.15.0",
            "scripts/publish-npm-release.sh",
            package_dir,
        ):
            require(publish_job, policy, f"{job} trusted publishing")

    install_proof_start = release.index("  install_proof:")
    install_proof_end = release.index("\n  npm_publish_preflight:", install_proof_start)
    install_proof_job = release[install_proof_start:install_proof_end]
    for policy in (
        "needs: publish",
        "always()",
        "needs.publish.result == 'success'",
        "uses: ./.github/workflows/install-proof.yml",
        "expected_vfs_commit: d6c72979a3837c484ce7a604377df1837f9de8bd",
    ):
        require(install_proof_job, policy, "mandatory public install proof")

    exact_result_gates = {
        "verify_npm_published": (
            "needs.publish_npm_canonical.result == 'success'",
            "needs.publish_npm_compatibility.result == 'success'",
            "needs.version_tag_image.result == 'success'",
        ),
        "smoke_npm_published": ("needs.verify_npm_published.result == 'success'",),
        "finalize_release": (
            "needs.publish.result == 'success'",
            "needs.install_proof.result == 'success'",
            "needs.version_tag_image.result == 'success'",
            "needs.smoke_npm_published.result == 'success'",
        ),
        "promote_ghcr_latest": (
            "needs.config.result == 'success'",
            "needs.finalize_release.result == 'success'",
            "needs.version_tag_image.result == 'success'",
            "needs.build_daemon_image.result == 'success'",
            "needs.attest_daemon_image.result == 'success'",
        ),
        "publish_boundary_contracts": (
            "needs.publish.result == 'success'",
            "needs.install_proof.result == 'success'",
            "needs.finalize_release.result == 'success'",
        ),
        "version_tag_image": (
            "needs.publish.result == 'success'",
            "needs.install_proof.result == 'success'",
            "needs.build_daemon_image.result == 'success'",
            "needs.attest_daemon_image.result == 'success'",
        ),
    }
    for job, policies in exact_result_gates.items():
        start = release.index(f"  {job}:")
        match = re.search(r"(?m)^  [a-zA-Z0-9_]+:\s*$", release[start + 3 :])
        end = start + 3 + match.start() if match else len(release)
        job_body = release[start:end]
        require(job_body, "always()", f"{job} exact result admission")
        for policy in policies:
            require(job_body, policy, f"{job} exact result admission")

    for policy in (
        "needs: [publish_npm_canonical, publish_npm_compatibility, version_tag_image]",
        "scripts/verify-npm-release.sh",
        "needs: verify_npm_published",
        '"${PACKAGE}@${VERSION}"',
        "needs: [publish, install_proof, version_tag_image, smoke_npm_published]",
        "GitHub Latest remains blocked",
        "published automatically through protected npm OIDC",
        "anonymous byte, provenance, and install proof",
    ):
        require(release, policy, "two-package automatic npm release gate")

    publisher = (ROOT / "scripts" / "publish-npm-release.sh").read_text(
        encoding="utf-8"
    )
    for policy in (
        'npm publish "$tarball" --access public --tag "$channel"',
        "--provenance",
        "exact bytes, final channel, and provenance verified before skipping publication",
        "short-lived OIDC credential only",
        "anonymous public authority",
        "--preflight] <package-dir>",
        'bash "$verify_script"',
        'node "$release_order_script" npm-channel "$package" "$channel"',
        "require_exact_channel",
        "assert-not-rollback",
        "integrity=$integrity",
        "immutable version cannot be rolled back",
        "rerun this same release",
    ):
        require(publisher, policy, "OIDC npm publisher")

    verifier = (ROOT / "scripts" / "verify-npm-release.sh").read_text(encoding="utf-8")
    for policy in (
        'if remote_integrity="$(printf \'%s\\n\' "$remote_dist" | node -e',
        'typeof dist.integrity !== "string"',
        "complete dist metadata with integrity",
    ):
        require(verifier, policy, "retryable npm dist metadata verifier")
    require(
        ci_workflow,
        "python3 ./scripts/test-verify-npm-release.py",
        "partial npm metadata failure-injection regression",
    )
    for helper_name, helper in (
        ("OIDC npm publisher", publisher),
        ("anonymous npm provenance verifier", verifier),
    ):
        require(
            helper,
            "env -u NODE_AUTH_TOKEN -u NPM_TOKEN",
            f"{helper_name} credential scrubbing",
        )

    public_npm_path = "\n".join((release, publisher, verifier))
    if re.search(r"npm stage(?:\s|$)", public_npm_path):
        raise AssertionError(
            "automatic npm release path must not retain staged publishing authority"
        )
    if re.search(r"(?m)^\s*(?:run:\s*)?npm publish(?:\s|$)", release):
        raise AssertionError(
            "release workflow must delegate npm mutation to the audited helper"
        )

    for live_contract in (
        "Both public npm packages trust only firelock-ai/kin + release.yml + environment",
        "allow `npm publish` through short-lived OIDC, and disallow",
        "publish_npm_canonical",
        "publish_npm_compatibility",
    ):
        require(release, live_contract, "live automatic npm trust contract")

    for forbidden in (
        "secrets.NPM_TOKEN",
        "release-candidate-",
        "npm dist-tag",
        "promote_npm",
        "promote-npm-release.sh",
        "stage_npm_",
        "wait_for_npm_approval",
    ):
        if forbidden in release or forbidden in publisher:
            raise AssertionError(
                f"automatic npm release path contains retired authority: {forbidden}"
            )
    for forbidden in (
        "workflow_dispatch",
        "branches: [main]",
        "WIF_PROVIDER",
        "WIF_SERVICE_ACCOUNT",
        "us-central1-docker.pkg.dev",
        ":latest",
    ):
        if forbidden in image_job or forbidden in attestation_job:
            raise AssertionError(
                f"release daemon image path contains forbidden authority: {forbidden}"
            )

    unpinned: list[str] = []
    for line_number, line in enumerate(release.splitlines(), start=1):
        match = re.match(r"\s*(?:-\s*)?uses:\s*([^\s]+)", line)
        if match is None:
            continue
        action = match.group(1)
        if action.startswith("./"):
            continue
        _, separator, ref = action.rpartition("@")
        if not separator or re.fullmatch(r"[0-9a-f]{40}", ref) is None:
            unpinned.append(f"line {line_number}: {action}")
    if unpinned:
        raise AssertionError(
            "release.yml has moving third-party action refs: " + ", ".join(unpinned)
        )

    for workflow in workflow_paths():
        content = workflow.read_text(encoding="utf-8")
        header = content.split("\njobs:", maxsplit=1)[0]
        if re.search(r"(?m)^permissions:\s*$", header) is None:
            raise AssertionError(
                f"{workflow.name} must set explicit top-level token permissions"
            )
        if re.search(r"(?m)^  contents:\s*read\s*$", header) is None:
            raise AssertionError(
                f"{workflow.name} must default its workflow token to contents: read"
            )
        main_branch = re.search(
            r"(?m)^\s+branches:\s*\[\s*['\"]?main['\"]?\s*\]\s*$",
            content,
        ) or re.search(
            r"(?m)^\s+branches:\s*$\n(?:\s+-.*\n)*?\s+-\s*['\"]?main['\"]?\s*$",
            content,
        )
        if main_branch:
            writes = re.findall(
                r"(?m)^\s+(contents|packages|id-token):\s*write\s*$", content
            )
            if writes:
                raise AssertionError(
                    f"{workflow.name} grants {sorted(set(writes))} on a main-push workflow"
                )

        for forbidden_secret in ("WIF_PROVIDER", "WIF_SERVICE_ACCOUNT"):
            if forbidden_secret in content:
                raise AssertionError(
                    f"{workflow.name} still consumes infra-only {forbidden_secret}"
                )

        if "workflow_dispatch:" in content and re.search(
            r"secrets\.(?:KIN_[A-Z0-9_]*(?:TOKEN|KEY|APP_ID)|NPM_TOKEN|WIF_PROVIDER|WIF_SERVICE_ACCOUNT)",
            content,
        ):
            raise AssertionError(
                f"{workflow.name} exposes branch-selectable dispatch with a release-capable secret"
            )

    print(
        "release workflow authority is reviewed-PR to App-tag automatic, "
        "protected, pinned, GCP-free, cross-platform byte-canonical, and npm "
        "automatic through short-lived OIDC with post-public proof"
    )


if __name__ == "__main__":
    main()

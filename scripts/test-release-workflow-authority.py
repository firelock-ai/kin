#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fail closed when Kin release authority drifts back onto main pushes."""

from __future__ import annotations

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
RELEASE_BOT_DOC = ROOT / "docs" / "release-bot.md"
INSTALL_PROOF = WORKFLOWS / "install-proof.yml"
INSTALLER_CALLBACK = WORKFLOWS / "publish-release-installers.yml"
UPDATE_TRUST = ROOT / "docs" / "security" / "signing-and-update-trust.md"
INSTALL_SH = ROOT / "scripts" / "install.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
ABANDONED_TAGS = ROOT / "scripts" / "abandoned-release-tags.json"
TAG_SELECTOR = ROOT / "scripts" / "select-admissible-release-tag.py"
ABANDONED_TAGS_POLICY = "scripts/abandoned-release-tags.json"
TAG_SELECTOR_POLICY = "scripts/select-admissible-release-tag.py"
TRUSTED_POLICY_PREFIX = "refs/remotes/origin/main:"
TAG_LISTING_FORMAT = (
    "--format='%(refname:strip=2) "
    "%(if)%(*objectname)%(then)%(*objectname)%(else)%(objectname)%(end)'"
)
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
# separately; these are the ones outside that trust boundary.
EXPECTED_REQUIRED_CONTEXT_ACTION_PINS = {
    ".github/workflows/sast.yml": {
        "dtolnay/rust-toolchain": "191af2e1955bbe165f9bbacff2d2438002dff4d4",
        "taiki-e/install-action": "6a1bd70eaac3c8bdf093356838d7ee09fda951cf",
    },
}
EXPECTED_SELECTOR_INVOCATIONS = {
    "release-tag": ('"$abandoned"', '"$candidate_tags"', '"$TAG"', '"$admissible"'),
    "release-train": ('"$abandoned"', '"$candidate_tags"', '""', '"$admissible"'),
}
HEALTH = ROOT / "crates" / "kin-cli" / "src" / "commands" / "health.rs"
RUST_CACHE_ACTION = "Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4"
MAIN_ONLY_CACHE_SAVE = "save-if: ${{ github.ref == 'refs/heads/main' }}"
MAIN_ONLY_CACHE_SAVE_VALUE = "${{ github.ref == 'refs/heads/main' }}"
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
    "DCO Sign-off",
    "cargo-deny",
    "gitleaks (full history)",
    "Windows installer + vector-free release build",
)
DOCS_ONLY_WORKFLOW_HEADER = textwrap.dedent(
    """\
    name: CI
    on:
      push:
        branches: [main]
      pull_request:
        branches: [main]
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
DOCS_ONLY_CHECK_JOB = textwrap.dedent(
    """\
    check-docs-only:
      name: Check & Test
      needs: changes
      if: ${{ !cancelled() && needs.changes.outputs.docs_only == 'true' }}
      runs-on: ubuntu-latest
      strategy:
        matrix:
          os: [ubuntu-latest, macos-latest]
      steps:
        - name: Report the documentation-only fast path
          run: echo "documentation-only diff; build and test validation not applicable"
    """
).rstrip()
REAL_CHECK_JOB_AUTHORITY = textwrap.dedent(
    """\
    check:
      name: Check & Test
      needs: changes
      if: ${{ !cancelled() && needs.changes.outputs.docs_only != 'true' }}
      runs-on: ${{ matrix.os }}
      timeout-minutes: 60
      env:
        CARGO_INCREMENTAL: "0"
        CARGO_PROFILE_DEV_DEBUG: "0"
        CARGO_PROFILE_TEST_DEBUG: "0"
      strategy:
        matrix:
          os: [ubuntu-latest, macos-latest]
      steps:
    """
).rstrip()
CI_JOB_DISPLAY_NAMES = {
    "dco": "DCO Sign-off",
    "npm-launchers": "npm launcher tests",
    "windows-authority-tests": "Windows authority tests",
    "windows-installer": "Windows installer + vector-free release build",
    "changes": "Classify diff scope",
    "check-docs-only": "Check & Test",
    "check": "Check & Test",
    "coverage": "Code Coverage",
}
EXPECTED_WORKFLOW_JOB_DISPLAY_NAMES: dict[str, dict[str, str | None]] = {
    ".github/workflows/approve-to-merge.yml": {
        "gate": None,
    },
    ".github/workflows/ci.yml": CI_JOB_DISPLAY_NAMES,
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
    ".github/workflows/link-check.yml": {
        "link-check": "Check public documentation links",
    },
    ".github/workflows/notify-approver.yml": {
        "notify": None,
    },
    ".github/workflows/publish-release-installers.yml": {
        "dispatch": None,
    },
    ".github/workflows/registry-index-migrate.yml": {
        "migrate": None,
    },
    ".github/workflows/release-recovery.yml": {
        "reconcile": "Reconcile failed release",
    },
    ".github/workflows/release-tag.yml": {
        "mint-release-tag": "Mint release tag",
    },
    ".github/workflows/release-train.yml": {
        "reconcile": "Reconcile release PR",
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
}
EXPECTED_DYNAMIC_JOB_CONTEXT_SHA256 = {
    (
        ".github/workflows/fuzz.yml",
        "fuzz",
    ): "aa645addde738ea8f1fac9c70071ac0f603fd0030602f15d013535abf9a32443",
    (
        ".github/workflows/install-proof.yml",
        "install-proof",
    ): "c5cd6bbfa99f45c84084d22aafe5e0bb038c2ee006404a58d72e19a0db69b46e",
    (
        ".github/workflows/release.yml",
        "build",
    ): "4708a5968103aa4c624423fd5a67c5c183969919773e52c9cc204b2c9983c90b",
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
    "Check & Test": {
        (".github/workflows/ci.yml", "check-docs-only"),
        (".github/workflows/ci.yml", "check"),
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
    "Windows installer + vector-free release build": {
        (".github/workflows/ci.yml", "windows-installer"),
    },
}
# Durable workflow IDs are GitHub's repository-scoped identity, while `path`
# makes that identity reviewable in source. These values are also exercised
# against the current REST response shape by the positive fixture below.
REQUIRED_RELEASE_CHECK_PROVENANCE = {
    "Check & Test (ubuntu-latest)": (
        245_803_170,
        ".github/workflows/ci.yml",
        "push",
    ),
    "Check & Test (macos-latest)": (
        245_803_170,
        ".github/workflows/ci.yml",
        "push",
    ),
    "DCO Sign-off": (245_803_170, ".github/workflows/ci.yml", "push"),
    "cargo-deny": (251_549_972, ".github/workflows/sast.yml", "push"),
    "gitleaks (full history)": (
        293_452_372,
        ".github/workflows/secret-scan.yml",
        "push",
    ),
    "Windows installer + vector-free release build": (
        245_803_170,
        ".github/workflows/ci.yml",
        "push",
    ),
}
GITHUB_ACTIONS_APP_ID = 15_368
RELEASE_TAG_WORKFLOW_ID = 318_521_292
RELEASE_GATE_FIXTURE_SHA = "1" * 40
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


def assert_check_consumer_authority(workflow: str) -> None:
    """Pin both jobs that can emit the release-required Check & Test contexts."""

    blocks = workflow_job_blocks(workflow)
    actual_names = {job: job_display_name(block) for job, block in blocks.items()}
    if actual_names != CI_JOB_DISPLAY_NAMES:
        raise AssertionError(
            "Check & Test consumer authority requires the exact reviewed CI job "
            "identity and display-name map"
        )

    docs_only = blocks.get("check-docs-only")
    real = blocks.get("check")
    if (
        docs_only is None
        or classifier_active_job_source(docs_only) != DOCS_ONLY_CHECK_JOB
    ):
        raise AssertionError(
            "Check & Test consumer authority requires the exact inert docs-only job"
        )
    if (
        real is None
        or real_check_job_authority_source(real) != REAL_CHECK_JOB_AUTHORITY
    ):
        raise AssertionError(
            "Check & Test consumer authority requires the exact real check admission "
            "and matrix contract"
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
            if save_value != MAIN_ONLY_CACHE_SAVE_VALUE:
                raise AssertionError(
                    f"{workflow.name} rust-cache save-if must be the exact "
                    "main-only scalar"
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
) -> subprocess.CompletedProcess[str]:
    """Execute the real gate against a current-API-shaped provenance fixture."""

    workflow_specs = {
        ".github/workflows/ci.yml": {
            "id": 1001,
            "workflow_id": 245_803_170,
            "path": ".github/workflows/ci.yml",
            "event": "push",
            "head_branch": "main",
            "head_sha": RELEASE_GATE_FIXTURE_SHA,
            "status": "completed",
            "conclusion": "success",
            "check_suite_id": 101,
        },
        ".github/workflows/sast.yml": {
            "id": 1002,
            "workflow_id": 251_549_972,
            "path": ".github/workflows/sast.yml",
            "event": "push",
            "head_branch": "main",
            "head_sha": RELEASE_GATE_FIXTURE_SHA,
            "status": "completed",
            "conclusion": "success",
            "check_suite_id": 102,
        },
        ".github/workflows/secret-scan.yml": {
            "id": 1003,
            "workflow_id": 293_452_372,
            "path": ".github/workflows/secret-scan.yml",
            "event": "push",
            "head_branch": "main",
            "head_sha": RELEASE_GATE_FIXTURE_SHA,
            "status": "completed",
            "conclusion": "success",
            "check_suite_id": 103,
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
    for index, name in enumerate(REQUIRED_RELEASE_CHECKS, start=1):
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
                "SHA": RELEASE_GATE_FIXTURE_SHA,
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
    """Extract one named workflow step so its internal order can be judged."""

    if step_anchor not in content:
        raise AssertionError(
            f"{workflow} no longer carries the step that owns release-lane "
            f"admission: {step_anchor.strip()}"
        )
    start = content.index(step_anchor)
    if "\n      - name:" not in content[start + 1 :]:
        raise AssertionError(
            f"{workflow} admission step is no longer followed by another step, "
            "so its boundary cannot be resolved"
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
    if "did not become readable" not in absent.stdout:
        raise AssertionError(
            "post-mint readback must distinguish exhausted reads from a "
            f"mismatch: {absent.stdout}{absent.stderr}"
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
        actual: dict[str, str] = {}
        for reference in re.findall(r"uses:\s*(\S+)", content):
            if reference.startswith("actions/"):
                continue
            action, _, version = reference.partition("@")
            actual[action] = version
        if actual != expected:
            raise AssertionError(
                f"{path} produces a presence-required release context, so every "
                "third-party action in it must stay pinned to its exact reviewed "
                f"commit: expected={expected} actual={actual}"
            )
        for action, sha in actual.items():
            if not re.fullmatch(r"[0-9a-f]{40}", sha):
                raise AssertionError(
                    f"{path} uses {action} at '{sha}', which is a movable ref "
                    "rather than an immutable commit"
                )


def assert_selector_arguments(release_tag: str, release_train: str) -> None:
    """Pin which tag each workflow declares it is about to mint."""

    actual = {
        "release-tag": selector_invocation("release-tag", release_tag),
        "release-train": selector_invocation("release-train", release_train),
    }
    if actual != EXPECTED_SELECTOR_INVOCATIONS:
        raise AssertionError(
            "each release workflow must hand the admission selector its own "
            "reviewed arguments. The mint-intent argument names the tag that "
            "workflow is about to create, and only the mint creates one. The "
            "train resolves drift from a base tag it never mints, so naming "
            "that base as mint intent refuses exactly when a record covers it, "
            f"which is every abandonment: expected={EXPECTED_SELECTOR_INVOCATIONS} "
            f"actual={actual}"
        )


def assert_abandoned_tag_admission(release_tag: str, release_train: str) -> None:
    """Only a reviewed record may waive release-lane serialization."""

    assert_selector_arguments(release_tag, release_train)

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
    release_bot_doc = RELEASE_BOT_DOC.read_text(encoding="utf-8")
    install_proof = INSTALL_PROOF.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    ci_workflow = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    installer_callback = INSTALLER_CALLBACK.read_text(encoding="utf-8")
    update_trust = UPDATE_TRUST.read_text(encoding="utf-8")
    install_sh = INSTALL_SH.read_text(encoding="utf-8")
    install_ps1 = INSTALL_PS1.read_text(encoding="utf-8")
    health = HEALTH.read_text(encoding="utf-8")
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
    if (
        dynamic_context_spoof[install_proof_workflow].count(
            "          - os: ubuntu-latest"
        )
        != 1
    ):
        raise AssertionError(
            "workflow census falsification could not identify install-proof matrix"
        )
    dynamic_context_spoof[install_proof_workflow] = dynamic_context_spoof[
        install_proof_workflow
    ].replace(
        "          - os: ubuntu-latest",
        "          - os: Check & Test (ubuntu-latest)",
        1,
    )
    expect_assertion(
        "dynamic matrix-only job resolves to a release-required context",
        "exact reviewed matrix expansions",
        lambda: assert_workflow_job_census(dynamic_context_spoof),
    )

    require(
        install_sh,
        '"$EXTRACT_DIR/kin" registry authority --initialize',
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
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
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
        "github.event.workflow_run.conclusion == 'success'",
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
        "if identity == expected_identity:",
        "ambiguous required check",
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
    assert_abandoned_tag_admission(release_tag, release_train)
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
        "Release blocked after automatic retries",
    ):
        require(release_recovery, policy, "bounded automatic release recovery")
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

    pinned_readme_version = re.search(r"\bv?\d+\.\d+\.\d+\b", readme)
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
    embedding_start = install_proof.index(
        "      - name: Unix embedding and semantic retrieval proof",
        first_run_start,
    )
    validation_start = install_proof.index(
        "      - name: Validate installed capability proof",
        embedding_start,
    )
    first_run = install_proof[first_run_start:embedding_start]
    embedding = install_proof[embedding_start:validation_start]
    for policy in (
        'case "$PROOF_SHELL" in',
        "export SHELL=/bin/bash",
        "export SHELL=/bin/zsh",
        'printf \'SHELL=%s\\n\' "$SHELL" >> "$GITHUB_ENV"',
    ):
        require(first_run, policy, "cross-step install-proof shell pin")
    for policy in (
        "PROOF_SHELL: ${{ matrix.setup-shell }}",
        'case "$PROOF_SHELL" in',
        "unset PSModulePath PSVersionTable",
        "export SHELL=/bin/bash",
        "export SHELL=/bin/zsh",
    ):
        require(embedding, policy, "embedded-health shell reset")
    for policy in (
        "overall healthy=${report.healthy}",
        "non-healthy checks: ${nonHealthyChecks(report)}",
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
        "cmp -s vfs-expected.txt vfs-graph-read.txt",
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
    # Both boundaries now reach the graph authority store, one transaction past
    # the config writer, so the config-writer refusal is pinned as a REFUTATION
    # and the store's missing durable-flush capability is pinned by name.
    # Requiring the absence of the one and the presence of the other is what
    # keeps a regression to the old fail-closed arm from reading as a pass, and
    # what forces the change that finally moves this boundary to say so here.
    windows_admission = (ROOT / "scripts" / "assert-windows-init-contract.sh").read_text(
        encoding="utf-8"
    )
    for policy in (
        '"$kin_bin" init',
        'CONFIG_REFUSAL="cannot publish repository config"',
        'SOURCE_PROOF_STAGE="prove mutable Git workspace"',
        'DURABLE_FLUSH_GAP="for durable metadata flush"',
        'NON_EMPTY_REFUSAL="requires an empty directory"',
        'refute_text "Windows exact-Git admission" "$SOURCE_PROOF_STAGE"',
        'refute_text "Windows exact-Git admission" "$CONFIG_REFUSAL"',
        'refute_text "Windows native-unborn bootstrap" "$CONFIG_REFUSAL"',
        'require_text "Windows exact-Git admission" "$DURABLE_FLUSH_GAP"',
        'require_text "Windows native-unborn bootstrap" "$DURABLE_FLUSH_GAP"',
        'require_refused "Windows exact-Git admission"',
        'require_refused "Windows native-unborn bootstrap"',
        'require_refused "Windows non-empty native boundary"',
        'fail "$label unexpectedly succeeded" "$log"',
        'if [ -e "$dir/.kin" ]; then',
        "'.kin.init-*'",
    ):
        require(windows_admission, policy, "Windows admission contract assertions")

    ci_jobs = workflow_job_blocks(ci_workflow)
    for job_id in ("windows-authority-tests", "windows-installer"):
        for policy in (
            "- name: Assert the Windows admission contract",
            "bash ./scripts/assert-windows-init-contract.sh",
        ):
            require(ci_jobs[job_id], policy, f"shared Windows admission proof in {job_id}")
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
    require(
        ci_jobs["windows-authority-tests"],
        "target/x86_64-pc-windows-msvc/debug/kin.exe",
        "pull-request Windows admission proof",
    )
    require(
        ci_jobs["windows-installer"],
        "target/x86_64-pc-windows-msvc/release/kin.exe",
        "landing-push Windows admission proof",
    )
    if re.search(r"(?m)^    if:", ci_jobs["windows-authority-tests"]) is not None:
        raise AssertionError(
            "the Windows authority job must stay on every event, so admission "
            "refusals are asserted before a release commit can carry them"
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
        "rustup target add x86_64-unknown-linux-musl",
        "musl-tools",
        "cargo check --locked --target x86_64-unknown-linux-musl",
        "-p kin-cli -p kin-daemon",
    ):
        require(ci_jobs["check"], policy, "pull-request Linux release-target compile guard")
    if "x86_64-unknown-linux-musl" not in release_musl_targets:
        raise AssertionError(
            "the pull-request compile guard must build a target the release "
            "workflow actually ships; release musl targets="
            f"{sorted(release_musl_targets)}"
        )
    for package in ("-p kin-cli", "-p kin-daemon"):
        require(
            workflow_job_blocks(release)["build"],
            package,
            "release core binary package set the compile guard mirrors",
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
        '[ "$(jq -r .status <<< "$run")" = completed ]',
        '[ "$(jq -r .conclusion <<< "$run")" = success ]',
        '[ "$(jq -r .path <<< "$run")" = .github/workflows/release.yml ]',
        '[ "$peeled" = "$KIN_SHA" ]',
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
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
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
        "docker/login-action@af1e73f918a031802d376d3c8bbc3fe56130a9b0",
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
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
        "subject-path: |",
        "kin-linux-x86_64.tar.gz",
        "kin-linux-aarch64.tar.gz",
        "kin-macos-x86_64.tar.gz",
        "kin-macos-aarch64.tar.gz",
        "kin-windows-x86_64.zip",
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

    # The Windows installer leg is off the pull-request path, so the only place
    # it can still prove anything is a push to main. The only reason that is
    # safe is that release-tag.yml refuses to mint a tag unless this exact
    # check is present and green on the release sha. Pin both halves together:
    # dropping either one silently turns a required release gate into a job that
    # never runs on the commit being released.
    installer_start = ci_workflow.index("  windows-installer:")
    installer_end = ci_workflow.index("\n  changes:", installer_start)
    installer_job = ci_workflow[installer_start:installer_end]
    for policy in (
        "name: Windows installer + vector-free release build",
        "github.event_name != 'pull_request'",
        "needs.changes.outputs.docs_only != 'true'",
    ):
        require(installer_job, policy, "main-only Windows installer admission")
    require(
        ci_workflow,
        "  push:\n    branches: [main]",
        "Windows installer proof still reaching every main commit",
    )

    # Main's classifier must keep reporting false so the release-critical
    # installer actually runs. The release-tag gate independently requires an
    # exact success conclusion, but preserving both controls keeps a main push
    # from silently losing the proof and discovering that only at tag time.
    # Enforce the classifier as a closed form at the whole-job boundary. The
    # reviewed shell is meaningless without its checkout, output, id, event,
    # SHA, shell, and startup-environment bindings, so those are one authority
    # contract rather than independently mutable text.
    classifier_start = ci_workflow.index("  changes:")
    classifier_end = ci_workflow.index("\n  check-docs-only:", classifier_start)
    classifier = ci_workflow[classifier_start:classifier_end]
    assert_docs_only_classifier_guard(ci_workflow)
    assert_check_consumer_authority(ci_workflow)
    consumer_blocks = workflow_job_blocks(ci_workflow)
    docs_only_check = consumer_blocks["check-docs-only"]
    real_check = consumer_blocks["check"]

    docs_only_condition = (
        "    if: ${{ !cancelled() && needs.changes.outputs.docs_only == 'true' }}"
    )
    real_check_condition = (
        "    if: ${{ !cancelled() && needs.changes.outputs.docs_only != 'true' }}"
    )
    swapped_docs_only_check = docs_only_check.replace(
        docs_only_condition,
        real_check_condition,
        1,
    )
    swapped_real_check = real_check.replace(
        real_check_condition,
        docs_only_condition,
        1,
    )
    swapped_consumers = ci_workflow.replace(
        docs_only_check,
        swapped_docs_only_check,
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
            "docs-only Check & Test job identity changed",
            "  check-docs-only:",
            "  check-context-spoof:",
        ),
        (
            "docs-only Check & Test display name changed",
            "    name: Check & Test",
            "    name: Documentation shortcut",
        ),
        (
            "docs-only Check & Test dependency changed",
            "    needs: changes",
            "    needs: dco",
        ),
        (
            "docs-only Check & Test runner changed",
            "    runs-on: ubuntu-latest",
            "    runs-on: ${{ matrix.os }}",
        ),
        (
            "docs-only Check & Test matrix changed",
            "        os: [ubuntu-latest, macos-latest]",
            "        os: [ubuntu-latest]",
        ),
        (
            "docs-only Check & Test inert step changed",
            '      run: echo "documentation-only diff; '
            'build and test validation not applicable"',
            '      run: echo "unreviewed shortcut"',
        ),
    ):
        if docs_only_check.count(old) != 1:
            raise AssertionError(
                f"Check & Test consumer falsification could not identify {label}"
            )
        mutant_job = docs_only_check.replace(old, new, 1)
        mutant_workflow = ci_workflow.replace(docs_only_check, mutant_job, 1)
        expect_assertion(
            label,
            "Check & Test consumer authority",
            lambda mutant_workflow=mutant_workflow: assert_check_consumer_authority(
                mutant_workflow
            ),
        )

    for label, old, new in (
        (
            "real Check & Test display name changed",
            "    name: Check & Test",
            "    name: Check & Test trusted",
        ),
        (
            "real Check & Test dependency changed",
            "    needs: changes",
            "    needs: dco",
        ),
        (
            "real Check & Test runner detached from its matrix",
            "    runs-on: ${{ matrix.os }}",
            "    runs-on: ubuntu-latest",
        ),
        (
            "real Check & Test matrix changed",
            "        os: [ubuntu-latest, macos-latest]",
            "        os: [ubuntu-latest]",
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
        "Windows installer + vector-free release build",
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
        "check not green: Mint release tag (conclusion=failure)",
        add_external_mint_failure,
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

    def add_merge_queue_producer(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        """A landing through the merge queue publishes the same contexts twice."""

        queue_branch = "gh-readonly-queue/main/pr-1-" + "0" * 40
        for path, suite in (
            (".github/workflows/ci.yml", 201),
            (".github/workflows/sast.yml", 202),
            (".github/workflows/secret-scan.yml", 203),
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
                    "event": (
                        "push" if path.endswith("secret-scan.yml") else "merge_group"
                    ),
                    "head_branch": queue_branch,
                    "check_suite_id": suite,
                }
            )
            workflow_runs.append(source)
        for name in REQUIRED_RELEASE_CHECKS:
            _, workflow_path, _ = REQUIRED_RELEASE_CHECK_PROVENANCE[name]
            queue_copy = required_check_fixture(check_runs, name).copy()
            queue_copy.update(
                {
                    "id": 20_000 + len(check_runs),
                    "check_suite_id": {
                        ".github/workflows/ci.yml": 201,
                        ".github/workflows/sast.yml": 202,
                        ".github/workflows/secret-scan.yml": 203,
                    }[workflow_path],
                    # The queue build deliberately skips the legs that only the
                    # landing push runs for real.
                    "conclusion": "skipped",
                }
            )
            check_runs.append(queue_copy)

    merge_queue_fixture = execute_release_check_gate(
        release_gate,
        {},
        mutate_fixture=add_merge_queue_producer,
    )
    if merge_queue_fixture.returncode != 0:
        raise AssertionError(
            "a merge-queue landing's duplicate contexts blocked the release: "
            f"{merge_queue_fixture.stdout}{merge_queue_fixture.stderr}"
        )

    def only_merge_queue_producer(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        current_run: dict[str, object],
    ) -> None:
        """Before the landing push runs, only queue evidence exists."""

        add_merge_queue_producer(check_runs, workflow_runs, current_run)
        release_suites = {
            run["check_suite_id"]
            for run in workflow_runs
            if run.get("head_branch") == "main"
            and run.get("path")
            in (
                ".github/workflows/ci.yml",
                ".github/workflows/sast.yml",
                ".github/workflows/secret-scan.yml",
            )
        }
        check_runs[:] = [
            run for run in check_runs if run["check_suite_id"] not in release_suites
        ]
        workflow_runs[:] = [
            run
            for run in workflow_runs
            if run.get("check_suite_id") not in release_suites
        ]

    queue_only_fixture = execute_release_check_gate(
        release_gate,
        {},
        mutate_fixture=only_merge_queue_producer,
    )
    if queue_only_fixture.returncode == 0:
        raise AssertionError(
            "the merge queue's skipped build was admitted as release evidence"
        )
    for name in REQUIRED_RELEASE_CHECKS:
        expected = f"missing required check: {name}"
        if expected not in queue_only_fixture.stdout + queue_only_fixture.stderr:
            raise AssertionError(
                "queue-only evidence was refused without naming the missing "
                f"producer: {name}: {queue_only_fixture.stdout}"
                f"{queue_only_fixture.stderr}"
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
            "Windows installer + vector-free release build",
        )
        check["head_sha"] = "2" * 40

    assert_release_gate_fixture_rejected(
        release_gate,
        "required check is attached to the wrong head sha",
        (
            "required check has wrong head sha: "
            "Windows installer + vector-free release build"
        ),
        change_required_check_head,
    )

    def change_required_workflow_head(
        check_runs: list[dict[str, object]],
        workflow_runs: list[dict[str, object]],
        _current_run: dict[str, object],
    ) -> None:
        check = required_check_fixture(
            check_runs,
            "Check & Test (macos-latest)",
        )
        workflow = workflow_fixture(workflow_runs, check["check_suite_id"])
        workflow["head_sha"] = "3" * 40

    assert_release_gate_fixture_rejected(
        release_gate,
        "required workflow run is attached to the wrong head sha",
        "required check workflow provenance mismatch: Check & Test (macos-latest)",
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
    check_end = ci_workflow.index("\n  coverage:", check_start)
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
        "expected_vfs_commit: c782905f39500a7a107aba5a91e85119c77726fa",
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

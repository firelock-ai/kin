#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fail closed when Kin release authority drifts back onto main pushes."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
README = ROOT / "README.md"
RELEASE = WORKFLOWS / "release.yml"
RELEASE_RECOVERY = WORKFLOWS / "release-recovery.yml"
RELEASE_TAG = WORKFLOWS / "release-tag.yml"
RELEASE_TRAIN = WORKFLOWS / "release-train.yml"
INSTALL_PROOF = WORKFLOWS / "install-proof.yml"
INSTALLER_CALLBACK = WORKFLOWS / "publish-release-installers.yml"
UPDATE_TRUST = ROOT / "docs" / "security" / "signing-and-update-trust.md"
INSTALL_SH = ROOT / "scripts" / "install.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
HEALTH = ROOT / "crates" / "kin-cli" / "src" / "commands" / "health.rs"


def require(content: str, needle: str, context: str) -> None:
    if needle not in content:
        raise AssertionError(f"{context} is missing required policy: {needle}")


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
    install_proof = INSTALL_PROOF.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    ci_workflow = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    installer_callback = INSTALLER_CALLBACK.read_text(encoding="utf-8")
    update_trust = UPDATE_TRUST.read_text(encoding="utf-8")
    install_sh = INSTALL_SH.read_text(encoding="utf-8")
    install_ps1 = INSTALL_PS1.read_text(encoding="utf-8")
    health = HEALTH.read_text(encoding="utf-8")
    docker_workflow = (WORKFLOWS / "docker.yml").read_text(encoding="utf-8")
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
        raise AssertionError("Windows installer must not imply Unix mode repair support")
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
        "node scripts/release-intent.mjs",
        "git merge-base --is-ancestor",
        "manual release sha",
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
        "verifiedTimestamps",
        "registry.npmjs.org/@kinlab%2F",
        "ghcr.io/v2/firelock-ai/kin/manifests",
        "oci://ghcr.io/firelock-ai/kin@${ghcr_latest}",
        "--bundle-from-oci",
        'latest_tag" != v0.3.6',
        "markerless logless fallback is retired",
        "matching_count",
        "highest_tag",
        "REQUIRED_CHECKS:",
        "did not settle within 20 minutes",
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "repositories: kin",
        'ref="refs/tags/$TAG"',
    ):
        require(release_tag, policy, "automatic App-mediated release tag admission")
    for forbidden in (
        "contents: write",
        "packages: write",
        "id-token: write",
        "KIN_CI_BOT_TOKEN",
    ):
        if forbidden in release_tag:
            raise AssertionError(
                f"release-tag workflow contains forbidden standing authority: {forbidden}"
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
        "git merge --signoff --no-edit -X ours refs/remotes/origin/main",
        'gh pr merge "$PR"',
        "GH_TOKEN: ${{ steps.app-token.outputs.token }}",
        "--match-head-commit",
        "--auto",
        "--squash",
        "git commit --allow-empty --signoff",
        "Activate protected checks for the automated release PR",
    ):
        require(release_train, policy, "coalescing protected release train")
    for forbidden in (
        "workflow_dispatch:",
        "contents: write",
        "packages: write",
        "id-token: write",
        "git push --force",
        "git push -f",
    ):
        if forbidden in release_train:
            raise AssertionError(
                f"release train contains forbidden authority or history rewrite: {forbidden}"
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
        "printf 'SHELL=%s\\n' \"$SHELL\" >> \"$GITHUB_ENV\"",
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
        'process_state="$(printf \'%s\' "$process_state" | tr -d \'[:space:]\')"',
        "trap 'on_vfs_signal 130' INT",
        "trap 'on_vfs_signal 143' TERM",
    ):
        require(install_proof, policy, "public VFS and installed-artifact proof")
    cleanup_start = install_proof.index("          cleanup_vfs() {")
    signal_start = install_proof.index("          on_vfs_signal() {", cleanup_start)
    cleanup_vfs = install_proof[cleanup_start:signal_start]
    require(cleanup_vfs, 'vfs_pid=""', "idempotent public VFS cleanup")
    if "ps -o stat= -p \"$vfs_pid\" 2>/dev/null | tr" in cleanup_vfs:
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
    proof_upload = install_proof[install_proof.index("- name: Preserve proof reports") :]
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
    vfs_expected = set(
        re.findall(r"EXPECTED_VFS_COMMIT:\s*([0-9a-f]{40})", release)
    )
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

    for policy in (
        "Reopen a fresh Windows graph through the daemon",
        'grep -q "byte-exact executable-mode proof is unsupported"',
        'grep -q "atomic repository config replacement is unsupported"',
        'test ! -e "$boot_dir/.kin/kindb/head-generation"',
    ):
        require(ci_workflow, policy, "Windows daemon reopen regression")

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
    latest_promotion_job = release[
        latest_promotion_start:boundary_publish_start
    ]
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
        'changed from ${initial_latest_state}:${initial_latest_digest:-<missing>}',
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
    install_proof_end = release.index(
        "\n  npm_publish_preflight:", install_proof_start
    )
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
        "smoke_npm_published": (
            "needs.verify_npm_published.result == 'success'",
        ),
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

    for workflow in sorted(WORKFLOWS.glob("*.yml")):
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
            r"secrets\.(?:KIN_[A-Z0-9_]*TOKEN|NPM_TOKEN|WIF_PROVIDER|WIF_SERVICE_ACCOUNT)",
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

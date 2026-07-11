#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fail closed when Kin release authority drifts back onto main pushes."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"


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
    docker_workflow = (WORKFLOWS / "docker.yml").read_text(encoding="utf-8")
    if "workflow_dispatch:" in release:
        raise AssertionError(
            "release.yml must not expose branch-selectable workflow_dispatch"
        )
    require(release, 'tags:\n      - "v*.*.*"', "release trigger")
    require(release, "  build_daemon_image:", "release daemon image job")
    require(release, "  attest_daemon_image:", "release daemon attestation job")

    for policy in (
        "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
        "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
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
        "actions/attest@a1948c3f048ba23858d222213b7c278aabede763",
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
        raise AssertionError("release daemon attestation job must not rebuild the image")
    if image_job.count("docker buildx build") != 1:
        raise AssertionError("release daemon path must contain exactly one image build command")

    require(
        release,
        "needs: [build, notarize_linux, attest_daemon_image]",
        "public release daemon attestation gate",
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

    for obsolete in (
        ROOT / "scripts" / "promote-npm-release.sh",
        ROOT / "scripts" / "test-promote-npm-release.py",
    ):
        if obsolete.exists():
            raise AssertionError(
                f"obsolete token-based npm promoter still exists: {obsolete}"
            )

    for job, next_job, package_dir in (
        ("stage_npm_compatibility", "stage_npm_canonical", "./packages/kin-mcp"),
        ("stage_npm_canonical", "wait_for_npm_approval", "./packages/kin"),
    ):
        start = release.index(f"  {job}:")
        end = release.index(f"\n  {next_job}:", start + 3)
        stage_job = release[start:end]
        for policy in (
            "needs: [publish, install_proof]",
            "environment: release",
            "id-token: write",
            "npm@11.15.0",
            "scripts/stage-npm-release.sh",
            package_dir,
        ):
            require(stage_job, policy, f"{job} trusted staging")

    for policy in (
        "needs: [stage_npm_canonical, stage_npm_compatibility, version_tag_image]",
        'bash scripts/wait-npm-approval.sh "${GITHUB_REF_NAME#v}"',
        "needs: wait_for_npm_approval",
        "scripts/verify-npm-release.sh",
        "needs: verify_npm_approved",
        '"${PACKAGE}@${VERSION}"',
        "needs: [publish, install_proof, version_tag_image, smoke_npm_approved]",
        "GitHub Latest remains blocked",
        "Wait until BOTH npm stage jobs succeed",
        "download and inspect BOTH staged tarballs",
        "reject remaining stages before any newer release",
    ):
        require(release, policy, "two-package staged npm release gate")

    stager = (ROOT / "scripts" / "stage-npm-release.sh").read_text(encoding="utf-8")
    waiter = (ROOT / "scripts" / "wait-npm-approval.sh").read_text(encoding="utf-8")
    for policy in (
        'npm stage publish "$tarball" --access public --tag "$channel"',
        "--provenance",
        "exact bytes and provenance verified before skipping staging",
        "OIDC identity cannot inspect staged packages",
        "human 2FA approval",
        'node "$release_order_script" npm-channel "$package" "$channel"',
        "assert_channel_not_newer before",
        "assert_channel_not_newer after",
        "expected integrity=",
        "Never cut or approve a newer release while this older stage remains pending",
        "Treat ${version} as pending and reject it before any approval or newer release",
    ):
        require(stager, policy, "OIDC npm staging helper")
    for policy in (
        'packages=("@kinlab/kin" "@kinlab/kin-mcp")',
        "Partial npm approval detected",
        "already newer",
        "Timed out waiting for both npm approvals",
        "GitHub Latest was not promoted",
        "Never leave an older stage pending across releases",
    ):
        require(waiter, policy, "anonymous npm approval waiter")

    verifier = (ROOT / "scripts" / "verify-npm-release.sh").read_text(encoding="utf-8")
    for helper_name, helper in (
        ("OIDC npm staging helper", stager),
        ("anonymous npm approval waiter", waiter),
        ("anonymous npm provenance verifier", verifier),
    ):
        require(
            helper,
            "env -u NODE_AUTH_TOKEN -u NPM_TOKEN",
            f"{helper_name} credential scrubbing",
        )

    public_npm_path = "\n".join((release, stager, waiter, verifier))
    if re.search(r"(?<!stage )npm publish(?:\s|$)", public_npm_path):
        raise AssertionError("public npm release path must remain stage-only")
    if re.search(
        r"npm stage (?:list|view|approve|reject|download)(?:\s|$)",
        public_npm_path,
    ):
        raise AssertionError(
            "OIDC release jobs must not invoke unsupported npm stage reads/writes"
        )

    for live_contract in (
        "Both public npm packages trust only firelock-ai/kin + release.yml + environment",
        "allow only `npm stage publish`, and disallow traditional tokens",
        "stage_npm_canonical",
        "stage_npm_compatibility",
    ):
        require(release, live_contract, "live stage-only npm trust contract")

    for forbidden in (
        "secrets.NPM_TOKEN",
        "release-candidate-",
        "npm dist-tag",
        "promote_npm",
        "promote-npm-release.sh",
    ):
        if forbidden in release or forbidden in stager or forbidden in waiter:
            raise AssertionError(
                f"staged npm release path contains retired authority: {forbidden}"
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
        "release workflow authority is tag-only, protected, pinned, GCP-free, "
        "and npm stage-only until human approval"
    )


if __name__ == "__main__":
    main()

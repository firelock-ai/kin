#!/usr/bin/env python3
"""Deterministic contract tests for the Kin registry-release receiver."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate-kin-registry-release.py"
AUTO_MERGE_PATH = ROOT / "scripts" / "ensure-kin-registry-wave-no-automerge.py"
IDENTITY_PATH = ROOT / "scripts" / "verify-kin-release-app-token.py"
ARTIFACT_PATH = ROOT / "scripts" / "kin-registry-wave-artifact.py"
ATTESTER_PATH = ROOT / "scripts" / "attest-kin-registry-wave.py"
HEAD_GUARD_PATH = ROOT / "scripts" / "verify-kin-registry-wave-head.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "kin-registry-release.yml"
ATTEST_WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "kin-registry-release-attest.yml"
)
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
KIN_ACTIONS_SHA = "398595fa14ba1eaebca6eb176facd8a57ce9db05"
SOURCE_SHA = "f1ac2bd93f0e3b7162f01481822087151e3b3af4"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


validator = load_module("kin_registry_receiver", VALIDATOR_PATH)
auto_merge = load_module("kin_registry_auto_merge", AUTO_MERGE_PATH)
identity = load_module("kin_registry_app_identity", IDENTITY_PATH)
artifact = load_module("kin_registry_wave_artifact_tests", ARTIFACT_PATH)
head_guard = load_module("kin_registry_head_guard", HEAD_GUARD_PATH)
attester = load_module("kin_registry_wave_attester_tests", ATTESTER_PATH)


def valid_payload(
    *, crate: str = "kin-db", source: str = "firelock-ai/kin-db"
) -> dict[str, str]:
    version = "0.7.69"
    return {
        "crate_name": crate,
        "crate_version": version,
        "delivery_id": f"{source}@{SOURCE_SHA}:{crate}@{version}",
        "source_repo": source,
        "source_sha": SOURCE_SHA,
    }


def valid_context(**overrides: str) -> dict[str, str]:
    context = {
        "event_name": "repository_dispatch",
        "event_action": "kin-registry-release",
        "actor": "troyjr4103",
        "repository": "firelock-ai/kin",
        "default_branch": "main",
        "ref": "refs/heads/main",
        "workflow_sha": "a" * 40,
    }
    context.update(overrides)
    return context


def job_block(workflow: str, job_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow job {job_id!r} is missing")
    return match.group(0)


def step_block(workflow: str, step_name: str) -> str:
    match = re.search(
        rf"(?ms)^      - name: {re.escape(step_name)}\n.*?"
        r"(?=^      - (?:name|uses):|^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow step {step_name!r} is missing")
    return match.group(0)


def run_git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def manifest(
    dependency: str = "=0.7.67",
    *,
    workspace_version: str = "0.6.1",
    extra: str = "",
) -> str:
    return (
        "[workspace]\n"
        "members = []\n\n"
        "[workspace.package]\n"
        f'version = "{workspace_version}"\n\n'
        "[workspace.dependencies]\n"
        f'kin-db = {{ version = "{dependency}", registry = "kin" }}\n'
        f"{extra}"
    )


def initialize_repo(repo: Path) -> str:
    run_git(repo, "init", "-q")
    run_git(repo, "config", "user.name", "Kin Test")
    run_git(repo, "config", "user.email", "kin-test@example.com")
    run_git(repo, "config", "commit.gpgsign", "false")
    run_git(repo, "config", "core.hooksPath", "/dev/null")
    (repo / "Cargo.toml").write_text(manifest(), encoding="utf-8")
    (repo / "Cargo.lock").write_text("version = 4\nkin-db 0.7.67\n", encoding="utf-8")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    # A baseline fuzz/Cargo.lock, mirroring the real repo shape: fuzz/Cargo.lock
    # is always a tracked file there, so ALLOWED_PATHS admits it as a path that
    # may be absent from a given wave's diff, never as a path absent from the
    # tree. Seeding it here keeps every other fixture's diff exactly as before
    # (an untouched tracked file produces no diff entry) and lets the two
    # fixtures that do touch it below register as modifications, not adds.
    (repo / "fuzz").mkdir(parents=True, exist_ok=True)
    (repo / "fuzz" / "Cargo.lock").write_text(
        "version = 4\nkin-model 0.7.23\n", encoding="utf-8"
    )
    run_git(repo, "add", "Cargo.toml", "Cargo.lock", "README.md", "fuzz/Cargo.lock")
    run_git(repo, "commit", "-q", "-m", "base")
    return run_git(repo, "rev-parse", "HEAD")


def restore_dependency_files(repo: Path, revision: str) -> None:
    run_git(
        repo,
        "restore",
        "--source",
        revision,
        "--staged",
        "--worktree",
        "--",
        "Cargo.lock",
        "Cargo.toml",
    )


def commit_dependency_head(
    repo: Path,
    *,
    dependency: str = "=0.7.69",
    workspace_version: str = "0.6.1",
    extra: str = "",
    lock_version: str = "0.7.69",
    marker: bool = True,
    readme: str | None = None,
    fuzz_lock_version: str | None = None,
) -> str:
    (repo / "Cargo.toml").write_text(
        manifest(dependency, workspace_version=workspace_version, extra=extra),
        encoding="utf-8",
    )
    (repo / "Cargo.lock").write_text(
        f"version = 4\nkin-db {lock_version}\n", encoding="utf-8"
    )
    if readme is not None:
        (repo / "README.md").write_text(readme, encoding="utf-8")
    if fuzz_lock_version is not None:
        # A modification, not an add: initialize_repo already committed a
        # baseline fuzz/Cargo.lock, matching how the real wave only ever
        # rewrites an already-tracked file.
        (repo / "fuzz" / "Cargo.lock").write_text(
            f"version = 4\nkin-model {fuzz_lock_version}\n", encoding="utf-8"
        )
    run_git(repo, "add", "-A")
    message = "dependency wave"
    if marker:
        message += f"\n\n{head_guard.COMMIT_MARKER}"
    run_git(repo, "commit", "-q", "-m", message)
    return run_git(repo, "rev-parse", "HEAD")


def attestation_documents(
    repo: Path,
    base: str,
    head: str,
    *,
    pull: int = 77,
    review_id: int = 41,
    comment_id: int = 51,
    run_id: int = 331,
    run_attempt: int = 2,
    created_at: str = "2026-08-27T22:00:01Z",
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    evidence = head_guard.validate_delta(repo, base, head, require_marker=True)
    tree = evidence.tree
    review_body = head_guard._review_body(
        head_guard.EXPECTED_REPOSITORY,
        pull,
        head,
        tree,
        base,
        evidence.delta_sha256,
        evidence.package_version,
        evidence.workspace_version,
        head_guard.RECEIVER_WORKFLOW_PATH,
        base,
        run_id,
        run_attempt,
    )
    review = {
        "id": review_id,
        "state": "COMMENTED",
        "commit_id": head,
        "body": review_body,
        "submitted_at": "2026-08-27T22:00:00Z",
        "user": {
            "id": head_guard.ATTESTATION_CREATOR_ID,
            "login": head_guard.ATTESTATION_CREATOR,
            "type": "Bot",
        },
    }
    comment_body = head_guard._comment_body(
        head_guard.EXPECTED_REPOSITORY,
        pull,
        review_id,
        head,
        tree,
        base,
        evidence.delta_sha256,
        evidence.package_version,
        evidence.workspace_version,
        head_guard.RECEIVER_WORKFLOW_PATH,
        base,
        run_id,
        run_attempt,
    )
    comment = {
        "id": comment_id,
        "body": comment_body,
        "created_at": created_at,
        "updated_at": created_at,
        "issue_url": f"https://api.github.com/repos/firelock-ai/kin/issues/{pull}",
        "html_url": (
            f"https://github.com/firelock-ai/kin/pull/{pull}"
            f"#issuecomment-{comment_id}"
        ),
        "user": {
            "id": head_guard.ATTESTATION_CREATOR_ID,
            "login": head_guard.ATTESTATION_CREATOR,
            "type": "Bot",
        },
        "performed_via_github_app": {
            "id": head_guard.ATTESTATION_APP_ID,
            "slug": head_guard.ATTESTATION_APP_SLUG,
            "owner": {
                "id": head_guard.ATTESTATION_APP_OWNER_ID,
                "login": head_guard.ATTESTATION_APP_OWNER,
            },
        },
    }
    return [review], [comment]


def outsider_attestation_comment(
    template: dict[str, object],
    *,
    comment_id: int = 52,
    malformed: bool = False,
) -> dict[str, object]:
    comment = copy.deepcopy(template)
    comment["id"] = comment_id
    comment["html_url"] = (
        f"https://github.com/{head_guard.EXPECTED_REPOSITORY}/pull/77"
        f"#issuecomment-{comment_id}"
    )
    comment["performed_via_github_app"] = None
    comment["user"] = {"id": 123, "login": "outsider", "type": "User"}
    if malformed:
        comment["body"] = head_guard.ATTESTATION_MARKER + "\nspoof"
    return comment


def workflow_run_document(
    policy_sha: str,
    *,
    conclusion: str = "success",
    run_id: int = 331,
    run_attempt: int = 2,
) -> dict[str, object]:
    return {
        "id": run_id,
        "run_attempt": run_attempt,
        "name": head_guard.RECEIVER_WORKFLOW_NAME,
        "path": head_guard.RECEIVER_WORKFLOW_PATH,
        "status": "completed",
        "conclusion": conclusion,
        "event": "repository_dispatch",
        "head_branch": head_guard.EXPECTED_BASE,
        "head_sha": policy_sha,
        "repository": {"full_name": head_guard.EXPECTED_REPOSITORY},
        "head_repository": {"full_name": head_guard.EXPECTED_REPOSITORY},
    }


def guard_api_fake(
    *,
    pull: dict[str, object],
    reviews: list[dict[str, object]],
    comments: list[dict[str, object]],
    policy_sha: str,
    open_pulls: list[dict[str, object]] | None = None,
    associated_pulls: list[dict[str, object]] | None = None,
):
    def fake(arguments: list[str]) -> object:
        endpoint = next(
            (item for item in arguments if item.startswith("repos/")), ""
        )
        if endpoint.endswith("/reviews?per_page=100"):
            return [reviews]
        if endpoint.endswith("/comments?per_page=100"):
            return [comments]
        if "/actions/runs/331/attempts/2" in endpoint:
            return workflow_run_document(policy_sha)
        if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
            return pull
        if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls":
            return open_pulls if open_pulls is not None else [{"number": 77}]
        if endpoint.endswith("/pulls") and "/commits/" in endpoint:
            return associated_pulls if associated_pulls is not None else [pull]
        raise AssertionError(f"unexpected mocked GitHub request: {arguments}")

    return fake


def pull_document(
    head: str,
    base: str,
    *,
    auto_merge_value: object = None,
    state: str = "open",
    merged_at: str | None = None,
) -> dict[str, object]:
    return {
        "number": 77,
        "state": state,
        "merged_at": merged_at,
        "head": {
            "sha": head,
            "ref": head_guard.WAVE_BRANCH,
            "repo": {"full_name": head_guard.EXPECTED_REPOSITORY},
        },
        "base": {"sha": base, "ref": head_guard.EXPECTED_BASE},
        "auto_merge": auto_merge_value,
    }


def graphql_pull_document(
    head: str,
    *,
    auto_merge: bool = False,
    queued: bool = False,
) -> str:
    return json.dumps(
        {
            "data": {
                "repository": {
                    "pullRequest": {
                        "id": "PR_node_77",
                        "number": 77,
                        "state": "OPEN",
                        "headRefName": head_guard.WAVE_BRANCH,
                        "headRefOid": head,
                        "baseRefName": head_guard.EXPECTED_BASE,
                        "headRepository": {
                            "nameWithOwner": head_guard.EXPECTED_REPOSITORY
                        },
                        "autoMergeRequest": {"enabledAt": "now"}
                        if auto_merge
                        else None,
                        "mergeQueueEntry": {"id": "MQE_node_77"}
                        if queued
                        else None,
                    }
                }
            }
        }
    )


def graphql_pull_node(head: str) -> dict[str, object]:
    return json.loads(graphql_pull_document(head))["data"]["repository"][
        "pullRequest"
    ]


def ci_run_document(
    head: str,
    base: str,
    *,
    run_id: int = 901,
    run_attempt: int = 1,
    created_at: str = "2026-08-27T22:00:02Z",
) -> dict[str, object]:
    repository_url = "https://api.github.com/repos/firelock-ai/kin"
    return {
        "id": run_id,
        "run_attempt": run_attempt,
        "name": attester.CI_WORKFLOW_NAME,
        "path": attester.CI_WORKFLOW_PATH,
        "event": "pull_request",
        "head_branch": head_guard.WAVE_BRANCH,
        "head_sha": head,
        "status": "in_progress",
        "conclusion": None,
        "created_at": created_at,
        "repository": {"full_name": head_guard.EXPECTED_REPOSITORY},
        "head_repository": {"full_name": head_guard.EXPECTED_REPOSITORY},
        "pull_requests": [
            {
                "number": 77,
                "head": {
                    "ref": head_guard.WAVE_BRANCH,
                    "sha": head,
                    "repo": {"name": "kin", "url": repository_url},
                },
                "base": {
                    "ref": head_guard.EXPECTED_BASE,
                    "sha": base,
                    "repo": {"name": "kin", "url": repository_url},
                },
            }
        ],
    }


def ci_job_document(
    *,
    run_id: int = 901,
    job_id: int = 9901,
    name: str = "Fast gate lint and policy",
    status: str = "queued",
    conclusion: str | None = None,
) -> dict[str, object]:
    return {
        "id": job_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "run_url": (
            f"https://api.github.com/repos/firelock-ai/kin/actions/runs/{run_id}"
        ),
    }


def ci_jobs_listing(jobs: list[dict[str, object]]) -> dict[str, object]:
    """Wrap an explicit job list the way the jobs endpoint reports it.

    A run that is seconds old reports an empty list here, which is the shape
    FIR-2865 turned into a hard failure, so tests need to build it directly.
    """
    return {"total_count": len(jobs), "jobs": jobs}


def ci_jobs_document(
    *,
    run_id: int = 901,
    name: str = "Fast gate lint and policy",
    status: str = "queued",
    conclusion: str | None = None,
) -> dict[str, object]:
    return ci_jobs_listing(
        [
            ci_job_document(
                run_id=run_id,
                name=name,
                status=status,
                conclusion=conclusion,
            )
        ]
    )


class ValidatorTests(unittest.TestCase):
    def test_accepts_exact_kindb_release_contract(self) -> None:
        self.assertEqual(
            validator.validate_context(**valid_context()), validator.DISPATCH_EVENT
        )
        self.assertEqual(
            validator.validate_payload(valid_payload())["crate_version"], "0.7.69"
        )

    def test_accepts_trusted_eventless_schedule(self) -> None:
        context = valid_context(
            event_name="schedule",
            event_action="",
            actor="schedule-owner-not-dispatch-allowlisted",
        )
        self.assertEqual(validator.validate_context(**context), validator.SCHEDULE_EVENT)
        result = self.run_cli(
            None, context=context, event={"schedule": "17 * * * *"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scheduled Kin registry reconciliation", result.stdout)

    def test_accepts_every_allowed_root_manifest_source_pair(self) -> None:
        for crate, source in validator.ALLOWED_SOURCES.items():
            with self.subTest(crate=crate):
                payload = validator.validate_payload(
                    valid_payload(crate=crate, source=source)
                )
                self.assertEqual(payload["source_repo"], source)

    def test_allowed_crates_are_exactly_the_root_registry_boundary(self) -> None:
        with (ROOT / "Cargo.toml").open("rb") as stream:
            dependencies = tomllib.load(stream)["workspace"]["dependencies"]
        root_registry_dependencies = {
            name
            for name, value in dependencies.items()
            if isinstance(value, dict) and value.get("registry") == "kin"
        }
        self.assertEqual(set(validator.ALLOWED_SOURCES), root_registry_dependencies)

    def test_rejects_wrong_event_action(self) -> None:
        with self.assertRaisesRegex(validator.ValidationError, "event action"):
            validator.validate_context(**valid_context(event_action="dependency-updated"))

    def test_rejects_untrusted_event_kind(self) -> None:
        with self.assertRaisesRegex(validator.ValidationError, "event name"):
            validator.validate_context(**valid_context(event_name="workflow_dispatch"))

    def test_rejects_missing_delivery_id(self) -> None:
        payload = valid_payload()
        del payload["delivery_id"]
        with self.assertRaisesRegex(validator.ValidationError, "missing=.*delivery_id"):
            validator.validate_payload(payload)

    def test_rejects_malformed_version(self) -> None:
        payload = valid_payload()
        payload["crate_version"] = "0.7"
        payload["delivery_id"] = (
            f"{payload['source_repo']}@{payload['source_sha']}:"
            f"{payload['crate_name']}@{payload['crate_version']}"
        )
        with self.assertRaisesRegex(validator.ValidationError, "stable SemVer"):
            validator.validate_payload(payload)

    def test_rejects_package_and_source_outside_boundary(self) -> None:
        with self.assertRaisesRegex(validator.ValidationError, "outside Kin's"):
            validator.validate_payload(
                valid_payload(crate="serde", source="serde-rs/serde")
            )
        with self.assertRaisesRegex(validator.ValidationError, "must come from"):
            validator.validate_payload(valid_payload(source="firelock-ai/kin-model"))

    def test_rejects_unbound_delivery_id(self) -> None:
        payload = valid_payload()
        payload["delivery_id"] = "not-the-source-tuple"
        with self.assertRaisesRegex(validator.ValidationError, "does not bind"):
            validator.validate_payload(payload)

    def test_cli_fails_loud_on_malformed_payload(self) -> None:
        payload = valid_payload()
        del payload["source_sha"]
        result = self.run_cli(payload)
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error title=Invalid Kin registry release::", result.stderr)

    def test_cli_labels_sender_sha_as_metadata_not_provenance(self) -> None:
        result = self.run_cli(valid_payload())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("correlation metadata, not source provenance", result.stdout)

    def run_cli(
        self,
        payload: dict[str, str] | None,
        *,
        context: dict[str, str] | None = None,
        event: dict[str, object] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        chosen_context = context or valid_context()
        if event is None:
            event = {"action": "kin-registry-release", "client_payload": payload}
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event), encoding="utf-8")
            command = ["python3", str(VALIDATOR_PATH), "--event-file", str(event_path)]
            for key, value in chosen_context.items():
                command.extend([f"--{key.replace('_', '-')}", value])
            return subprocess.run(
                command,
                cwd=ROOT,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                check=False,
            )


class AutoMergeTests(unittest.TestCase):
    def test_clears_auto_merge_and_queue_then_rereads_both_null(self) -> None:
        armed = pull_document("b" * 40, "a" * 40, auto_merge_value={"by": "captain"})
        with mock.patch.object(
            auto_merge,
            "run_gh",
            side_effect=[
                json.dumps([armed]),
                graphql_pull_document("b" * 40, auto_merge=True, queued=True),
                "",
                graphql_pull_document("b" * 40, queued=True),
                json.dumps({"data": {"dequeuePullRequest": {"mergeQueueEntry": None}}}),
                graphql_pull_document("b" * 40),
            ],
        ) as runner:
            result = auto_merge.ensure_disabled(
                repository="firelock-ai/kin",
                branch=head_guard.WAVE_BRANCH,
                base="main",
            )
        self.assertIsNone(result["auto_merge"])
        self.assertIsNone(result["merge_queue_entry"])
        disable = runner.call_args_list[2].args[0]
        self.assertIn("--disable-auto", disable)
        self.assertIn("--match-head-commit", disable)
        self.assertNotIn("--auto", disable)
        dequeue = runner.call_args_list[4].args[0]
        self.assertIn("dequeuePullRequest", " ".join(dequeue))
        self.assertIn("id=PR_node_77", dequeue)

    def test_fails_if_queue_state_remains_after_dequeue(self) -> None:
        armed = pull_document("b" * 40, "a" * 40)
        with mock.patch.object(
            auto_merge,
            "run_gh",
            side_effect=[
                json.dumps([armed]),
                graphql_pull_document("b" * 40, queued=True),
                json.dumps({"data": {"dequeuePullRequest": {"mergeQueueEntry": None}}}),
                graphql_pull_document("b" * 40, queued=True),
            ],
        ):
            with self.assertRaisesRegex(auto_merge.LandingStateError, "still has"):
                auto_merge.ensure_disabled(
                    repository="firelock-ai/kin",
                    branch=head_guard.WAVE_BRANCH,
                    base="main",
                )

    def test_post_write_binding_rejects_a_moved_head(self) -> None:
        moved = pull_document("c" * 40, "a" * 40)
        with mock.patch.object(
            auto_merge, "run_gh", return_value=json.dumps([moved])
        ):
            with self.assertRaisesRegex(auto_merge.LandingStateError, "moved"):
                auto_merge.ensure_disabled(
                    repository="firelock-ai/kin",
                    branch=head_guard.WAVE_BRANCH,
                    base="main",
                    expected_number=77,
                    expected_head="b" * 40,
                )


class HeadAdmissionTests(unittest.TestCase):
    def test_staged_evidence_matches_the_committed_dependency_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            (repo / "Cargo.toml").write_text(manifest("=0.7.69"), encoding="utf-8")
            (repo / "Cargo.lock").write_text(
                "version = 4\nkin-db 0.7.69\n", encoding="utf-8"
            )
            run_git(repo, "add", "Cargo.toml", "Cargo.lock")
            tree = run_git(repo, "write-tree")
            staged = head_guard.validate_index_delta(repo, base, tree)
            run_git(
                repo,
                "commit",
                "-q",
                "-m",
                f"dependency wave\n\n{head_guard.COMMIT_MARKER}",
            )
            head = run_git(repo, "rev-parse", "HEAD")
            committed = head_guard.validate_delta(
                repo, base, head, require_marker=True
            )
            self.assertEqual(staged.tree, committed.tree)
            self.assertEqual(staged.delta_sha256, committed.delta_sha256)
            self.assertEqual(staged.package_version, committed.package_version)
            self.assertEqual(staged.workspace_version, committed.workspace_version)

    def test_exact_release_app_attestation_binds_allowed_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            # Touches all three admitted paths, so evidence.paths below covers
            # the full ALLOWED_PATHS set, including the detached fuzz workspace
            # lock the receiver now regenerates alongside the root pins.
            head = commit_dependency_head(repo, fuzz_lock_version="0.7.24")
            reviews, comments = attestation_documents(repo, base, head)
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments,
                expected_base=base,
            )
            self.assertEqual(evidence.paths, head_guard.ALLOWED_PATHS)

    def test_attestation_requires_exact_terminal_receiver_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            reviews, comments = attestation_documents(repo, base, head)
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments,
                expected_base=base,
                workflow_run=workflow_run_document(base),
            )
            self.assertEqual(evidence.head, head)
            wrong_bot = outsider_attestation_comment(comments[0], comment_id=55)
            wrong_bot["performed_via_github_app"] = copy.deepcopy(
                comments[0]["performed_via_github_app"]
            )
            wrong_bot["user"] = {
                "id": 1,
                "login": head_guard.ATTESTATION_CREATOR,
                "type": "Bot",
            }
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments + [wrong_bot],
            )
            self.assertEqual(evidence.head, head)
            failed = workflow_run_document(base, conclusion="failure")
            with self.assertRaisesRegex(head_guard.AdmissionError, "successful"):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    reviews,
                    comments,
                    workflow_run=failed,
                )
            wrong_policy = workflow_run_document("d" * 40)
            with self.assertRaisesRegex(head_guard.AdmissionError, "successful"):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    reviews,
                    comments,
                    workflow_run=wrong_policy,
                )

    def test_rejects_non_admitted_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo, readme="not admitted\n")
            with self.assertRaisesRegex(head_guard.AdmissionError, "README.md"):
                head_guard.validate_delta(repo, base, head, require_marker=True)

    def test_rejects_workspace_version_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo, workspace_version="0.6.2")
            with self.assertRaisesRegex(head_guard.AdmissionError, "workspace version"):
                head_guard.validate_delta(repo, base, head, require_marker=True)

    def test_ignores_body_spoof_without_exact_app_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            reviews, comments = attestation_documents(repo, base, head)
            wrong_app = outsider_attestation_comment(comments[0])
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments + [wrong_app],
            )
            self.assertEqual(evidence.head, head)
            with self.assertRaises(head_guard.PendingAttestation):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    reviews,
                    [wrong_app],
                )
            same_login = outsider_attestation_comment(comments[0], comment_id=53)
            same_login["user"] = {
                "id": 1,
                "login": head_guard.ATTESTATION_CREATOR,
                "type": "Bot",
            }
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments + [same_login],
            )
            self.assertEqual(evidence.head, head)
            different_app = outsider_attestation_comment(
                comments[0], comment_id=54, malformed=True
            )
            different_app["performed_via_github_app"] = copy.deepcopy(
                comments[0]["performed_via_github_app"]
            )
            different_app["performed_via_github_app"]["id"] = 15368
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments + [different_app],
            )
            self.assertEqual(evidence.head, head)

    def test_rejects_malformed_exact_app_comment_but_ignores_outsider_marker(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            reviews, comments = attestation_documents(repo, base, head)
            outsider = outsider_attestation_comment(comments[0], malformed=True)
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments + [outsider],
            )
            self.assertEqual(evidence.head, head)
            exact_app_malformed = copy.deepcopy(comments[0])
            exact_app_malformed["body"] = head_guard.ATTESTATION_MARKER + "\nspoof"
            with self.assertRaisesRegex(head_guard.AdmissionError, "malformed"):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    reviews,
                    [exact_app_malformed],
                )
            wrong_exact_app_identity = copy.deepcopy(comments[0])
            wrong_exact_app_identity["performed_via_github_app"]["slug"] = "wrong"
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments + [wrong_exact_app_identity],
            )
            self.assertEqual(evidence.head, head)
            with self.assertRaises(head_guard.PendingAttestation):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    reviews,
                    [wrong_exact_app_identity],
                )

    def test_rejects_edited_comment_deleted_review_and_dismissed_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            reviews, comments = attestation_documents(repo, base, head)
            edited = copy.deepcopy(comments)
            edited[0]["updated_at"] = "2026-08-27T22:01:00Z"
            with self.assertRaisesRegex(head_guard.AdmissionError, "was edited"):
                head_guard.validate_attestation(
                    repo, head_guard.EXPECTED_REPOSITORY, 77, head, reviews, edited
                )
            with self.assertRaisesRegex(head_guard.AdmissionError, "deleted or missing"):
                head_guard.validate_attestation(
                    repo, head_guard.EXPECTED_REPOSITORY, 77, head, [], comments
                )
            dismissed = copy.deepcopy(reviews)
            dismissed[0]["state"] = "DISMISSED"
            with self.assertRaisesRegex(head_guard.AdmissionError, "dismissed"):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    dismissed,
                    comments,
                )

    def test_rejects_stale_review_and_post_review_synchronize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            reviews, comments = attestation_documents(repo, base, head)
            stale = copy.deepcopy(reviews)
            stale[0]["commit_id"] = base
            with self.assertRaisesRegex(head_guard.AdmissionError, "stale"):
                head_guard.validate_attestation(
                    repo, head_guard.EXPECTED_REPOSITORY, 77, head, stale, comments
                )
            with self.assertRaises(head_guard.PendingAttestation):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    "c" * 40,
                    reviews,
                    comments,
                )

    def test_rejects_conflicting_current_head_attestations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            reviews, comments = attestation_documents(repo, base, head)
            second_reviews, second_comments = attestation_documents(
                repo,
                base,
                head,
                review_id=42,
                comment_id=52,
            )
            actual_tree = run_git(repo, "rev-parse", f"{head}^{{tree}}")
            conflicting_tree = "d" * 40
            second_reviews[0]["body"] = str(second_reviews[0]["body"]).replace(
                f"tree={actual_tree}", f"tree={conflicting_tree}"
            )
            second_comments[0]["body"] = str(second_comments[0]["body"]).replace(
                f"tree={actual_tree}", f"tree={conflicting_tree}"
            )
            with self.assertRaisesRegex(head_guard.AdmissionError, "conflicting"):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    reviews + second_reviews,
                    comments + second_comments,
                )

    def test_rejects_tampered_delta_and_version_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            reviews, comments = attestation_documents(repo, base, head)
            admitted = head_guard.validate_delta(repo, base, head, require_marker=True)

            bad_delta_reviews = copy.deepcopy(reviews)
            bad_delta_comments = copy.deepcopy(comments)
            for document in (bad_delta_reviews[0], bad_delta_comments[0]):
                document["body"] = str(document["body"]).replace(
                    f"delta_sha256={admitted.delta_sha256}",
                    f"delta_sha256={'c' * 64}",
                )
            with self.assertRaisesRegex(head_guard.AdmissionError, "fingerprint"):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    bad_delta_reviews,
                    bad_delta_comments,
                )

            bad_version_reviews = copy.deepcopy(reviews)
            bad_version_comments = copy.deepcopy(comments)
            for document in (bad_version_reviews[0], bad_version_comments[0]):
                document["body"] = str(document["body"]).replace(
                    f"workspace_version={admitted.workspace_version}",
                    "workspace_version=9.9.9",
                )
            with self.assertRaisesRegex(head_guard.AdmissionError, "workspace version"):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    bad_version_reviews,
                    bad_version_comments,
                )

    def test_rejects_wrong_pull_and_wrong_base_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            reviews, comments = attestation_documents(repo, base, head, pull=78)
            with self.assertRaisesRegex(head_guard.AdmissionError, "another pull"):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    reviews,
                    comments,
                )
            pull = pull_document(head, base)
            pull["base"]["ref"] = "not-main"
            with self.assertRaisesRegex(head_guard.AdmissionError, "first-party"):
                head_guard.validate_pull(
                    pull,
                    repository=head_guard.EXPECTED_REPOSITORY,
                    expected_head=head,
                    require_open=True,
                )

    def test_accepts_a_descendant_pull_base_and_rejects_an_unrelated_one(self) -> None:
        # The pull base is main's tip at the pull's last push, so it moves past
        # the attested base whenever a lane lands between the receiver's
        # checkout and its push. Protected main at or after the attested base
        # is what the attestation needs; a base the attested base does not
        # reach descends from something else.
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            reviews, comments = attestation_documents(repo, base, head)
            run_git(repo, "switch", "-q", "-c", "advanced", base)
            (repo / "README.md").write_text("advanced\n", encoding="utf-8")
            run_git(repo, "add", "README.md")
            run_git(repo, "commit", "-q", "-m", "advance main")
            advanced_base = run_git(repo, "rev-parse", "HEAD")
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments,
                expected_base=advanced_base,
            )
            self.assertEqual(evidence.base, base)
            run_git(repo, "switch", "-q", "--orphan", "unrelated")
            (repo / "Cargo.toml").write_text(manifest(), encoding="utf-8")
            (repo / "Cargo.lock").write_text(
                "version = 4\nkin-db 0.7.67\n", encoding="utf-8"
            )
            (repo / "README.md").write_text("unrelated\n", encoding="utf-8")
            run_git(repo, "add", "-A")
            run_git(repo, "commit", "-q", "-m", "unrelated root")
            unrelated_base = run_git(repo, "rev-parse", "HEAD")
            with self.assertRaisesRegex(head_guard.AdmissionError, "not an ancestor"):
                head_guard.validate_attestation(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    77,
                    head,
                    reviews,
                    comments,
                    expected_base=unrelated_base,
                )

    def test_rejects_server_side_auto_merge(self) -> None:
        pull = pull_document(
            "b" * 40,
            "a" * 40,
            auto_merge_value={"enabled_by": {"login": "captain"}},
        )
        with self.assertRaisesRegex(head_guard.AdmissionError, "auto-merge armed"):
            head_guard.validate_pull(
                pull,
                repository=head_guard.EXPECTED_REPOSITORY,
                expected_head="b" * 40,
                require_open=True,
            )

    def test_classic_delivery_compares_intended_patch_not_full_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            run_git(repo, "switch", "-q", "-c", "admitted")
            admitted_head = commit_dependency_head(repo)
            admitted = head_guard.validate_delta(
                repo, base, admitted_head, require_marker=True
            )

            run_git(repo, "switch", "-q", "-c", "delivery", base)
            (repo / "README.md").write_text("main advanced\n", encoding="utf-8")
            run_git(repo, "add", "README.md")
            run_git(repo, "commit", "-q", "-m", "main advanced")
            delivery_base = run_git(repo, "rev-parse", "HEAD")
            delivery_head = commit_dependency_head(repo, marker=False)
            delivered = head_guard.validate_delta(
                repo, delivery_base, delivery_head, require_marker=False
            )
            self.assertNotEqual(admitted.tree, delivered.tree)
            head_guard.verify_delivery_tree(repo, admitted, delivered)

    def test_classic_delivery_rejects_a_different_patch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            run_git(repo, "switch", "-q", "-c", "admitted")
            admitted_head = commit_dependency_head(repo)
            admitted = head_guard.validate_delta(
                repo, base, admitted_head, require_marker=True
            )
            run_git(repo, "switch", "-q", "-c", "delivery", base)
            delivered_head = commit_dependency_head(
                repo,
                dependency="=0.7.70",
                lock_version="0.7.70",
                marker=False,
            )
            delivered = head_guard.validate_delta(
                repo, base, delivered_head, require_marker=False
            )
            with self.assertRaisesRegex(head_guard.AdmissionError, "delivery tree"):
                head_guard.verify_delivery_tree(repo, admitted, delivered)


class InstallationIdentityTests(unittest.TestCase):
    def test_contract_fake_accepts_only_installation_compatible_endpoints(self) -> None:
        calls: list[list[str]] = []

        def fake(arguments: list[str]) -> str:
            calls.append(arguments)
            if arguments == ["api", "users/kin-release-bot[bot]"]:
                return json.dumps(
                    {
                        "id": identity.EXPECTED_BOT_ID,
                        "login": identity.EXPECTED_BOT_LOGIN,
                        "type": "Bot",
                    }
                )
            if arguments == ["api", "installation/repositories?per_page=100"]:
                return json.dumps(
                    {
                        "total_count": 1,
                        "repositories": [{"full_name": identity.EXPECTED_REPOSITORY}],
                    }
                )
            raise AssertionError(f"unsupported token-class endpoint: {arguments}")

        with mock.patch.object(identity, "run_gh", side_effect=fake):
            result = identity.verify_identity(
                app_slug=identity.EXPECTED_APP_SLUG,
                repository=identity.EXPECTED_REPOSITORY,
            )
        self.assertEqual(result["bot_id"], identity.EXPECTED_BOT_ID)
        self.assertEqual(
            calls,
            [
                ["api", "users/kin-release-bot[bot]"],
                ["api", "installation/repositories?per_page=100"],
            ],
        )
        self.assertNotIn(["api", "user"], calls)

    def test_rejects_wrong_installation_scope(self) -> None:
        responses = [
            json.dumps(
                {
                    "id": identity.EXPECTED_BOT_ID,
                    "login": identity.EXPECTED_BOT_LOGIN,
                    "type": "Bot",
                }
            ),
            json.dumps(
                {
                    "total_count": 2,
                    "repositories": [
                        {"full_name": identity.EXPECTED_REPOSITORY},
                        {"full_name": "firelock-ai/kin-db"},
                    ],
                }
            ),
        ]
        with mock.patch.object(identity, "run_gh", side_effect=responses):
            with self.assertRaisesRegex(identity.IdentityError, "scoped"):
                identity.verify_identity(
                    app_slug=identity.EXPECTED_APP_SLUG,
                    repository=identity.EXPECTED_REPOSITORY,
                )


class CandidateArtifactTests(unittest.TestCase):
    def _prepared(self, directory: str) -> tuple[Path, Path, str, str]:
        root = Path(directory)
        repo = root / "repo"
        repo.mkdir()
        candidate = root / "candidate"
        base = initialize_repo(repo)
        (repo / "Cargo.toml").write_text(manifest("=0.7.69"), encoding="utf-8")
        (repo / "Cargo.lock").write_text(
            "version = 4\nkin-db 0.7.69\n", encoding="utf-8"
        )
        run_git(repo, "add", "Cargo.toml", "Cargo.lock")
        tree = run_git(repo, "write-tree")
        artifact.prepare_candidate(
            workspace=repo,
            output_dir=candidate,
            repository=artifact.EXPECTED_REPOSITORY,
            policy_sha=base,
            base=base,
            expected_tree=tree,
        )
        return repo, candidate, base, tree

    def test_hash_bound_candidate_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, candidate, base, tree = self._prepared(directory)
            restore_dependency_files(repo, base)
            result = artifact.apply_candidate(
                workspace=repo,
                artifact_dir=candidate,
                repository=artifact.EXPECTED_REPOSITORY,
                policy_sha=base,
                base=base,
            )
            self.assertEqual(result["tree"], tree)
            self.assertEqual(
                run_git(repo, "diff", "--cached", "--name-only").splitlines(),
                ["Cargo.lock", "Cargo.toml"],
            )

    def test_rejects_path_and_github_env_poisoning_entries_before_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, candidate, base, _ = self._prepared(directory)
            restore_dependency_files(repo, base)
            poison = candidate / "python3"
            poison.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            poison.chmod(0o755)
            env_file = Path(directory) / "github-env"
            with mock.patch.dict(
                os.environ,
                {"PATH": str(candidate), "GITHUB_ENV": str(env_file)},
                clear=False,
            ):
                with self.assertRaisesRegex(artifact.ArtifactError, "allowlist"):
                    artifact.apply_candidate(
                        workspace=repo,
                        artifact_dir=candidate,
                        repository=artifact.EXPECTED_REPOSITORY,
                        policy_sha=base,
                        base=base,
                    )
            self.assertEqual(run_git(repo, "status", "--porcelain"), "")
            self.assertFalse(env_file.exists())

    def test_rejects_tampered_candidate_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, candidate, base, _ = self._prepared(directory)
            restore_dependency_files(repo, base)
            (candidate / "Cargo.lock").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(artifact.ArtifactError, "digest"):
                artifact.apply_candidate(
                    workspace=repo,
                    artifact_dir=candidate,
                    repository=artifact.EXPECTED_REPOSITORY,
                    policy_sha=base,
                    base=base,
                )

    def test_no_change_result_is_explicit_and_server_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result_file = Path(directory) / "result.json"
            policy = "a" * 40
            result = artifact.finalize_no_change(
                output_file=result_file,
                repository=artifact.EXPECTED_REPOSITORY,
                policy_sha=policy,
                base=policy,
                workflow_path=artifact.EXPECTED_WORKFLOW_PATH,
                run_id=331,
                run_attempt=2,
            )
            self.assertIs(result["changed"], False)
            validated = artifact.validate_result(
                result_file=result_file,
                repository=artifact.EXPECTED_REPOSITORY,
                workflow_path=artifact.EXPECTED_WORKFLOW_PATH,
                policy_sha=policy,
                run_id=331,
                run_attempt=2,
            )
            self.assertEqual(validated, result)
            with self.assertRaisesRegex(artifact.ArtifactError, "authority"):
                artifact.validate_result(
                    result_file=result_file,
                    repository=artifact.EXPECTED_REPOSITORY,
                    workflow_path=artifact.EXPECTED_WORKFLOW_PATH,
                    policy_sha="b" * 40,
                    run_id=331,
                    run_attempt=2,
                )


class PostCompletionAttesterTests(unittest.TestCase):
    def _changed(
        self,
        directory: str,
        *,
        run_id: int = 331,
        run_attempt: int = 2,
    ) -> tuple[Path, Path, Path, str, str]:
        root = Path(directory)
        repo = root / "repo"
        repo.mkdir()
        candidate = root / "candidate"
        base = initialize_repo(repo)
        (repo / "Cargo.toml").write_text(manifest("=0.7.69"), encoding="utf-8")
        (repo / "Cargo.lock").write_text(
            "version = 4\nkin-db 0.7.69\n", encoding="utf-8"
        )
        run_git(repo, "add", "Cargo.toml", "Cargo.lock")
        tree = run_git(repo, "write-tree")
        artifact.prepare_candidate(
            workspace=repo,
            output_dir=candidate,
            repository=artifact.EXPECTED_REPOSITORY,
            policy_sha=base,
            base=base,
            expected_tree=tree,
        )
        run_git(
            repo,
            "commit",
            "-q",
            "-m",
            f"dependency wave\n\n{head_guard.COMMIT_MARKER}",
        )
        head = run_git(repo, "rev-parse", "HEAD")
        result_file = root / f"result-{run_id}" / "result.json"
        artifact.finalize_admission(
            artifact_dir=candidate,
            output_file=result_file,
            repository=artifact.EXPECTED_REPOSITORY,
            policy_sha=base,
            base=base,
            pull=77,
            head=head,
            workflow_path=artifact.EXPECTED_WORKFLOW_PATH,
            run_id=run_id,
            run_attempt=run_attempt,
        )
        return repo, candidate, result_file, base, head

    @staticmethod
    def _live_graphql(head: str):
        return mock.patch.object(
            attester.landing,
            "_graphql_pull",
            return_value=graphql_pull_node(head),
        )

    def test_no_change_receiver_completes_without_minting_an_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_dir = root / "result"
            result_file = result_dir / "result.json"
            policy = "a" * 40
            artifact.finalize_no_change(
                output_file=result_file,
                repository=artifact.EXPECTED_REPOSITORY,
                policy_sha=policy,
                base=policy,
                workflow_path=artifact.EXPECTED_WORKFLOW_PATH,
                run_id=331,
                run_attempt=2,
            )
            event_file = root / "event.json"
            event_file.write_text(
                json.dumps(
                    {
                        "action": "completed",
                        "workflow_run": workflow_run_document(policy),
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(
                attester,
                "gh_json",
                return_value=workflow_run_document(policy),
            ) as api:
                result = attester.validate_for_attestation(
                    event_file=event_file,
                    admission_file=result_file,
                    workspace=root,
                    repository=attester.EXPECTED_REPOSITORY,
                )
            self.assertIs(result["changed"], False)
            self.assertEqual(api.call_count, 1)
            self.assertIn("/attempts/2", api.call_args.args[0][-1])

    def test_changed_post_is_persisted_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _, result_file, base, head = self._changed(directory)
            pull = pull_document(head, base)
            reviews, comments = attestation_documents(repo, base, head)
            comments.append(
                outsider_attestation_comment(comments[0], malformed=True)
            )
            posted = False
            writes: list[str] = []

            def fake(arguments: list[str]) -> object:
                nonlocal posted
                endpoint = next(
                    (item for item in arguments if item.startswith("repos/")), ""
                )
                if endpoint.endswith("/git/ref/heads/main"):
                    return {"object": {"sha": base}}
                if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
                    return pull
                if endpoint.endswith("/reviews?per_page=100"):
                    return [reviews if posted else []]
                if endpoint.endswith("/comments?per_page=100"):
                    return [comments if posted else []]
                if endpoint.endswith("/pulls/77/reviews"):
                    writes.append("review")
                    return reviews[0]
                if endpoint.endswith("/issues/77/comments"):
                    writes.append("comment")
                    posted = True
                    return comments[0]
                if endpoint.endswith("/pulls/77/reviews/41"):
                    return reviews[0]
                if endpoint.endswith("/issues/comments/51"):
                    return comments[0]
                raise AssertionError(f"unexpected mocked GitHub request: {arguments}")

            with mock.patch.object(attester, "gh_json", side_effect=fake), self._live_graphql(
                head
            ):
                first = attester.post_attestation(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                )
                second = attester.post_attestation(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                )
            self.assertIs(first["created"], True)
            self.assertIs(second["created"], False)
            self.assertEqual(first["comment_created_at"], comments[0]["created_at"])
            self.assertEqual(second["comment_id"], first["comment_id"])
            self.assertEqual(writes, ["review", "comment"])

    def test_repeated_receiver_reuses_one_attestation_and_guard_stays_green(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, candidate, _, base, head = self._changed(directory)
            second_result = Path(directory) / "result-332" / "result.json"
            artifact.finalize_admission(
                artifact_dir=candidate,
                output_file=second_result,
                repository=artifact.EXPECTED_REPOSITORY,
                policy_sha=base,
                base=base,
                pull=77,
                head=head,
                workflow_path=artifact.EXPECTED_WORKFLOW_PATH,
                run_id=332,
                run_attempt=1,
            )
            second_run = workflow_run_document(
                base,
                run_id=332,
                run_attempt=1,
            )
            event_file = Path(directory) / "event-332.json"
            event_file.write_text(
                json.dumps({"action": "completed", "workflow_run": second_run}),
                encoding="utf-8",
            )
            pull = pull_document(head, base)
            reviews, comments = attestation_documents(repo, base, head)

            def fake(arguments: list[str]) -> object:
                endpoint = next(
                    (item for item in arguments if item.startswith("repos/")), ""
                )
                if "/actions/runs/332/attempts/1" in endpoint:
                    return second_run
                if endpoint.endswith("/git/ref/heads/main"):
                    return {"object": {"sha": base}}
                if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
                    return pull
                if endpoint.endswith("/reviews?per_page=100"):
                    return [reviews]
                if endpoint.endswith("/comments?per_page=100"):
                    return [comments]
                raise AssertionError(f"unexpected mocked GitHub request: {arguments}")

            with mock.patch.object(attester, "gh_json", side_effect=fake), mock.patch.object(
                attester.guard,
                "gh_json",
                return_value=workflow_run_document(base),
            ), self._live_graphql(head):
                result = attester.validate_for_attestation(
                    event_file=event_file,
                    admission_file=second_result,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                )
            self.assertIs(result["changed"], True)
            self.assertIs(result["needs_attestation"], False)
            evidence = head_guard.validate_attestation(
                repo,
                head_guard.EXPECTED_REPOSITORY,
                77,
                head,
                reviews,
                comments,
                expected_base=base,
                workflow_run=workflow_run_document(base),
            )
            self.assertEqual(evidence.head, head)

    def test_attestation_survives_main_advancing_and_refuses_a_rewrite(self) -> None:
        # Main advances after the receiver's checkout and the pull-request
        # action rebases the wave onto the new tip, so the live head's parent
        # and the pull base are the tip, not the admitted base. The admission
        # still names the admitted base and tree; the attester has to accept
        # the rebased head and refuse a rewritten main.
        with tempfile.TemporaryDirectory() as directory:
            repo, _, result_file, base, admitted_head = self._changed(directory)
            run = workflow_run_document(base)
            event_file = Path(directory) / "event.json"
            event_file.write_text(
                json.dumps({"action": "completed", "workflow_run": run}),
                encoding="utf-8",
            )
            run_git(repo, "switch", "-q", "--detach", base)
            (repo / "README.md").write_text("advanced\n", encoding="utf-8")
            run_git(repo, "add", "README.md")
            run_git(repo, "commit", "-q", "-m", "advance main")
            tip = run_git(repo, "rev-parse", "HEAD")
            run_git(repo, "cherry-pick", admitted_head)
            head = run_git(repo, "rev-parse", "HEAD")
            admission = json.loads(result_file.read_text(encoding="utf-8"))
            admission["head"] = head
            result_file.write_text(json.dumps(admission, sort_keys=True), encoding="utf-8")
            pull = pull_document(head, tip)
            reviews, comments = attestation_documents(repo, base, admitted_head)
            for comment in comments:
                comment["body"] = comment["body"].replace(f"head={admitted_head}", f"head={head}")
            for review in reviews:
                review["commit_id"] = head
                review["body"] = review["body"].replace(f"head={admitted_head}", f"head={head}")

            def fake(relation: str):
                compare = {
                    "status": relation,
                    "ahead_by": 2 if relation == "ahead" else 1,
                    "behind_by": 0 if relation == "ahead" else 1,
                    "merge_base_commit": {"sha": base},
                }

                def answer(arguments: list[str]) -> object:
                    endpoint = next(
                        (item for item in arguments if item.startswith("repos/")), ""
                    )
                    if "/actions/runs/331/attempts/2" in endpoint:
                        return run
                    if endpoint.endswith("/git/ref/heads/main"):
                        return {"object": {"sha": tip}}
                    if endpoint.endswith(f"/compare/{base}...{tip}"):
                        return compare
                    if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
                        return pull
                    if endpoint.endswith("/reviews?per_page=100"):
                        return [reviews]
                    if endpoint.endswith("/comments?per_page=100"):
                        return [comments]
                    raise AssertionError(f"unexpected mocked GitHub request: {arguments}")

                return answer

            with mock.patch.object(
                attester, "gh_json", side_effect=fake("ahead")
            ), mock.patch.object(
                attester.guard, "gh_json", return_value=workflow_run_document(base)
            ), self._live_graphql(head):
                result = attester.validate_for_attestation(
                    event_file=event_file,
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                )
            self.assertIs(result["changed"], True)
            self.assertIs(result["needs_attestation"], False)

            with mock.patch.object(
                attester, "gh_json", side_effect=fake("diverged")
            ), mock.patch.object(
                attester.guard, "gh_json", return_value=workflow_run_document(base)
            ), self._live_graphql(head):
                with self.assertRaisesRegex(
                    attester.AttesterError, "not protected main history"
                ):
                    attester.validate_for_attestation(
                        event_file=event_file,
                        admission_file=result_file,
                        workspace=repo,
                        repository=attester.EXPECTED_REPOSITORY,
                    )

    def test_recheck_filters_irrelevant_same_sha_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _, result_file, base, head = self._changed(directory)
            pull = pull_document(head, base)
            reviews, comments = attestation_documents(repo, base, head)
            exact = ci_run_document(head, base, run_id=901)
            irrelevant = copy.deepcopy(exact)
            irrelevant["id"] = 900
            irrelevant["head_repository"] = {"full_name": "outsider/kin"}
            irrelevant["created_at"] = "not-a-timestamp"
            irrelevant["pull_requests"][0]["number"] = 123
            other_pull_same_branch = copy.deepcopy(irrelevant)
            other_pull_same_branch["id"] = 899
            other_pull_same_branch["head_repository"] = {
                "full_name": head_guard.EXPECTED_REPOSITORY
            }

            def fake_for_runs(runs: list[dict[str, object]]):
                def fake(arguments: list[str]) -> object:
                    endpoint = next(
                        (item for item in arguments if item.startswith("repos/")), ""
                    )
                    if endpoint.endswith("/git/ref/heads/main"):
                        return {"object": {"sha": base}}
                    if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
                        return pull
                    if endpoint.endswith("/reviews?per_page=100"):
                        return [reviews]
                    if endpoint.endswith("/comments?per_page=100"):
                        return [comments]
                    if endpoint.endswith("/actions/workflows/ci.yml/runs"):
                        return [{"total_count": len(runs), "workflow_runs": runs}]
                    if endpoint.endswith("/actions/runs/901/attempts/1/jobs"):
                        return ci_jobs_document(run_id=901)
                    if endpoint.endswith("/actions/runs/902/attempts/1/jobs"):
                        return ci_jobs_document(run_id=902)
                    raise AssertionError(
                        f"unexpected mocked GitHub request: {arguments}"
                    )

                return fake

            for runs in (
                [irrelevant, other_pull_same_branch, exact],
                [exact, other_pull_same_branch, irrelevant],
            ):
                with (
                    self.subTest(order=[int(run["id"]) for run in runs]),
                    mock.patch.object(
                        attester,
                        "gh_json",
                        side_effect=fake_for_runs(runs),
                    ),
                    mock.patch.object(
                        attester.guard,
                        "gh_json",
                        return_value=workflow_run_document(base),
                    ),
                    self._live_graphql(head),
                ):
                    recheck = attester.recheck_status(
                        admission_file=result_file,
                        workspace=repo,
                        repository=attester.EXPECTED_REPOSITORY,
                        wait_seconds=0,
                        require_recheck=True,
                    )
                    self.assertEqual(recheck["run_id"], 901)

            newest = ci_run_document(
                head,
                base,
                run_id=902,
                created_at="2026-08-27T22:00:03Z",
            )
            with mock.patch.object(
                attester,
                "gh_json",
                side_effect=fake_for_runs([newest, exact]),
            ), mock.patch.object(
                attester.guard,
                "gh_json",
                return_value=workflow_run_document(base),
            ), self._live_graphql(head):
                selected = attester.recheck_status(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                    wait_seconds=0,
                    require_recheck=True,
                )
            self.assertEqual(selected["run_id"], 902)

            with mock.patch.object(
                attester,
                "gh_json",
                side_effect=fake_for_runs([irrelevant, other_pull_same_branch]),
            ), mock.patch.object(
                attester.guard,
                "gh_json",
                return_value=workflow_run_document(base),
            ), self._live_graphql(head):
                missing = attester.recheck_status(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                    wait_seconds=0,
                    require_recheck=False,
                )
            self.assertIs(missing["needs_retrigger"], True)

            associated_but_wrong = copy.deepcopy(irrelevant)
            associated_but_wrong["created_at"] = "2026-08-27T22:00:03Z"
            associated_but_wrong["pull_requests"][0]["number"] = 77
            with mock.patch.object(
                attester,
                "gh_json",
                side_effect=fake_for_runs([associated_but_wrong]),
            ), mock.patch.object(
                attester.guard,
                "gh_json",
                return_value=workflow_run_document(base),
            ), self._live_graphql(head):
                with self.assertRaisesRegex(attester.AttesterError, "wrong authority"):
                    attester.recheck_status(
                        admission_file=result_file,
                        workspace=repo,
                        repository=attester.EXPECTED_REPOSITORY,
                        wait_seconds=0,
                        require_recheck=False,
                    )

    def test_late_attestation_retriggers_and_materializes_required_recheck(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _, result_file, base, head = self._changed(directory)
            pull = pull_document(head, base)
            reviews, comments = attestation_documents(repo, base, head)
            empty_runs = [{"total_count": 0, "workflow_runs": []}]

            def read_without_recheck(arguments: list[str]) -> object:
                endpoint = next(
                    (item for item in arguments if item.startswith("repos/")), ""
                )
                if endpoint.endswith("/git/ref/heads/main"):
                    return {"object": {"sha": base}}
                if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
                    return pull
                if endpoint.endswith("/reviews?per_page=100"):
                    return [reviews]
                if endpoint.endswith("/comments?per_page=100"):
                    return [comments]
                if endpoint.endswith("/actions/workflows/ci.yml/runs"):
                    return empty_runs
                raise AssertionError(f"unexpected mocked GitHub request: {arguments}")

            with mock.patch.object(
                attester, "gh_json", side_effect=read_without_recheck
            ), mock.patch.object(
                attester.guard,
                "gh_json",
                return_value=workflow_run_document(base),
            ), self._live_graphql(head):
                before = attester.recheck_status(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                    wait_seconds=0,
                    require_recheck=False,
                )
            self.assertIs(before["needs_retrigger"], True)

            states: list[str] = []

            def writer(arguments: list[str]) -> object:
                endpoint = next(
                    (item for item in arguments if item.startswith("repos/")), ""
                )
                if endpoint.endswith("/git/ref/heads/main"):
                    return {"object": {"sha": base}}
                if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
                    requested_state = next(
                        (
                            item.split("=", 1)[1]
                            for item in arguments
                            if item.startswith("state=")
                        ),
                        None,
                    )
                    if requested_state is not None:
                        states.append(requested_state)
                        return pull_document(head, base, state=requested_state)
                    return pull
                if endpoint.endswith("/reviews?per_page=100"):
                    return [reviews]
                if endpoint.endswith("/comments?per_page=100"):
                    return [comments]
                raise AssertionError(f"unexpected mocked GitHub request: {arguments}")

            with mock.patch.object(attester, "gh_json", side_effect=writer), self._live_graphql(
                head
            ):
                reopened = attester.retrigger_pull(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                )
            self.assertIs(reopened["reopened"], True)
            self.assertEqual(states, ["closed", "open"])

            run = ci_run_document(head, base)

            def read_with_recheck(arguments: list[str]) -> object:
                endpoint = next(
                    (item for item in arguments if item.startswith("repos/")), ""
                )
                if endpoint.endswith("/git/ref/heads/main"):
                    return {"object": {"sha": base}}
                if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
                    return pull
                if endpoint.endswith("/reviews?per_page=100"):
                    return [reviews]
                if endpoint.endswith("/comments?per_page=100"):
                    return [comments]
                if endpoint.endswith("/actions/workflows/ci.yml/runs"):
                    return [{"total_count": 1, "workflow_runs": [run]}]
                if endpoint.endswith("/actions/runs/901/attempts/1/jobs"):
                    return ci_jobs_document()
                raise AssertionError(f"unexpected mocked GitHub request: {arguments}")

            with mock.patch.object(
                attester, "gh_json", side_effect=read_with_recheck
            ), mock.patch.object(
                attester.guard,
                "gh_json",
                return_value=workflow_run_document(base),
            ), self._live_graphql(head):
                after = attester.recheck_status(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                    wait_seconds=0,
                    require_recheck=True,
                )
            self.assertIs(after["needs_retrigger"], False)
            self.assertEqual(after["job_status"], "queued")

            def missing_gate(arguments: list[str]) -> object:
                endpoint = next(
                    (item for item in arguments if item.startswith("repos/")), ""
                )
                if endpoint.endswith("/actions/runs/901/attempts/1/jobs"):
                    return ci_jobs_document(name="not the required context")
                return read_with_recheck(arguments)

            with mock.patch.object(
                attester, "gh_json", side_effect=missing_gate
            ), mock.patch.object(
                attester.guard,
                "gh_json",
                return_value=workflow_run_document(base),
            ), self._live_graphql(head):
                with self.assertRaisesRegex(
                    attester.AttesterError,
                    r"looked for a job named 'Fast gate lint and policy'.*"
                    r"found only run 901 \(in_progress, 1 jobs listed\)",
                ):
                    attester.recheck_status(
                        admission_file=result_file,
                        workspace=repo,
                        repository=attester.EXPECTED_REPOSITORY,
                        wait_seconds=0,
                        require_recheck=True,
                    )

    def test_recheck_waits_for_a_young_runs_jobs_to_be_listed(self) -> None:
        """FIR-2865: the recheck read a three-second-old run and found no jobs.

        Run 33185320130 was created at 15:28:38Z, the attester read it at
        15:28:41Z, and its one 'Fast gate lint and policy' job started at
        15:28:57Z. The old code raised on that empty listing, so the raise
        escaped the wait loop and the step died 3.3 seconds into a 120 second
        budget. Each arm below pins one producer of an absent required fast gate
        apart from the others, because one message used to cover them all.
        """
        with tempfile.TemporaryDirectory() as directory:
            repo, _, result_file, base, head = self._changed(directory)
            pull = pull_document(head, base)
            reviews, comments = attestation_documents(repo, base, head)
            empty = ci_jobs_listing([])
            with_gate = ci_jobs_document()
            live = ci_run_document(head, base)
            finished = copy.deepcopy(live)
            finished["status"] = "completed"
            finished["conclusion"] = "failure"

            def reader(
                runs: list[dict[str, object]],
                listings: list[dict[str, object]],
            ) -> tuple[object, dict[str, int]]:
                """Serve the jobs endpoint one listing per call, then repeat the last."""
                calls = {"jobs": 0, "runs": 0}

                def fake(arguments: list[str]) -> object:
                    endpoint = next(
                        (item for item in arguments if item.startswith("repos/")), ""
                    )
                    if endpoint.endswith("/git/ref/heads/main"):
                        return {"object": {"sha": base}}
                    if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
                        return pull
                    if endpoint.endswith("/reviews?per_page=100"):
                        return [reviews]
                    if endpoint.endswith("/comments?per_page=100"):
                        return [comments]
                    if endpoint.endswith("/actions/workflows/ci.yml/runs"):
                        calls["runs"] += 1
                        return [{"total_count": len(runs), "workflow_runs": runs}]
                    if endpoint.endswith("/actions/runs/901/attempts/1/jobs"):
                        index = min(calls["jobs"], len(listings) - 1)
                        calls["jobs"] += 1
                        return listings[index]
                    raise AssertionError(
                        f"unexpected mocked GitHub request: {arguments}"
                    )

                return fake, calls

            @contextlib.contextmanager
            def observing(
                runs: list[dict[str, object]],
                listings: list[dict[str, object]],
            ):
                fake, calls = reader(runs, listings)
                slept: list[float] = []
                with mock.patch.object(
                    attester, "gh_json", side_effect=fake
                ), mock.patch.object(
                    attester.guard,
                    "gh_json",
                    return_value=workflow_run_document(base),
                ), mock.patch.object(
                    attester.time, "sleep", side_effect=slept.append
                ), self._live_graphql(head):
                    yield calls, slept

            # Arm one, the production shape. The gate appears on the third poll
            # and the wait has to survive the two empty ones.
            with observing([live], [empty, empty, with_gate]) as (calls, slept):
                arrived = attester.recheck_status(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                    wait_seconds=5,
                    require_recheck=True,
                )
            self.assertIs(arrived["needs_retrigger"], False)
            self.assertEqual(arrived["run_id"], 901)
            self.assertEqual(arrived["job_id"], 9901)
            self.assertEqual(arrived["job_status"], "queued")
            self.assertEqual(calls["jobs"], 3)
            self.assertEqual(len(slept), 2)

            # Arm two. A run already in flight is the reason NOT to retrigger,
            # because reopening the pull would cancel it.
            with observing([live], [empty]) as (calls, _):
                in_flight = attester.recheck_status(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                    wait_seconds=0,
                    require_recheck=False,
                )
            self.assertIs(in_flight["needs_retrigger"], False)
            self.assertEqual(calls["jobs"], 1)

            # Arm three. Under --require-recheck the deadline is still a
            # refusal, and the message names the job, the branch, the head and
            # the run it did find.
            with observing([live], [empty]) as (_, _slept):
                with self.assertRaisesRegex(
                    attester.AttesterError,
                    r"looked for a job named 'Fast gate lint and policy' on "
                    r"\.github/workflows/ci\.yml runs on "
                    r"automation/kin-registry-dependency-wave at head "
                    rf"{head}.*found only run 901 \(in_progress, 0 jobs listed\)",
                ):
                    attester.recheck_status(
                        admission_file=result_file,
                        workspace=repo,
                        repository=attester.EXPECTED_REPOSITORY,
                        wait_seconds=0,
                        require_recheck=True,
                    )

            # Arm four. A COMPLETED run that never published the gate is a real
            # authority failure, and no wait may soften it. One jobs call proves
            # it refused rather than waited.
            with observing(
                [finished], [ci_jobs_document(name="not the required context")]
            ) as (calls, slept):
                with self.assertRaisesRegex(
                    attester.AttesterError,
                    r"completed post-attestation CI run 901 publishes no job named "
                    r"'Fast gate lint and policy' among its 1 jobs",
                ):
                    attester.recheck_status(
                        admission_file=result_file,
                        workspace=repo,
                        repository=attester.EXPECTED_REPOSITORY,
                        wait_seconds=5,
                        require_recheck=True,
                    )
            self.assertEqual(calls["jobs"], 1)
            self.assertEqual(slept, [])

            # Arm five. Two gates never resolve by waiting, so a live run with
            # duplicates refuses on the first poll too.
            duplicated = ci_jobs_listing(
                [ci_job_document(job_id=9901), ci_job_document(job_id=9902)]
            )
            with observing([live], [duplicated]) as (calls, slept):
                with self.assertRaisesRegex(
                    attester.AttesterError,
                    r"post-attestation CI run 901 publishes 2 jobs named "
                    r"'Fast gate lint and policy'; the recheck requires exactly one",
                ):
                    attester.recheck_status(
                        admission_file=result_file,
                        workspace=repo,
                        repository=attester.EXPECTED_REPOSITORY,
                        wait_seconds=5,
                        require_recheck=True,
                    )
            self.assertEqual(calls["jobs"], 1)
            self.assertEqual(slept, [])

            # Arm six. No candidate run at all is the one case that still asks
            # for a retrigger, which is what separates it from arm two.
            with observing([], [empty]) as (calls, _):
                absent = attester.recheck_status(
                    admission_file=result_file,
                    workspace=repo,
                    repository=attester.EXPECTED_REPOSITORY,
                    wait_seconds=0,
                    require_recheck=False,
                )
            self.assertIs(absent["needs_retrigger"], True)
            self.assertEqual(calls["jobs"], 0)

    def test_retrigger_reopens_after_an_uncertain_close_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _, result_file, base, head = self._changed(directory)
            pull = pull_document(head, base)
            reviews, comments = attestation_documents(repo, base, head)
            reopened = False

            def writer(arguments: list[str]) -> object:
                nonlocal reopened
                endpoint = next(
                    (item for item in arguments if item.startswith("repos/")), ""
                )
                if endpoint.endswith("/git/ref/heads/main"):
                    return {"object": {"sha": base}}
                if endpoint == f"repos/{head_guard.EXPECTED_REPOSITORY}/pulls/77":
                    requested_state = next(
                        (
                            item.split("=", 1)[1]
                            for item in arguments
                            if item.startswith("state=")
                        ),
                        None,
                    )
                    if requested_state == "closed":
                        raise attester.AttesterError("close response was lost")
                    if requested_state == "open":
                        reopened = True
                        return pull
                    return pull
                if endpoint.endswith("/reviews?per_page=100"):
                    return [reviews]
                if endpoint.endswith("/comments?per_page=100"):
                    return [comments]
                raise AssertionError(f"unexpected mocked GitHub request: {arguments}")

            with mock.patch.object(attester, "gh_json", side_effect=writer), self._live_graphql(
                head
            ):
                with self.assertRaisesRegex(
                    attester.AttesterError,
                    "reopened after an invalid close response",
                ):
                    attester.retrigger_pull(
                        admission_file=result_file,
                        workspace=repo,
                        repository=attester.EXPECTED_REPOSITORY,
                    )
            self.assertIs(reopened, True)


class EventHandlerTests(unittest.TestCase):
    @staticmethod
    def pull_event(head: str, base: str, *, branch: str | None = None) -> dict[str, Any]:
        return {
            "pull_request": {
                "number": 77,
                "head": {"sha": head, "ref": branch or head_guard.WAVE_BRANCH},
                "base": {"sha": base, "ref": head_guard.EXPECTED_BASE},
            }
        }

    def test_verify_pull_request_and_current_base_movement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            pull = pull_document(head, base)
            reviews, comments = attestation_documents(repo, base, head)
            fake = guard_api_fake(
                pull=pull,
                reviews=reviews,
                comments=comments,
                policy_sha=base,
            )
            with mock.patch.object(head_guard, "gh_json", side_effect=fake):
                message = head_guard.verify_pull_request(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    self.pull_event(head, base),
                    wait_seconds=0,
                )
            self.assertIn("verified dependency-wave pull request", message)

            moved = pull_document(head, "c" * 40)
            with mock.patch.object(head_guard, "_fresh_pull", return_value=moved):
                with self.assertRaisesRegex(head_guard.AdmissionError, "base moved"):
                    head_guard.verify_pull_request(
                        repo,
                        head_guard.EXPECTED_REPOSITORY,
                        self.pull_event(head, base),
                        wait_seconds=0,
                    )

    def test_non_wave_pull_rejects_reserved_marker_before_early_return(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            with self.assertRaisesRegex(head_guard.AdmissionError, "reserved"):
                head_guard.verify_pull_request(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    self.pull_event(head, base, branch="feature/not-a-wave"),
                    wait_seconds=0,
                )

    def test_pull_handler_fails_loud_for_missing_and_malformed_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_dependency_head(repo)
            pull = pull_document(head, base)
            with mock.patch.object(head_guard, "_fresh_pull", return_value=pull), mock.patch.object(
                head_guard, "_attestation_documents", return_value=([], [])
            ):
                with self.assertRaises(head_guard.PendingAttestation):
                    head_guard.verify_pull_request(
                        repo,
                        head_guard.EXPECTED_REPOSITORY,
                        self.pull_event(head, base),
                        wait_seconds=0,
                    )
            _, malformed = attestation_documents(repo, base, head)
            malformed[0]["body"] = head_guard.ATTESTATION_MARKER + "\nspoof"
            with mock.patch.object(head_guard, "_fresh_pull", return_value=pull), mock.patch.object(
                head_guard, "_attestation_documents", return_value=([], malformed)
            ):
                with self.assertRaisesRegex(head_guard.AdmissionError, "malformed"):
                    head_guard.verify_pull_request(
                        repo,
                        head_guard.EXPECTED_REPOSITORY,
                        self.pull_event(head, base),
                        wait_seconds=0,
                    )

    def test_merge_group_accepts_readme_peer_and_rejects_second_cargo_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            admitted_head = commit_dependency_head(repo)
            (repo / "README.md").write_text("queued docs\n", encoding="utf-8")
            run_git(repo, "add", "README.md")
            run_git(repo, "commit", "-q", "-m", "queued docs")
            docs_group = run_git(repo, "rev-parse", "HEAD")
            pull = pull_document(admitted_head, base)
            reviews, comments = attestation_documents(repo, base, admitted_head)
            fake = guard_api_fake(
                pull=pull,
                reviews=reviews,
                comments=comments,
                policy_sha=base,
                open_pulls=[{"number": 77}],
            )
            with mock.patch.object(head_guard, "gh_json", side_effect=fake):
                message = head_guard.verify_merge_group(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    {"merge_group": {"base_sha": base, "head_sha": docs_group}},
                    wait_seconds=0,
                )
            self.assertIn("in merge group", message)

            (repo / "Cargo.toml").write_text(manifest("=0.7.70"), encoding="utf-8")
            (repo / "Cargo.lock").write_text(
                "version = 4\nkin-db 0.7.70\n", encoding="utf-8"
            )
            run_git(repo, "add", "Cargo.toml", "Cargo.lock")
            run_git(repo, "commit", "-q", "-m", "queued cargo change")
            cargo_group = run_git(repo, "rev-parse", "HEAD")
            fake = guard_api_fake(
                pull=pull,
                reviews=reviews,
                comments=comments,
                policy_sha=base,
                open_pulls=[{"number": 77}],
            )
            with mock.patch.object(head_guard, "gh_json", side_effect=fake):
                with self.assertRaisesRegex(head_guard.AdmissionError, "outside the wave"):
                    head_guard.verify_merge_group(
                        repo,
                        head_guard.EXPECTED_REPOSITORY,
                        {"merge_group": {"base_sha": base, "head_sha": cargo_group}},
                        wait_seconds=0,
                    )

    def test_verify_push_accepts_exact_classic_squash_and_rejects_other_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            run_git(repo, "switch", "-q", "-c", "admitted")
            admitted_head = commit_dependency_head(repo)
            run_git(repo, "switch", "-q", "-c", "delivery", base)
            delivery_head = commit_dependency_head(repo, marker=False)
            pull = pull_document(
                admitted_head,
                base,
                state="closed",
                merged_at="2026-08-27T23:00:00Z",
            )
            reviews, comments = attestation_documents(repo, base, admitted_head)
            fake = guard_api_fake(
                pull=pull,
                reviews=reviews,
                comments=comments,
                policy_sha=base,
                associated_pulls=[pull],
            )
            with mock.patch.object(head_guard, "gh_json", side_effect=fake):
                message = head_guard.verify_push(
                    repo,
                    head_guard.EXPECTED_REPOSITORY,
                    {
                        "ref": "refs/heads/main",
                        "before": base,
                        "after": delivery_head,
                    },
                    wait_seconds=0,
                )
            self.assertIn("classic-main delivery", message)

            run_git(repo, "switch", "-q", "-c", "wrong-delivery", base)
            wrong_head = commit_dependency_head(
                repo,
                dependency="=0.7.70",
                lock_version="0.7.70",
                marker=False,
            )
            fake = guard_api_fake(
                pull=pull,
                reviews=reviews,
                comments=comments,
                policy_sha=base,
                associated_pulls=[pull],
            )
            with mock.patch.object(head_guard, "gh_json", side_effect=fake):
                with self.assertRaisesRegex(head_guard.AdmissionError, "delivery tree"):
                    head_guard.verify_push(
                        repo,
                        head_guard.EXPECTED_REPOSITORY,
                        {
                            "ref": "refs/heads/main",
                            "before": base,
                            "after": wrong_head,
                        },
                        wait_seconds=0,
                    )


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.disarm_job = job_block(cls.workflow, "disarm-wave")
        cls.prepare_job = job_block(cls.workflow, "prepare-wave")
        cls.mutation_job = job_block(cls.workflow, "mutate-wave")
        cls.attest_workflow = ATTEST_WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.ci = CI_PATH.read_text(encoding="utf-8")
        cls.fast_gate = job_block(cls.ci, "fast-gate-lint")

    def test_default_branch_triggers_and_post_validation_concurrency(self) -> None:
        trigger = self.workflow.split("jobs:", 1)[0]
        self.assertIn("types: [kin-registry-release]", trigger)
        self.assertIn('cron: "17 * * * *"', trigger)
        self.assertNotIn("workflow_dispatch:", trigger)
        self.assertNotIn("concurrency:", trigger)
        for job in (self.disarm_job, self.prepare_job, self.mutation_job):
            self.assertLess(job.index("needs:"), job.index("concurrency:"))
            self.assertIn("cancel-in-progress: false", job)
        self.assertIn("kin-registry-release-disarm-${{ github.repository }}", self.disarm_job)
        self.assertIn("kin-registry-release-prepare-${{ github.repository }}", self.prepare_job)
        self.assertIn("kin-registry-release-mutate-${{ github.repository }}", self.mutation_job)

    def test_schedule_refreshes_full_set_without_event_floor(self) -> None:
        update = step_block(self.workflow, "Update the allowed root-manifest pins")
        self.assertIn('case "$GITHUB_EVENT_NAME" in', update)
        self.assertIn("repository_dispatch)", update)
        self.assertIn("schedule) ;;", update)
        for crate in validator.ALLOWED_SOURCES:
            self.assertIn(f"--crate {crate}", update)
        self.assertEqual(update.count("--crate "), len(validator.ALLOWED_SOURCES))
        self.assertIn('--event-crate "$EVENT_CRATE"', update)
        self.assertIn('--version "$EVENT_VERSION"', update)
        self.assertNotIn('--crate "$EVENT_CRATE"', update)

    def test_generated_smoke_and_admission_order_is_exact(self) -> None:
        snapshot = step_block(
            self.workflow, "Snapshot the exact generated dependency delta"
        )
        smoke = step_block(
            self.workflow,
            "Verify the updated Kin consumers on the credential-free runner",
        )
        admission = step_block(
            self.workflow, "Admit the generated dependency delta before compilation"
        )
        fuzz_lock = step_block(
            self.workflow, "Update the detached fuzz workspace lock to match"
        )
        self.assertIn(
            "run: cargo check --locked -p kin-core -p kin-cli -p kin-daemon -p kin-mcp",
            smoke,
        )
        for block in (snapshot, admission):
            self.assertIn("--version-mode manual", block)
            self.assertIn("--bump-own-version false", block)
        self.assertIn("expected_tree=", snapshot)
        self.assertIn('--expected-tree "$EXPECTED_TREE"', admission)
        # This has to run before the snapshot below, not after: every later
        # re-check in this pipeline (apply_candidate's re-validation in
        # mutate-wave, and the final verify-generated-head check against the
        # pushed PR head) compares against the tree the snapshot step records,
        # so fuzz/Cargo.lock has to already be in the working tree by then.
        self.assertIn("if: steps.update.outputs.changed == 'true'", fuzz_lock)
        self.assertIn("cargo update --manifest-path fuzz/Cargo.toml", fuzz_lock)
        self.assertIn("git add fuzz/Cargo.lock", fuzz_lock)
        prepare_names = [
            "Update the detached fuzz workspace lock to match",
            "Snapshot the exact generated dependency delta",
            "Admit the generated dependency delta before compilation",
            "Build the hash-bound data-only candidate handoff",
            "Upload the exact candidate before dependency code executes",
            "Verify the updated Kin consumers on the credential-free runner",
        ]
        prepare_positions = [
            self.prepare_job.index(f"- name: {name}") for name in prepare_names
        ]
        self.assertEqual(prepare_positions, sorted(prepare_positions))
        self.assertNotIn("- name:", self.prepare_job[prepare_positions[-1] + 1 :])

        mutation_names = [
            "Clear inherited landing state before candidate handling",
            "Download the compiled data-only candidate",
            "Revalidate and apply only the admitted manifest bytes",
            "Refuse protected-main rewrite before repository mutation",
            "Open or update the dependency bump PR",
            "Clear and verify landing state on the generated PR",
            "Verify exact first-party generated PR",
            "Build the post-completion admission record",
            "Upload exact result for the post-completion attester",
        ]
        mutation_positions = [
            self.mutation_job.index(f"- name: {name}") for name in mutation_names
        ]
        self.assertEqual(mutation_positions, sorted(mutation_positions))

    def test_base_branch_and_admitted_paths_bind_the_writer(self) -> None:
        early_resolve = step_block(
            self.workflow, "Bind early disarm to the queued workflow policy"
        )
        resolve = step_block(self.workflow, "Bind preparation to the queued workflow policy")
        checkout = step_block(self.workflow, "Checkout exact queued protected main")
        mutation_fence = step_block(
            self.workflow, "Refuse protected-main rewrite immediately before token mint"
        )
        admission = step_block(
            self.workflow, "Revalidate and apply only the admitted manifest bytes"
        )
        writer = step_block(self.workflow, "Open or update the dependency bump PR")
        verifier = step_block(self.workflow, "Verify exact first-party generated PR")
        # Bound to github.sha and proven protected main history rather than
        # equal to the live tip; scripts/test-kin-registry-wave-landing.py
        # pins the proof itself.
        self.assertIn("base_sha=$GITHUB_SHA", resolve)
        history_call = "python3 scripts/verify-protected-main-history.py"
        for block in (early_resolve, resolve):
            self.assertIn(history_call, block)
            self.assertIn('--policy-sha "$GITHUB_SHA"', block)
        self.assertIn("ref: ${{ github.sha }}", checkout)
        self.assertIn(history_call, mutation_fence)
        self.assertIn('--policy-sha "$ADMITTED_BASE"', mutation_fence)
        self.assertIn("kin-registry-wave-artifact.py apply", admission)
        self.assertIn("branch: ${{ env.WAVE_BRANCH }}", writer)
        self.assertIn("base: ${{ env.BASE_BRANCH }}", writer)
        self.assertIn("add-paths: |", writer)
        self.assertIn("Cargo.lock", writer)
        self.assertIn("Cargo.toml", writer)
        self.assertIn("fuzz/Cargo.lock", writer)
        self.assertIn("ADMITTED_BASE", verifier)
        self.assertIn(".base.sha", verifier)
        self.assertIn(".auto_merge == null", verifier)
        self.assertIn("api_tree", verifier)
        # The head's tree equals the admitted tree only while main stood still;
        # the guard proves the admitted delta on whatever parent the action
        # rebased onto, and the API's tree has to agree with the fetched head.
        self.assertIn("verify-generated-head", verifier)
        self.assertIn('--expected-tree "$EXPECTED_TREE"', verifier)
        self.assertIn('!= "$api_tree"', verifier)

    def test_fixed_pr_landing_state_is_cleared_before_and_after_write(self) -> None:
        early = step_block(
            self.workflow, "Clear inherited landing state before dependency preparation"
        )
        before = step_block(
            self.workflow, "Clear inherited landing state before candidate handling"
        )
        after = step_block(
            self.workflow, "Clear and verify landing state on the generated PR"
        )
        no_change = step_block(
            self.workflow, "Verify no-change reconciliation left no landing state"
        )
        script = AUTO_MERGE_PATH.read_text(encoding="utf-8")
        for block in (early, before, after, no_change):
            self.assertIn("ensure-kin-registry-wave-no-automerge.py", block)
            self.assertIn('--branch "$WAVE_BRANCH"', block)
            self.assertIn('--base "$BASE_BRANCH"', block)
        self.assertNotIn("if:", early)
        self.assertNotIn("if:", before)
        self.assertIn("needs: [validate-dispatch, disarm-wave]", self.prepare_job)
        self.assertIn('--expected-number "$PR"', after)
        self.assertIn('--expected-head "$ACTION_HEAD"', after)
        self.assertIn('"--disable-auto"', script)
        self.assertIn('"--match-head-commit"', script)
        self.assertIn("mergeQueueEntry", script)
        self.assertIn("dequeuePullRequest", script)
        self.assertIn("server-owned landing state", script)
        self.assertNotIn('"--auto"', script)
        self.assertLess(
            self.mutation_job.index("Clear inherited landing state"),
            self.mutation_job.index("Download the compiled data-only candidate"),
        )

    def test_write_token_is_isolated_from_candidate_execution(self) -> None:
        token = step_block(
            self.workflow, "Mint repository-scoped dependency-wave token"
        )
        self.assertIn("permission-contents: write", token)
        self.assertIn("permission-pull-requests: write", token)
        self.assertIn("permission-issues: write", token)
        self.assertNotIn("permission-statuses", token)
        self.assertNotIn("environment: release-tag", self.prepare_job)
        self.assertNotIn("create-github-app-token", self.prepare_job)
        self.assertNotIn("cargo ", self.disarm_job)
        self.assertNotIn("cargo ", self.mutation_job)
        upload = step_block(
            self.workflow, "Upload the exact candidate before dependency code executes"
        )
        smoke = step_block(
            self.workflow,
            "Verify the updated Kin consumers on the credential-free runner",
        )
        self.assertLess(self.prepare_job.index(upload), self.prepare_job.index(smoke))
        self.assertEqual(
            self.prepare_job.rfind("- name:"),
            self.prepare_job.index(
                "- name: Verify the updated Kin consumers on the credential-free runner"
            ),
        )
        identity_step = step_block(
            self.workflow, "Verify exact App installation identity and scope"
        )
        self.assertIn("verify-kin-release-app-token.py", identity_step)
        identity_source = IDENTITY_PATH.read_text(encoding="utf-8")
        self.assertIn('f"users/{EXPECTED_BOT_LOGIN}"', identity_source)
        self.assertIn("installation/repositories?per_page=100", identity_source)
        self.assertNotIn('["api", "user"]', identity_source)
        self.assertNotIn("KIN_DOWNSTREAM_DISPATCH_TOKEN", self.workflow)
        self.assertNotIn("/statuses/", self.workflow)

    def test_attestation_is_post_completion_and_server_verified(self) -> None:
        trigger = self.attest_workflow.split("jobs:", 1)[0]
        self.assertIn("workflow_run:", trigger)
        self.assertIn("workflows: [Kin Registry Release Receiver]", trigger)
        self.assertIn("types: [completed]", trigger)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", self.attest_workflow)
        validate = step_block(
            self.attest_workflow,
            "Validate terminal server authority and live admitted head",
        )
        token = step_block(
            self.attest_workflow, "Mint repository-scoped attestation token"
        )
        post = step_block(
            self.attest_workflow,
            "Persist exact post-completion admission attestation",
        )
        inspect = step_block(
            self.attest_workflow,
            "Inspect exact-head CI after the persisted attestation",
        )
        retrigger = step_block(
            self.attest_workflow,
            "Retrigger exact-head CI when the attestation arrived late",
        )
        recheck = step_block(
            self.attest_workflow,
            "Verify a required exact-head CI recheck materialized",
        )
        self.assertLess(self.attest_workflow.index(validate), self.attest_workflow.index(token))
        self.assertLess(self.attest_workflow.index(token), self.attest_workflow.index(post))
        self.assertLess(self.attest_workflow.index(post), self.attest_workflow.index(inspect))
        self.assertLess(
            self.attest_workflow.index(inspect),
            self.attest_workflow.index(retrigger),
        )
        self.assertLess(
            self.attest_workflow.index(retrigger),
            self.attest_workflow.index(recheck),
        )
        self.assertIn("attest-kin-registry-wave.py validate", validate)
        self.assertIn("attest-kin-registry-wave.py post", post)
        self.assertIn("if: steps.validate.outputs.changed == 'true'", token)
        self.assertIn("steps.validate.outputs.needs_attestation == 'true'", post)
        self.assertIn("attest-kin-registry-wave.py recheck-status", inspect)
        self.assertIn("steps.recheck.outputs.needs_retrigger == 'true'", retrigger)
        self.assertIn("attest-kin-registry-wave.py retrigger", retrigger)
        self.assertIn("--require-recheck", recheck)
        self.assertIn(
            "group: kin-registry-admission-${{ github.repository }}",
            self.attest_workflow,
        )
        self.assertNotIn("github.event.workflow_run.id }}-${{", self.attest_workflow)
        no_change = step_block(
            self.workflow, "Build the post-completion no-change record"
        )
        result_upload = step_block(
            self.workflow, "Upload exact result for the post-completion attester"
        )
        self.assertIn("finalize-no-change", no_change)
        self.assertNotIn("if:", result_upload)
        guard_source = HEAD_GUARD_PATH.read_text(encoding="utf-8")
        for field in (
            "workflow_path",
            "policy_sha",
            "run_id",
            "run_attempt",
            'workflow_run.get("status") != "completed"',
            'workflow_run.get("conclusion") != "success"',
        ):
            self.assertIn(field, guard_source)
        self.assertIn("kin-registry-dependency-admission:v2", guard_source)

    def test_required_fast_gate_revalidates_every_delivery_event(self) -> None:
        ci_trigger = self.ci.split("permissions:", 1)[0]
        self.assertIn("types: [opened, synchronize, reopened]", ci_trigger)
        self.assertIn("permissions:", self.fast_gate)
        self.assertIn("actions: read", self.fast_gate)
        self.assertIn("issues: read", self.fast_gate)
        self.assertIn("pull-requests: read", self.fast_gate)
        self.assertNotIn("statuses: read", self.fast_gate)
        self.assertIn("fetch-depth: 0", self.fast_gate)
        verifier = step_block(self.ci, "Verify registry dependency-wave admission")
        self.assertIn("verify-kin-registry-wave-head.py", verifier)
        self.assertIn('--event-name "$GITHUB_EVENT_NAME"', verifier)
        self.assertIn('--workflow-sha "$GITHUB_SHA"', verifier)
        self.assertIn("--attestation-wait-seconds 300", verifier)
        guard_source = HEAD_GUARD_PATH.read_text(encoding="utf-8")
        for event in ("pull_request", "merge_group", "push"):
            self.assertIn(f'args.event_name == "{event}"', guard_source)
        self.assertIn("classic-main delivery tree differs", guard_source)
        self.assertIn("merge group changes admitted dependency paths", guard_source)
        self.assertIn("non-wave pull request uses the reserved", guard_source)
        self.assertIn('"merge-tree"', guard_source)
        self.assertIn("package or workspace version", guard_source)
        self.assertIn("ALLOWED_PATHS", guard_source)
        self.assertIn("performed_via_github_app", guard_source)
        self.assertIn("review.get(\"commit_id\") != head", guard_source)

    def test_dispatch_metadata_is_not_claimed_as_provenance(self) -> None:
        self.assertIn(
            "sender-supplied correlation metadata. They are not treated as source provenance.",
            self.workflow,
        )


if __name__ == "__main__":
    unittest.main()

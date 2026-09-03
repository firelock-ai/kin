#!/usr/bin/env python3
"""Create and verify the data-only handoff for a Kin registry dependency wave."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Sequence


EXPECTED_REPOSITORY = "firelock-ai/kin"
EXPECTED_WORKFLOW_PATH = ".github/workflows/kin-registry-release.yml"
# Kept as its own ordered tuple rather than importing verify-kin-registry-wave-
# head.py's ALLOWED_PATHS frozenset: this constant is serialized as
# `list(ALLOWED_PATHS)` into the candidate.json handoff and compared for exact
# list equality across two separate CI processes (prepare-wave writes it,
# mutate-wave reads it back). Python randomizes string-hash seeds per process,
# so a frozenset's iteration order is not guaranteed stable across processes; a
# literal tuple is. land-kin-registry-wave.py can safely import the frozenset
# because it only ever uses it for membership and sorted() there.
ALLOWED_PATHS = ("Cargo.lock", "Cargo.toml", "fuzz/Cargo.lock")
LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
VERSION_EVIDENCE = re.compile(r"^(?:absent|[0-9A-Za-z.+-]+)$")
MAX_FILE_BYTES = 32 * 1024 * 1024
CANDIDATE_KEYS = frozenset(
    {
        "schema",
        "repository",
        "policy_sha",
        "base",
        "tree",
        "delta_sha256",
        "package_version",
        "workspace_version",
        "paths",
        "files",
    }
)
ADMISSION_KEYS = CANDIDATE_KEYS | frozenset(
    {"changed", "pull", "head", "workflow_path", "run_id", "run_attempt"}
)
NO_CHANGE_KEYS = frozenset(
    {
        "schema",
        "repository",
        "changed",
        "policy_sha",
        "base",
        "workflow_path",
        "run_id",
        "run_attempt",
    }
)


class ArtifactError(RuntimeError):
    """The dependency-wave artifact is malformed or not bound to this run."""


def _load_guard() -> ModuleType:
    path = Path(__file__).resolve().with_name("verify-kin-registry-wave-head.py")
    spec = importlib.util.spec_from_file_location("kin_registry_wave_runtime_guard", path)
    if spec is None or spec.loader is None:
        raise ArtifactError(f"cannot load trusted verifier {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha(label: str, value: Any) -> str:
    if not isinstance(value, str) or LOWER_SHA.fullmatch(value) is None:
        raise ArtifactError(f"{label} must be 40-character lowercase hex")
    return value


def _require_positive(label: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ArtifactError(f"{label} must be a positive integer")
    return value


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = _safe_regular(path).decode("utf-8")
        value = json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot read exact JSON artifact {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactError(f"{path.name} is not a JSON object")
    return value


def _safe_regular(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ArtifactError(f"artifact file {path.name} is missing: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ArtifactError(f"artifact entry {path.name} is not a regular file")
    if info.st_size > MAX_FILE_BYTES:
        raise ArtifactError(f"artifact entry {path.name} exceeds the size limit")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ArtifactError(f"cannot read artifact entry {path.name}: {exc}") from exc


def _exact_entries(directory: Path, expected: frozenset[str]) -> None:
    """Require the directory tree to hold exactly the expected file paths.

    Walks recursively rather than listing top-level names only, because
    ALLOWED_PATHS now includes fuzz/Cargo.lock: a shallow `iterdir()` would see
    a bare `fuzz` directory entry that can never equal the string
    "fuzz/Cargo.lock", refusing every candidate. Every directory encountered is
    rejected if it is a symlink before being walked into, so a symlinked
    subdirectory can never smuggle a read from outside `directory`; the same
    rejection applies to any non-regular leaf.
    """

    if directory.is_symlink() or not directory.is_dir():
        raise ArtifactError("artifact path is not an exact directory")
    found: set[str] = set()
    pending = [directory]
    while pending:
        current = pending.pop()
        for item in current.iterdir():
            relative = item.relative_to(directory).as_posix()
            if item.is_symlink():
                raise ArtifactError(f"artifact entry {relative} is a symlink")
            if item.is_dir():
                pending.append(item)
            elif item.is_file():
                found.add(relative)
            else:
                raise ArtifactError(f"artifact entry {relative} is not a regular file")
    if found != expected:
        raise ArtifactError(
            "artifact entries differ from the allowlist: "
            + ", ".join(sorted(found ^ expected))
        )


def _validate_candidate(
    value: dict[str, Any],
    *,
    repository: str,
    policy_sha: str,
    base: str,
) -> dict[str, Any]:
    if frozenset(value) != CANDIDATE_KEYS:
        raise ArtifactError("candidate manifest keys differ from the exact schema")
    if value.get("schema") != 1:
        raise ArtifactError("candidate manifest schema is not 1")
    if repository != EXPECTED_REPOSITORY or value.get("repository") != repository:
        raise ArtifactError("candidate repository is not firelock-ai/kin")
    policy_sha = _require_sha("expected policy sha", policy_sha)
    base = _require_sha("expected candidate base", base)
    if policy_sha != base:
        raise ArtifactError("current protected main differs from the workflow policy sha")
    if value.get("policy_sha") != policy_sha or value.get("base") != base:
        raise ArtifactError("candidate policy or base does not match protected main")
    _require_sha("candidate tree", value.get("tree"))
    if not isinstance(value.get("delta_sha256"), str) or HEX_64.fullmatch(
        value["delta_sha256"]
    ) is None:
        raise ArtifactError("candidate delta digest is invalid")
    for field in ("package_version", "workspace_version"):
        item = value.get(field)
        if not isinstance(item, str) or VERSION_EVIDENCE.fullmatch(item) is None:
            raise ArtifactError(f"candidate {field} is invalid")
    # "paths" is the subset of ALLOWED_PATHS this delta actually touched, in
    # ALLOWED_PATHS's own canonical order, not the full allowlist: a wave that
    # moves a pin fuzz/Cargo.lock does not depend on (kin-blobs, say) never
    # touches it, and validate_index_delta/validate_delta already admit that
    # subset. Every real wave happened to touch every one of the previous two
    # paths together, which is what let this check hard-require the full list
    # without it ever being exercised as a subset.
    paths_value = value.get("paths")
    if (
        not isinstance(paths_value, list)
        or not paths_value
        or len(set(paths_value)) != len(paths_value)
        or any(path not in ALLOWED_PATHS for path in paths_value)
        or paths_value != [path for path in ALLOWED_PATHS if path in paths_value]
    ):
        raise ArtifactError("candidate paths differ from the exact allowlist")
    files = value.get("files")
    if not isinstance(files, dict) or frozenset(files) != frozenset(ALLOWED_PATHS):
        raise ArtifactError("candidate file digest map differs from the allowlist")
    for path in ALLOWED_PATHS:
        digest = files.get(path)
        if not isinstance(digest, str) or HEX_64.fullmatch(digest) is None:
            raise ArtifactError(f"candidate digest for {path} is invalid")
    return value


def _git(workspace: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(workspace), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ArtifactError(f"git {' '.join(arguments)} failed: {detail or 'no output'}")
    return result.stdout


def prepare_candidate(
    *,
    workspace: Path,
    output_dir: Path,
    repository: str,
    policy_sha: str,
    base: str,
    expected_tree: str,
) -> dict[str, Any]:
    if policy_sha != base:
        raise ArtifactError("candidate base must equal the workflow policy sha")
    guard = _load_guard()
    try:
        evidence = guard.validate_index_delta(workspace, base, expected_tree)
    except guard.AdmissionError as exc:
        raise ArtifactError(str(exc)) from exc
    if output_dir.exists():
        if output_dir.is_symlink() or any(output_dir.iterdir()):
            raise ArtifactError("candidate output directory must be absent or empty")
    else:
        output_dir.mkdir(parents=True)

    files: dict[str, str] = {}
    for path in ALLOWED_PATHS:
        content = _git(workspace, "show", f":{path}")
        # ALLOWED_PATHS now includes fuzz/Cargo.lock, the first admitted path
        # with a directory component; output_dir itself is created above but
        # not its subdirectories.
        (output_dir / path).parent.mkdir(parents=True, exist_ok=True)
        (output_dir / path).write_bytes(content)
        files[path] = _sha256(content)
    manifest: dict[str, Any] = {
        "schema": 1,
        "repository": repository,
        "policy_sha": policy_sha,
        "base": base,
        "tree": evidence.tree,
        "delta_sha256": evidence.delta_sha256,
        "package_version": evidence.package_version,
        "workspace_version": evidence.workspace_version,
        # The subset of ALLOWED_PATHS this delta actually touched (evidence.paths
        # comes from validate_index_delta's real git diff), not the full
        # allowlist: `files` below always carries all of ALLOWED_PATHS, because
        # apply_candidate needs every admitted path's current bytes to
        # reconstruct the tree, changed or not, but "paths" describes the delta.
        "paths": [path for path in ALLOWED_PATHS if path in evidence.paths],
        "files": files,
    }
    _validate_candidate(
        manifest,
        repository=repository,
        policy_sha=policy_sha,
        base=base,
    )
    (output_dir / "candidate.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return manifest


def apply_candidate(
    *,
    workspace: Path,
    artifact_dir: Path,
    repository: str,
    policy_sha: str,
    base: str,
) -> dict[str, Any]:
    _exact_entries(
        artifact_dir,
        frozenset({"candidate.json", *ALLOWED_PATHS}),
    )
    value = _validate_candidate(
        _read_json(artifact_dir / "candidate.json"),
        repository=repository,
        policy_sha=policy_sha,
        base=base,
    )
    if _git(workspace, "rev-parse", "HEAD").decode("ascii").strip() != base:
        raise ArtifactError("mutation checkout is not the exact protected main")
    if _git(workspace, "status", "--porcelain", "-z", "--untracked-files=all"):
        raise ArtifactError("mutation checkout is not clean before artifact admission")

    for path in ALLOWED_PATHS:
        content = _safe_regular(artifact_dir / path)
        if _sha256(content) != value["files"][path]:
            raise ArtifactError(f"artifact bytes for {path} differ from their digest")
    for path in ALLOWED_PATHS:
        (workspace / path).parent.mkdir(parents=True, exist_ok=True)
        (workspace / path).write_bytes((artifact_dir / path).read_bytes())
    _git(workspace, "add", "--", *ALLOWED_PATHS)

    guard = _load_guard()
    try:
        evidence = guard.validate_index_delta(workspace, base, str(value["tree"]))
    except guard.AdmissionError as exc:
        raise ArtifactError(str(exc)) from exc
    observed = {
        "tree": evidence.tree,
        "delta_sha256": evidence.delta_sha256,
        "package_version": evidence.package_version,
        "workspace_version": evidence.workspace_version,
        "paths": sorted(evidence.paths),
    }
    expected = {
        "tree": value["tree"],
        "delta_sha256": value["delta_sha256"],
        "package_version": value["package_version"],
        "workspace_version": value["workspace_version"],
        "paths": value["paths"],
    }
    if observed != expected:
        raise ArtifactError("fresh mutation admission differs from prepared evidence")
    return value


def finalize_admission(
    *,
    artifact_dir: Path,
    output_file: Path,
    repository: str,
    policy_sha: str,
    base: str,
    pull: int,
    head: str,
    workflow_path: str,
    run_id: int,
    run_attempt: int,
) -> dict[str, Any]:
    _exact_entries(
        artifact_dir,
        frozenset({"candidate.json", *ALLOWED_PATHS}),
    )
    candidate = _validate_candidate(
        _read_json(artifact_dir / "candidate.json"),
        repository=repository,
        policy_sha=policy_sha,
        base=base,
    )
    pull = _require_positive("pull request number", pull)
    head = _require_sha("pull request head", head)
    run_id = _require_positive("workflow run id", run_id)
    run_attempt = _require_positive("workflow run attempt", run_attempt)
    if workflow_path != EXPECTED_WORKFLOW_PATH:
        raise ArtifactError("receiver workflow path is not the exact admitted path")
    result = dict(candidate)
    result.update(
        {
            "changed": True,
            "pull": pull,
            "head": head,
            "workflow_path": workflow_path,
            "run_id": run_id,
            "run_attempt": run_attempt,
        }
    )
    if frozenset(result) != ADMISSION_KEYS:
        raise ArtifactError("final admission keys differ from the exact schema")
    if output_file.exists() and output_file.is_symlink():
        raise ArtifactError("final admission output is a symlink")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return result


def finalize_no_change(
    *,
    output_file: Path,
    repository: str,
    policy_sha: str,
    base: str,
    workflow_path: str,
    run_id: int,
    run_attempt: int,
) -> dict[str, Any]:
    policy_sha = _require_sha("no-change policy sha", policy_sha)
    base = _require_sha("no-change base", base)
    if repository != EXPECTED_REPOSITORY:
        raise ArtifactError("no-change repository is not firelock-ai/kin")
    if policy_sha != base:
        raise ArtifactError("no-change base differs from the workflow policy sha")
    if workflow_path != EXPECTED_WORKFLOW_PATH:
        raise ArtifactError("no-change workflow path is not the receiver")
    run_id = _require_positive("workflow run id", run_id)
    run_attempt = _require_positive("workflow run attempt", run_attempt)
    result: dict[str, Any] = {
        "schema": 1,
        "repository": repository,
        "changed": False,
        "policy_sha": policy_sha,
        "base": base,
        "workflow_path": workflow_path,
        "run_id": run_id,
        "run_attempt": run_attempt,
    }
    if frozenset(result) != NO_CHANGE_KEYS:
        raise ArtifactError("no-change result keys differ from the exact schema")
    if output_file.exists() and output_file.is_symlink():
        raise ArtifactError("receiver result output is a symlink")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return result


def validate_admission(
    *,
    admission_file: Path,
    repository: str,
    workflow_path: str,
    policy_sha: str,
    run_id: int,
    run_attempt: int,
) -> dict[str, Any]:
    value = _read_json(admission_file)
    if frozenset(value) != ADMISSION_KEYS:
        raise ArtifactError("final admission keys differ from the exact schema")
    if value.get("changed") is not True:
        raise ArtifactError("final admission is not a changed receiver result")
    _validate_candidate(
        {key: value[key] for key in CANDIDATE_KEYS},
        repository=repository,
        policy_sha=policy_sha,
        base=policy_sha,
    )
    _require_positive("admission pull", value.get("pull"))
    _require_sha("admission head", value.get("head"))
    if value.get("workflow_path") != workflow_path or workflow_path != EXPECTED_WORKFLOW_PATH:
        raise ArtifactError("admission workflow path differs from the completed receiver")
    if value.get("run_id") != run_id or value.get("run_attempt") != run_attempt:
        raise ArtifactError("admission run identity differs from the completed receiver")
    _require_positive("expected workflow run id", run_id)
    _require_positive("expected workflow run attempt", run_attempt)
    return value


def validate_result(
    *,
    result_file: Path,
    repository: str,
    workflow_path: str,
    policy_sha: str,
    run_id: int,
    run_attempt: int,
) -> dict[str, Any]:
    value = _read_json(result_file)
    if value.get("changed") is True:
        return validate_admission(
            admission_file=result_file,
            repository=repository,
            workflow_path=workflow_path,
            policy_sha=policy_sha,
            run_id=run_id,
            run_attempt=run_attempt,
        )
    if value.get("changed") is not False or frozenset(value) != NO_CHANGE_KEYS:
        raise ArtifactError("receiver result is neither exact changed nor no-change schema")
    if (
        value.get("schema") != 1
        or value.get("repository") != repository
        or repository != EXPECTED_REPOSITORY
        or value.get("workflow_path") != workflow_path
        or workflow_path != EXPECTED_WORKFLOW_PATH
        or value.get("policy_sha") != policy_sha
        or value.get("base") != policy_sha
        or value.get("run_id") != run_id
        or value.get("run_attempt") != run_attempt
    ):
        raise ArtifactError("no-change result differs from completed receiver authority")
    _require_sha("no-change policy sha", policy_sha)
    _require_positive("expected workflow run id", run_id)
    _require_positive("expected workflow run attempt", run_attempt)
    return value


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--workspace", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--policy-sha", required=True)
    prepare.add_argument("--base", required=True)
    prepare.add_argument("--expected-tree", required=True)
    apply = subparsers.add_parser("apply")
    apply.add_argument("--workspace", type=Path, required=True)
    apply.add_argument("--artifact-dir", type=Path, required=True)
    apply.add_argument("--repository", required=True)
    apply.add_argument("--policy-sha", required=True)
    apply.add_argument("--base", required=True)
    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--artifact-dir", type=Path, required=True)
    finalize.add_argument("--output-file", type=Path, required=True)
    finalize.add_argument("--repository", required=True)
    finalize.add_argument("--policy-sha", required=True)
    finalize.add_argument("--base", required=True)
    finalize.add_argument("--pull", type=int, required=True)
    finalize.add_argument("--head", required=True)
    finalize.add_argument("--workflow-path", required=True)
    finalize.add_argument("--run-id", type=int, required=True)
    finalize.add_argument("--run-attempt", type=int, required=True)
    no_change = subparsers.add_parser("finalize-no-change")
    no_change.add_argument("--output-file", type=Path, required=True)
    no_change.add_argument("--repository", required=True)
    no_change.add_argument("--policy-sha", required=True)
    no_change.add_argument("--base", required=True)
    no_change.add_argument("--workflow-path", required=True)
    no_change.add_argument("--run-id", type=int, required=True)
    no_change.add_argument("--run-attempt", type=int, required=True)
    validate = subparsers.add_parser("validate-admission")
    validate.add_argument("--admission-file", type=Path, required=True)
    validate.add_argument("--repository", required=True)
    validate.add_argument("--workflow-path", required=True)
    validate.add_argument("--policy-sha", required=True)
    validate.add_argument("--run-id", type=int, required=True)
    validate.add_argument("--run-attempt", type=int, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "prepare":
            result = prepare_candidate(
                workspace=args.workspace,
                output_dir=args.output_dir,
                repository=args.repository,
                policy_sha=args.policy_sha,
                base=args.base,
                expected_tree=args.expected_tree,
            )
        elif args.command == "apply":
            result = apply_candidate(
                workspace=args.workspace,
                artifact_dir=args.artifact_dir,
                repository=args.repository,
                policy_sha=args.policy_sha,
                base=args.base,
            )
        elif args.command == "finalize":
            result = finalize_admission(
                artifact_dir=args.artifact_dir,
                output_file=args.output_file,
                repository=args.repository,
                policy_sha=args.policy_sha,
                base=args.base,
                pull=args.pull,
                head=args.head,
                workflow_path=args.workflow_path,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
        elif args.command == "finalize-no-change":
            result = finalize_no_change(
                output_file=args.output_file,
                repository=args.repository,
                policy_sha=args.policy_sha,
                base=args.base,
                workflow_path=args.workflow_path,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
        else:
            result = validate_admission(
                admission_file=args.admission_file,
                repository=args.repository,
                workflow_path=args.workflow_path,
                policy_sha=args.policy_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
    except (ArtifactError, OSError, UnicodeDecodeError) as exc:
        print(
            f"::error title=Invalid Kin registry wave artifact::{exc}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

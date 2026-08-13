#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Deterministic tests for the public Homebrew release follow-up proof."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parent
ROOT = SCRIPTS_DIR.parent
VERIFIER = SCRIPTS_DIR / "verify-homebrew-formula.sh"
VALIDATOR = SCRIPTS_DIR / "validate-homebrew-formula.py"
WORKFLOW = ROOT / ".github/workflows/publish-release-installers.yml"

FIXTURE_CHECKSUMS = {
    "kin-macos-aarch64.tar.gz": "a" * 64,
    "kin-macos-x86_64.tar.gz": "b" * 64,
    "kin-linux-aarch64.tar.gz": "c" * 64,
    "kin-linux-x86_64.tar.gz": "d" * 64,
}


FAKE_CURL = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import sys

EXPECTED = os.environ["EXPECTED_FORMULA_VERSION"]
ARTIFACTS = {
    ("macos", "arm"): ("kin-macos-aarch64.tar.gz", "a" * 64),
    ("macos", "intel"): ("kin-macos-x86_64.tar.gz", "b" * 64),
    ("linux", "arm"): ("kin-linux-aarch64.tar.gz", "c" * 64),
    ("linux", "intel"): ("kin-linux-x86_64.tar.gz", "d" * 64),
}

state_path = pathlib.Path(os.environ["FAKE_CURL_STATE"])
try:
    state = json.loads(state_path.read_text(encoding="utf-8"))
except FileNotFoundError:
    state = {"formula": 0, "checksums": 0}

args_path = pathlib.Path(os.environ["FAKE_CURL_ARGS"])
with args_path.open("a", encoding="utf-8") as handle:
    handle.write(" ".join(sys.argv[1:]) + "\n")

try:
    output_index = sys.argv.index("--output")
    output_path = pathlib.Path(sys.argv[output_index + 1])
except (ValueError, IndexError):
    print("fake curl requires an --output destination", file=sys.stderr)
    raise SystemExit(22)

url = sys.argv[-1]
if "kind=formula" in url:
    kind = "formula"
    artifact = None
elif "kind=checksum-" in url:
    kind = "checksums"
    artifact = url.split("kind=checksum-", 1)[1].split("&", 1)[0]
else:
    print(f"fake curl received unknown URL: {url}", file=sys.stderr)
    raise SystemExit(22)

state[kind] += 1
state_path.write_text(json.dumps(state), encoding="utf-8")


def formula_pair(
    os_name,
    arch,
    artifact,
    sha,
    *,
    malformed_url=False,
    nested_url=False,
    nested_sha=False,
):
    url = (
        f"https://github.com/firelock-ai/kin/releases/download/"
        f"v#{{version}}/{artifact}"
    )
    if malformed_url:
        url = f"https://example.invalid/releases/v#{{version}}/{artifact}"
    pair = [
        f"  on_{arch} do",
        f'    url "{url}"',
        f'    sha256 "{sha}"',
        "  end",
    ]
    if nested_url:
        pair[1:3] = ["    if true", f'      url "{url}"', f'      sha256 "{sha}"', "    end"]
    elif nested_sha:
        pair[2:3] = ["    if true", f'      sha256 "{sha}"', "    end"]
    return pair


def render_formula(mode, ready):
    version = EXPECTED if ready else "0.0.0"
    lines = []
    if mode == "version_outside_class":
        lines.append(f'version "{version}"')
    lines.append("class Kin < Formula")
    if mode == "conditional_version":
        lines.extend(["  if false", f'    version "{version}"', "  end"])
    elif mode == "comment_only":
        lines.append(f'  # version "{EXPECTED}"')
    elif mode != "version_outside_class":
        lines.append(f'  version "{version}"')
    if mode == "duplicate_version":
        lines.append(f'  version "{version}"')

    if mode == "nested_os":
        lines.append("  if true")
    for os_name in ("macos", "linux"):
        lines.append(f"  on_{os_name} do")
        if mode == "nested_arch" and os_name == "macos":
            lines.append("    if true")
        for arch in ("arm", "intel"):
            if mode == "missing_mapping" and (os_name, arch) == ("linux", "arm"):
                continue
            artifact, sha = ARTIFACTS[(os_name, arch)]
            if mode == "stale_checksum" and (os_name, arch) == ("macos", "arm"):
                sha = "e" * 64
            if mode == "malformed_sha" and (os_name, arch) == ("linux", "intel"):
                sha = "not-a-sha256"
            malformed_url = mode == "malformed_mapping" and (os_name, arch) == ("linux", "arm")
            lines.extend(
                formula_pair(
                    os_name,
                    arch,
                    artifact,
                    sha,
                    malformed_url=malformed_url,
                    nested_url=(
                        mode == "nested_url" and (os_name, arch) == ("macos", "arm")
                    ),
                    nested_sha=(
                        mode == "nested_sha" and (os_name, arch) == ("macos", "arm")
                    ),
                )
            )
            if mode == "missing_arch_end" and (os_name, arch) == ("linux", "arm"):
                lines.pop()
        if mode == "duplicate_mapping" and os_name == "macos":
            artifact, sha = ARTIFACTS[("macos", "arm")]
            lines.extend(formula_pair("macos", "arm", artifact, sha))
        if mode == "nested_arch" and os_name == "macos":
            lines.append("    end")
        if not (mode == "missing_linux_end" and os_name == "linux"):
            lines.append("  end")
    if mode == "nested_os":
        lines.append("  end")

    lines.extend(
        [
            "  def install",
            '    bin.install "kin"',
            '    bin.install "kin-vfs" if File.exist?("kin-vfs")',
            "  end",
            "",
            "  test do",
            '    assert_match "kin", shell_output("#{bin}/kin --version")',
            "  end",
        ]
    )
    if mode != "missing_class_end":
        lines.append("end")
    if mode == "extra_end":
        lines.append("end")
    if mode == "duplicate_class":
        lines.extend(["class Kin < Formula", "end"])
    return "\n".join(lines)


def render_sidecar(mode, artifact):
    checksums = {name: sha for name, sha in ARTIFACTS.values()}
    if artifact not in checksums:
        print(f"fake curl received unknown artifact: {artifact}", file=sys.stderr)
        raise SystemExit(22)
    if mode == "sidecar_missing" and artifact == "kin-linux-aarch64.tar.gz":
        return ""
    if mode == "sidecar_malformed" and artifact == "kin-linux-aarch64.tar.gz":
        return "not-a-checksum-line"
    if mode == "sidecar_swapped" and artifact == "kin-macos-aarch64.tar.gz":
        other = "kin-macos-x86_64.tar.gz"
        return f"{checksums[other]}  {other}"
    line = f"{checksums[artifact]}  {artifact}"
    if mode == "sidecar_duplicate" and artifact == "kin-macos-aarch64.tar.gz":
        return f"{line}\n{line}"
    return line


if kind == "formula":
    success_after = int(os.environ.get("FAKE_CURL_SUCCESS_AFTER", "1"))
    ready = state["formula"] >= success_after
    mode = os.environ.get("FAKE_FORMULA_MODE", "valid") if ready else "stale_version"
    payload = render_formula(mode, ready).encode() + b"\n"
    if mode == "raw_nul":
        payload = payload[:-1] + b"\0\n"
else:
    payload = (
        render_sidecar(os.environ.get("FAKE_SIDECAR_MODE", "valid"), artifact).encode()
        + b"\n"
    )
    if os.environ.get("FAKE_SIDECAR_NUL_ARTIFACT") == artifact:
        payload = payload[:-1] + b"\0\n"
output_path.write_bytes(payload)
"""


def verifier_env(
    fake_bin: Path,
    state: Path,
    args: Path,
    *,
    success_after: int,
    formula_mode: str = "valid",
    sidecar_mode: str = "valid",
    sidecar_nul_artifact: str = "",
) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("KIN_CI_BOT_TOKEN", None)
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "FAKE_CURL_STATE": str(state),
            "FAKE_CURL_ARGS": str(args),
            "FAKE_CURL_SUCCESS_AFTER": str(success_after),
            "FAKE_FORMULA_MODE": formula_mode,
            "FAKE_SIDECAR_MODE": sidecar_mode,
            "FAKE_SIDECAR_NUL_ARTIFACT": sidecar_nul_artifact,
            "EXPECTED_FORMULA_VERSION": "1.2.3",
            "KIN_HOMEBREW_VERIFY_MAX_WAIT_SECONDS": "10",
            "KIN_HOMEBREW_VERIFY_MAX_ATTEMPTS": "3",
            "KIN_HOMEBREW_VERIFY_POLL_SECONDS": "0",
            "KIN_HOMEBREW_VERIFY_CURL_MAX_SECONDS": "1",
        }
    )
    return env


def run_verifier(
    *,
    success_after: int = 1,
    formula_mode: str = "valid",
    sidecar_mode: str = "valid",
    sidecar_nul_artifact: str = "",
) -> tuple[subprocess.CompletedProcess[str], str, dict[str, int]]:
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        fake_bin = temp / "bin"
        fake_bin.mkdir()
        fake_curl = fake_bin / "curl"
        fake_curl.write_text(FAKE_CURL, encoding="utf-8")
        fake_curl.chmod(0o755)
        state = temp / "state.json"
        args = temp / "args"
        result = subprocess.run(
            ["bash", str(VERIFIER), "v1.2.3"],
            check=False,
            capture_output=True,
            text=True,
            env=verifier_env(
                fake_bin,
                state,
                args,
                success_after=success_after,
                formula_mode=formula_mode,
                sidecar_mode=sidecar_mode,
                sidecar_nul_artifact=sidecar_nul_artifact,
            ),
        )
        curl_args = args.read_text(encoding="utf-8")
        attempts = json.loads(state.read_text(encoding="utf-8"))
    return result, curl_args, attempts


def assert_bounded_failure(
    *,
    formula_mode: str = "valid",
    sidecar_mode: str = "valid",
    sidecar_nul_artifact: str = "",
    expected_error: str,
) -> None:
    result, _, attempts = run_verifier(
        formula_mode=formula_mode,
        sidecar_mode=sidecar_mode,
        sidecar_nul_artifact=sidecar_nul_artifact,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert attempts == {"formula": 3, "checksums": 12}, attempts
    assert expected_error in result.stderr, result.stderr
    assert "after 3 checks" in result.stderr, result.stderr


def run_validator(formula: str) -> subprocess.CompletedProcess[bytes]:
    payload_parts = [formula.encode()]
    payload_parts.extend(
        f"{FIXTURE_CHECKSUMS[artifact]}  {artifact}\n".encode()
        for artifact in (
            "kin-macos-aarch64.tar.gz",
            "kin-macos-x86_64.tar.gz",
            "kin-linux-aarch64.tar.gz",
            "kin-linux-x86_64.tar.gz",
        )
    )
    return subprocess.run(
        ["python3", str(VALIDATOR), "1.2.3"],
        input=b"\0".join(payload_parts) + b"\0",
        check=False,
        capture_output=True,
    )


def current_real_formula_shape() -> str:
    return f'''# GENERATED by scripts/render-formula.sh. Do not hand-edit.
class Kin < Formula
  desc "Semantic system of record for AI-written software"
  homepage "https://github.com/firelock-ai/kin"
  version "1.2.3"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/firelock-ai/kin/releases/download/v#{{version}}/kin-macos-aarch64.tar.gz"
      sha256 "{FIXTURE_CHECKSUMS["kin-macos-aarch64.tar.gz"]}"
    end
    on_intel do
      url "https://github.com/firelock-ai/kin/releases/download/v#{{version}}/kin-macos-x86_64.tar.gz"
      sha256 "{FIXTURE_CHECKSUMS["kin-macos-x86_64.tar.gz"]}"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/firelock-ai/kin/releases/download/v#{{version}}/kin-linux-x86_64.tar.gz"
      sha256 "{FIXTURE_CHECKSUMS["kin-linux-x86_64.tar.gz"]}"
    end
    on_arm do
      url "https://github.com/firelock-ai/kin/releases/download/v#{{version}}/kin-linux-aarch64.tar.gz"
      sha256 "{FIXTURE_CHECKSUMS["kin-linux-aarch64.tar.gz"]}"
    end
  end

  def install
    bin.install "kin"
    bin.install "kin-daemon"
    bin.install "kin-vfs" if File.exist?("kin-vfs")
    lib.install "libkin_vfs_shim.dylib" if File.exist?("libkin_vfs_shim.dylib")
    lib.install "libkin_vfs_shim.so" if File.exist?("libkin_vfs_shim.so")
  end

  test do
    assert_match "kin", shell_output("#{{bin}}/kin --version")
  end
end
'''


def replace_fixture_version(replacement: str) -> str:
    formula = current_real_formula_shape()
    marker = '  version "1.2.3"'
    assert formula.count(marker) == 1
    return formula.replace(marker, replacement)


def replace_fixture_install(replacement: str) -> str:
    formula = current_real_formula_shape()
    canonical_install = """  def install
    bin.install "kin"
    bin.install "kin-daemon"
    bin.install "kin-vfs" if File.exist?("kin-vfs")
    lib.install "libkin_vfs_shim.dylib" if File.exist?("libkin_vfs_shim.dylib")
    lib.install "libkin_vfs_shim.so" if File.exist?("libkin_vfs_shim.so")
  end"""
    assert formula.count(canonical_install) == 1
    return formula.replace(canonical_install, replacement, 1)


def assert_ruby_syntax_valid(formula: str) -> None:
    ruby = shutil.which("ruby")
    if ruby is None:
        return
    result = subprocess.run(
        [ruby, "-c"],
        input=formula,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def assert_validator_rejects(
    formula: str, expected_error: str, *, ruby_syntax_valid: bool = True
) -> None:
    if ruby_syntax_valid:
        assert_ruby_syntax_valid(formula)
    result = run_validator(formula)
    output = result.stdout.decode() + result.stderr.decode()
    assert result.returncode == 1, output
    assert expected_error in output, output


def test_exact_public_formula_and_checksums_succeed_without_token() -> None:
    result, curl_args, attempts = run_verifier()
    assert result.returncode == 0, result.stdout + result.stderr
    assert attempts == {"formula": 1, "checksums": 4}
    lines = curl_args.splitlines()
    assert len(lines) == 5, lines
    assert "raw.githubusercontent.com/firelock-ai/homebrew-kin" in lines[0]
    assert "kind=formula" in lines[0]
    for artifact, line in zip(
        (
            "kin-macos-aarch64.tar.gz",
            "kin-macos-x86_64.tar.gz",
            "kin-linux-aarch64.tar.gz",
            "kin-linux-x86_64.tar.gz",
        ),
        lines[1:],
        strict=True,
    ):
        assert f"/releases/download/v1.2.3/{artifact}.sha256" in line
        assert f"kind=checksum-{artifact}" in line
    assert all("kin_release=1.2.3&attempt=1" in line for line in lines)
    assert all("--disable" in line for line in lines)
    assert all("Cache-Control: no-cache" in line for line in lines)
    assert all("--connect-timeout 1" in line for line in lines)
    assert all("--max-time 1" in line for line in lines)
    assert all("--output" in line for line in lines)
    assert "Authorization" not in curl_args
    assert "exactly matches Kin v1.2.3" in result.stdout


def test_raw_nul_in_formula_fails_before_parsing() -> None:
    assert_bounded_failure(
        formula_mode="raw_nul",
        expected_error="public formula contains a NUL byte",
    )


def test_raw_nul_in_each_release_sidecar_fails_before_parsing() -> None:
    for artifact in FIXTURE_CHECKSUMS:
        assert_bounded_failure(
            sidecar_nul_artifact=artifact,
            expected_error=f"public {artifact} contains a NUL byte",
        )


def test_poll_then_exact_success() -> None:
    result, _, attempts = run_verifier(success_after=2)
    assert result.returncode == 0, result.stdout + result.stderr
    assert attempts == {"formula": 2, "checksums": 8}
    assert "attempt 1/3" in result.stdout


def test_polling_is_bounded_by_attempt_limit() -> None:
    result, curl_args, attempts = run_verifier(success_after=99)
    assert result.returncode == 1
    assert attempts == {"formula": 3, "checksums": 12}
    assert "after 3 checks" in result.stderr
    assert "attempt=3" in curl_args


def test_stale_formula_checksum_fails() -> None:
    assert_bounded_failure(
        formula_mode="stale_checksum",
        expected_error="checksum mismatch for kin-macos-aarch64.tar.gz",
    )


def test_comment_only_version_fails() -> None:
    assert_bounded_failure(
        formula_mode="comment_only",
        expected_error="expected exactly one active version directive",
    )


def test_conditional_inactive_version_fails() -> None:
    assert_bounded_failure(
        formula_mode="conditional_version",
        expected_error="unsupported Ruby block outside an install/test body",
    )


def test_version_outside_kin_class_fails() -> None:
    assert_bounded_failure(
        formula_mode="version_outside_class",
        expected_error="version directive must be directly inside class Kin < Formula",
    )


def test_duplicate_kin_class_fails() -> None:
    assert_bounded_failure(
        formula_mode="duplicate_class",
        expected_error="expected exactly one class Kin < Formula declaration; found 2",
    )


def test_missing_linux_end_fails() -> None:
    assert_bounded_failure(
        formula_mode="missing_linux_end",
        expected_error="install block must be directly inside class Kin < Formula",
    )


def test_missing_arch_end_fails() -> None:
    assert_bounded_failure(
        formula_mode="missing_arch_end",
        expected_error=(
            "architecture block must be directly inside a supported operating-system block"
        ),
    )


def test_missing_class_end_fails() -> None:
    assert_bounded_failure(
        formula_mode="missing_class_end",
        expected_error="unclosed Ruby block(s): class Kin < Formula opened at line 1",
    )


def test_extra_end_fails() -> None:
    assert_bounded_failure(
        formula_mode="extra_end",
        expected_error="unmatched or extra end at formula line",
    )


def test_ruby_block_comment_cannot_supply_inactive_version() -> None:
    formula = replace_fixture_version('=begin\n  version "1.2.3"\n=end')
    assert_validator_rejects(formula, "Ruby block comments")


def test_ruby_heredoc_cannot_supply_inactive_version() -> None:
    formula = replace_fixture_version(
        '  ignored_version = <<~KIN_VERSION\n    version "1.2.3"\n  KIN_VERSION'
    )
    assert_validator_rejects(formula, "Ruby heredocs and shift expressions")


def test_ruby_brace_block_cannot_supply_inactive_version() -> None:
    formula = replace_fixture_version('  [false].each {\n    version "1.2.3"\n  }')
    assert_validator_rejects(formula, "Ruby brace blocks and hash literals")


def test_ruby_percent_literal_cannot_supply_inactive_version() -> None:
    formula = replace_fixture_version(
        '  ignored_version = %q(\n    version "1.2.3"\n  )'
    )
    assert_validator_rejects(formula, "Ruby percent literals")


def test_hash_delimited_percent_literal_cannot_escape_install_scope() -> None:
    scope_escape = """  def install
    %q=#=; end
    $kin_gate_bypass = :executed_at_class_scope
    %q=#=; if true
  end"""
    formula = replace_fixture_install(scope_escape)

    assert_ruby_syntax_valid(formula)
    assert_validator_rejects(formula, "Ruby percent literals")


def test_hash_character_literal_cannot_hide_percent_scope_escape() -> None:
    scope_escape = """  def install
    ?#; %q=#=; end
    $kin_gate_bypass = :executed_at_class_scope
    ?#; %q=#=; if true
  end"""
    formula = replace_fixture_install(scope_escape)

    assert_ruby_syntax_valid(formula)
    assert_validator_rejects(formula, "Ruby character literals and ternary expressions")


def test_hash_character_literal_cannot_escape_install_scope_without_percent() -> None:
    scope_escape = """  def install
    ?#; end
    $kin_gate_bypass = :executed_at_class_scope
    ?#; if true
  end"""
    formula = replace_fixture_install(scope_escape)

    assert_ruby_syntax_valid(formula)
    assert_validator_rejects(formula, "Ruby character literals and ternary expressions")


def test_escaped_character_literals_cannot_hide_comment_boundaries() -> None:
    for character_literal in (r"?\C-#", r"?\c#", r"?\M-#"):
        scope_escape = f"""  def install
    {character_literal}; end
    $kin_gate_bypass = :executed_at_class_scope
    {character_literal}; if true
  end"""
        formula = replace_fixture_install(scope_escape)

        assert_ruby_syntax_valid(formula)
        assert_validator_rejects(
            formula, "Ruby character literals and ternary expressions"
        )


def test_numeric_and_variable_ternaries_cannot_bypass_question_guard() -> None:
    for condition in (
        "1",
        "1_000",
        "0xff",
        "@ivar",
        "@@cvar",
        "$gvar",
        "$-a",
        "$-d",
        "$-F",
        "$-i",
        "$-I",
        "$-l",
        "$-p",
        "$-v",
        "$-w",
        "$-W",
    ):
        formula = current_real_formula_shape().replace(
            '    bin.install "kin"',
            f'    value = {condition}?2:3\n    bin.install "kin"',
            1,
        )

        assert_ruby_syntax_valid(formula)
        assert_validator_rejects(
            formula, "Ruby character literals and ternary expressions"
        )


def test_predicate_identifier_with_digit_remains_supported() -> None:
    formula = current_real_formula_shape().replace("File.exist?", "File.ready1?", 1)
    assert_ruby_syntax_valid(formula)

    result = run_validator(formula)

    assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()


def test_percent_characters_inside_strings_and_comments_remain_data() -> None:
    formula = current_real_formula_shape().replace(
        '    bin.install "kin"',
        '    puts "100% verified ?#"\n    # 100% comment ?#\n    bin.install "kin"',
        1,
    )
    assert_ruby_syntax_valid(formula)

    result = run_validator(formula)

    assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()


def test_unparsed_ruby_regex_cannot_supply_inactive_version() -> None:
    formula = replace_fixture_version('  ignored_version = /\n    version "1.2.3"\n  /')
    assert_validator_rejects(
        formula, "Ruby regular expressions and division expressions"
    )


def test_multiline_ruby_regex_inside_install_body_is_rejected() -> None:
    formula = current_real_formula_shape().replace(
        '    bin.install "kin"',
        '    ignored = /\n      version "9.9.9"\n    /x\n    bin.install "kin"',
        1,
    )
    assert_validator_rejects(
        formula, "Ruby regular expressions and division expressions"
    )


def test_reopened_kin_class_is_rejected() -> None:
    formula = (
        current_real_formula_shape()
        + """
class Kin
  def install
    bin.install "replacement"
  end
end
"""
    )
    assert_validator_rejects(
        formula, "Ruby class reopening and additional class declarations"
    )


def test_version_dsl_cannot_be_shadowed_by_class_method() -> None:
    formula = current_real_formula_shape().replace(
        '  version "1.2.3"',
        '  def self.version(*)\n  end\n  version "1.2.3"',
        1,
    )
    assert_validator_rejects(
        formula, "unsupported Ruby class/module/method declaration"
    )


def test_platform_dsl_cannot_be_shadowed_by_class_method() -> None:
    formula = current_real_formula_shape().replace(
        "  on_macos do",
        "  def self.on_macos(&block)\n  end\n\n  on_macos do",
        1,
    )
    assert_validator_rejects(
        formula, "unsupported Ruby class/module/method declaration"
    )


def test_metadata_cannot_append_a_dsl_shadowing_statement() -> None:
    formula = current_real_formula_shape().replace(
        '  desc "Semantic system of record for AI-written software"',
        '  desc "Semantic system of record for AI-written software"; '
        "define_singleton_method(:version, method(:puts))",
        1,
    )
    assert_validator_rejects(formula, "multiple Ruby statements")


def test_metadata_requires_one_canonical_quoted_string() -> None:
    formula = current_real_formula_shape().replace(
        '  license "Apache-2.0"',
        '  license("Apache-2.0")',
        1,
    )
    assert_validator_rejects(
        formula, "metadata directives must use one canonical quoted-string statement"
    )


def test_metadata_cannot_execute_ruby_interpolation() -> None:
    formula = current_real_formula_shape().replace(
        '  desc "Semantic system of record for AI-written software"',
        '  desc "#{define_singleton_method(:version, method(:puts))}'
        'Semantic system of record for AI-written software"',
        1,
    )
    assert_validator_rejects(
        formula, "metadata directives cannot contain Ruby interpolation"
    )


def test_ruby_data_section_is_rejected_fail_closed() -> None:
    formula = current_real_formula_shape() + '__END__\nversion "1.2.3"\n'
    assert_validator_rejects(formula, "Ruby data sections")


def test_duplicate_empty_os_block_fails() -> None:
    formula = current_real_formula_shape().replace(
        "  on_macos do", "  on_macos do\n  end\n\n  on_macos do", 1
    )
    assert_validator_rejects(
        formula,
        "expected exactly one on_macos block directly inside class Kin < Formula; found 2",
    )


def test_duplicate_empty_arch_block_fails() -> None:
    formula = current_real_formula_shape().replace(
        "    on_arm do", "    on_arm do\n    end\n    on_arm do", 1
    )
    assert_validator_rejects(
        formula,
        "expected exactly one on_arm block directly inside on_macos; found 2",
    )


def test_unsupported_os_block_fails() -> None:
    formula = current_real_formula_shape().replace(
        "  on_macos do", "  on_windows do\n  end\n\n  on_macos do", 1
    )
    assert_validator_rejects(
        formula, "unsupported or malformed Homebrew platform block 'on_windows'"
    )


def test_os_block_outside_direct_class_scope_fails() -> None:
    assert_bounded_failure(
        formula_mode="nested_os",
        expected_error="unsupported Ruby block outside an install/test body",
    )


def test_arch_block_outside_direct_os_scope_fails() -> None:
    assert_bounded_failure(
        formula_mode="nested_arch",
        expected_error="unsupported Ruby block outside an install/test body",
    )


def test_url_outside_direct_arch_scope_fails() -> None:
    assert_bounded_failure(
        formula_mode="nested_url",
        expected_error="unsupported Ruby block outside an install/test body",
    )


def test_sha_must_immediately_pair_with_direct_arch_url() -> None:
    assert_bounded_failure(
        formula_mode="nested_sha",
        expected_error="missing sha256 directive after URL for kin-macos-aarch64.tar.gz",
    )


def test_current_real_formula_shape_is_accepted() -> None:
    result = run_validator(current_real_formula_shape())
    assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()


def test_missing_artifact_mapping_fails() -> None:
    assert_bounded_failure(
        formula_mode="missing_mapping",
        expected_error="expected exactly one on_arm block directly inside on_linux; found 0",
    )


def test_duplicate_artifact_mapping_fails() -> None:
    assert_bounded_failure(
        formula_mode="duplicate_mapping",
        expected_error="expected exactly one on_arm block directly inside on_macos; found 2",
    )


def test_malformed_artifact_mapping_fails() -> None:
    assert_bounded_failure(
        formula_mode="malformed_mapping",
        expected_error="unexpected URL for linux/arm",
    )


def test_malformed_formula_checksum_fails() -> None:
    assert_bounded_failure(
        formula_mode="malformed_sha",
        expected_error="malformed sha256 for kin-linux-x86_64.tar.gz",
    )


def test_missing_duplicate_malformed_and_swapped_release_sidecars_fail() -> None:
    for mode, message in (
        ("sidecar_missing", "must contain exactly one nonblank entry; found 0"),
        ("sidecar_duplicate", "must contain exactly one nonblank entry; found 2"),
        ("sidecar_malformed", "malformed public checksum sidecar"),
        ("sidecar_swapped", "names 'kin-macos-x86_64.tar.gz'"),
    ):
        assert_bounded_failure(sidecar_mode=mode, expected_error=message)


def test_release_defaults_remain_1800_seconds_and_90_attempts() -> None:
    verifier = VERIFIER.read_text(encoding="utf-8")
    assert "KIN_HOMEBREW_VERIFY_MAX_WAIT_SECONDS:-1800" in verifier
    assert "KIN_HOMEBREW_VERIFY_MAX_ATTEMPTS:-90" in verifier
    assert "deadline=$((SECONDS + max_wait_seconds))" in verifier
    assert '--max-time "$request_timeout"' in verifier


def test_dispatch_result_cannot_skip_verification() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    marker = "      - name: Prove Homebrew workflow and public formula\n"
    start = workflow.index(marker)
    next_step = workflow.find("\n      - name:", start + len(marker))
    verification_step = workflow[start : next_step if next_step != -1 else None]

    assert 'bash scripts/verify-homebrew-formula.sh "$KIN_TAG"' in verification_step
    assert "steps.homebrew-dispatch.outputs.dispatched_at" in verification_step
    assert "if:" not in verification_step
    assert "TAP_DISPATCH_TOKEN" not in verification_step


def main() -> None:
    assert VALIDATOR.is_file(), f"missing validator: {VALIDATOR}"
    tests = (
        test_exact_public_formula_and_checksums_succeed_without_token,
        test_raw_nul_in_formula_fails_before_parsing,
        test_raw_nul_in_each_release_sidecar_fails_before_parsing,
        test_poll_then_exact_success,
        test_polling_is_bounded_by_attempt_limit,
        test_stale_formula_checksum_fails,
        test_comment_only_version_fails,
        test_conditional_inactive_version_fails,
        test_version_outside_kin_class_fails,
        test_duplicate_kin_class_fails,
        test_missing_linux_end_fails,
        test_missing_arch_end_fails,
        test_missing_class_end_fails,
        test_extra_end_fails,
        test_ruby_block_comment_cannot_supply_inactive_version,
        test_ruby_heredoc_cannot_supply_inactive_version,
        test_ruby_brace_block_cannot_supply_inactive_version,
        test_ruby_percent_literal_cannot_supply_inactive_version,
        test_hash_delimited_percent_literal_cannot_escape_install_scope,
        test_hash_character_literal_cannot_hide_percent_scope_escape,
        test_hash_character_literal_cannot_escape_install_scope_without_percent,
        test_escaped_character_literals_cannot_hide_comment_boundaries,
        test_numeric_and_variable_ternaries_cannot_bypass_question_guard,
        test_predicate_identifier_with_digit_remains_supported,
        test_percent_characters_inside_strings_and_comments_remain_data,
        test_unparsed_ruby_regex_cannot_supply_inactive_version,
        test_multiline_ruby_regex_inside_install_body_is_rejected,
        test_reopened_kin_class_is_rejected,
        test_version_dsl_cannot_be_shadowed_by_class_method,
        test_platform_dsl_cannot_be_shadowed_by_class_method,
        test_metadata_cannot_append_a_dsl_shadowing_statement,
        test_metadata_requires_one_canonical_quoted_string,
        test_metadata_cannot_execute_ruby_interpolation,
        test_ruby_data_section_is_rejected_fail_closed,
        test_duplicate_empty_os_block_fails,
        test_duplicate_empty_arch_block_fails,
        test_unsupported_os_block_fails,
        test_os_block_outside_direct_class_scope_fails,
        test_arch_block_outside_direct_os_scope_fails,
        test_url_outside_direct_arch_scope_fails,
        test_sha_must_immediately_pair_with_direct_arch_url,
        test_current_real_formula_shape_is_accepted,
        test_missing_artifact_mapping_fails,
        test_duplicate_artifact_mapping_fails,
        test_malformed_artifact_mapping_fails,
        test_malformed_formula_checksum_fails,
        test_missing_duplicate_malformed_and_swapped_release_sidecars_fail,
        test_release_defaults_remain_1800_seconds_and_90_attempts,
        test_dispatch_result_cannot_skip_verification,
    )
    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
    print(f"{len(tests)} Homebrew release gate tests passed")


if __name__ == "__main__":
    main()

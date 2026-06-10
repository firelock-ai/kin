# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# =============================================================================
#  DRAFT FORMULA — NOT YET INSTALLABLE
# -----------------------------------------------------------------------------
#  The `sha256` values below are PLACEHOLDERS, not real checksums. This formula
#  is committed so the packaging shape is reviewable, but it will NOT install
#  until a real tagged release exists and these are filled in.
#
#  Before publishing this to a Homebrew tap you MUST:
#    1. Tag and publish a release (see .github/workflows/release.yml). Each
#       release uploads `<asset>.tar.gz` and a matching `<asset>.tar.gz.sha256`.
#    2. Set `version` below to that release tag, WITHOUT the leading "v"
#       (e.g. tag v0.1.0-alpha.1  ->  version "0.1.0-alpha.1").
#    3. Replace each placeholder `sha256` with the real hash, e.g.:
#         curl -fsSL \
#           https://github.com/firelock-ai/kin/releases/download/v0.1.0-alpha.1/kin-macos-aarch64.tar.gz.sha256
#
#  Do NOT paste a zero/dummy 64-hex hash to make `brew` proceed — that would
#  silently install an unverified binary. A real release is the only fix; until
#  then the obviously-non-hex placeholders below make `brew` fail fast on
#  purpose.
# =============================================================================
class Kin < Formula
  desc "Semantic system of record for software work"
  homepage "https://github.com/firelock-ai/kin"
  version "0.1.0-alpha.1" # TODO: set to the real released tag (no leading "v")
  license "Apache-2.0"

  # macOS-only for now. The release also publishes Linux tarballs
  # (kin-linux-x86_64 / kin-linux-aarch64); add `on_linux` blocks here when a
  # Linux tap target is wanted. Windows users should use WSL2 (see
  # docs/windows-wsl2.md) and install via the Linux path.
  on_macos do
    on_arm do
      url "https://github.com/firelock-ai/kin/releases/download/v#{version}/kin-macos-aarch64.tar.gz"
      # TODO: real hash from kin-macos-aarch64.tar.gz.sha256
      sha256 "REPLACE_WITH_RELEASE_SHA256_kin_macos_aarch64"
    end
    on_intel do
      url "https://github.com/firelock-ai/kin/releases/download/v#{version}/kin-macos-x86_64.tar.gz"
      # TODO: real hash from kin-macos-x86_64.tar.gz.sha256
      sha256 "REPLACE_WITH_RELEASE_SHA256_kin_macos_x86_64"
    end
  end

  def install
    # The release tarball expands to a directory named after the asset
    # (e.g. kin-macos-aarch64/) holding `kin`, `kin-vfs`, and the VFS shim
    # (libkin_vfs_shim.dylib). Homebrew changes into that single root dir on
    # extract, so the binaries are at the current path here.
    bin.install "kin"
    bin.install "kin-vfs" if File.exist?("kin-vfs")
  end

  test do
    assert_match "kin", shell_output("#{bin}/kin --version")
  end
end

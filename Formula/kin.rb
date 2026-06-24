# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
class Kin < Formula
  desc "Semantic system of record for software work"
  homepage "https://github.com/firelock-ai/kin"
  version "0.2.2"
  license "Apache-2.0"

  # macOS-only for now. The release also publishes Linux tarballs
  # (kin-linux-x86_64 / kin-linux-aarch64); add `on_linux` blocks here when a
  # Linux tap target is wanted. Windows users should use WSL2 (see
  # docs/windows-wsl2.md) and install via the Linux path.
  on_macos do
    on_arm do
      url "https://github.com/firelock-ai/kin/releases/download/v#{version}/kin-macos-aarch64.tar.gz"
      sha256 "7a222f929ce0984e5a4478cf4db9a4b53726b6fc62c25ae01f16adf5b40ccfe2"
    end
    on_intel do
      url "https://github.com/firelock-ai/kin/releases/download/v#{version}/kin-macos-x86_64.tar.gz"
      sha256 "621230294d298b17f482daabe3f0b7fce4fc92f28b3b0e41ebebff9e2c77acff"
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

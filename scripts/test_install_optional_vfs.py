#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Behavior tests for the optional VFS portion of the Unix installer."""

from __future__ import annotations

import hashlib
import os
import platform
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "scripts" / "install.sh"
VERSION = "9.9.9"


def target_name() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    os_name = {"Darwin": "macos", "Linux": "linux"}[system]
    arch = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }[machine]
    return f"{os_name}-{arch}"


def executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class OptionalVfsInstallerTests(unittest.TestCase):
    def run_installer(
        self, *, vfs_exit: int
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        target = target_name()
        archive_root = root / f"kin-{target}"
        archive_root.mkdir()

        executable(
            archive_root / "kin",
            "#!/bin/sh\nprintf 'kin 9.9.9\\n'\n",
        )
        executable(archive_root / "kin-daemon", "#!/bin/sh\nexit 0\n")
        executable(
            archive_root / "kin-vfs",
            f"#!/bin/sh\nexit {vfs_exit}\n",
        )
        shim_name = (
            "libkin_vfs_shim.dylib"
            if platform.system() == "Darwin"
            else "libkin_vfs_shim.so"
        )
        (archive_root / shim_name).write_bytes(b"test shim")

        release_dir = root / "download" / f"v{VERSION}"
        release_dir.mkdir(parents=True)
        archive = release_dir / f"kin-{target}.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(archive_root, arcname=archive_root.name)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix(archive.suffix + ".sha256").write_text(
            f"{digest}  {archive.name}\n", encoding="utf-8"
        )

        home = root / "home"
        home.mkdir()
        kin_home = home / ".kin"
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(home),
                "KIN_BASE_URL": root.as_uri(),
                "KIN_HOME": str(kin_home),
                "KIN_NO_SETUP": "1",
                "KIN_VERSION": VERSION,
                "SHELL": "/bin/sh",
            }
        )
        result = subprocess.run(
            ["sh", str(INSTALLER)],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        return result, kin_home

    def test_reports_projection_only_when_vfs_is_executable(self) -> None:
        result, kin_home = self.run_installer(vfs_exit=0)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Filesystem projection installed", result.stdout)
        self.assertTrue((kin_home / "bin" / "kin-vfs").exists())

    def test_removes_and_reports_unusable_projection(self) -> None:
        result, kin_home = self.run_installer(vfs_exit=127)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Filesystem projection installed", result.stdout)
        self.assertIn("Filesystem projection is unavailable", result.stdout)
        self.assertFalse((kin_home / "bin" / "kin-vfs").exists())
        self.assertFalse(any((kin_home / "lib").glob("libkin_vfs_shim.*")))


if __name__ == "__main__":
    unittest.main()

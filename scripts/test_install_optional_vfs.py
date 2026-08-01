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
        self,
        *,
        vfs_exit: int,
        pretend_macos: bool = False,
        archive_notifier: bool = True,
        symlinked_notifier_ancestry: bool = False,
        existing_notifier: bool = False,
        seed_current_install: bool = False,
        seed_launcher_stamp: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        target = "macos-x86_64" if pretend_macos else target_name()
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
        if target.startswith("macos-") and archive_notifier:
            bundle_root = archive_root / "KinNotifier.app"
            notifier = bundle_root / (
                "Payload" if symlinked_notifier_ancestry else "Contents"
            )
            (notifier / "MacOS").mkdir(parents=True)
            (notifier / "Resources").mkdir()
            executable(
                notifier / "MacOS" / "KinNotifier",
                "#!/bin/sh\nprintf 'new-notifier\\n'\n",
            )
            (notifier / "Info.plist").write_text("<plist>new</plist>", encoding="utf-8")
            if symlinked_notifier_ancestry:
                (bundle_root / "Contents").symlink_to("Payload", target_is_directory=True)

        release_dir = root / "download" / f"v{VERSION}"
        release_dir.mkdir(parents=True)
        archive = release_dir / f"kin-{target}.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.dereference = False
            bundle.add(archive_root, arcname=archive_root.name)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix(archive.suffix + ".sha256").write_text(
            f"{digest}  {archive.name}\n", encoding="utf-8"
        )

        home = root / "home"
        home.mkdir()
        kin_home = home / ".kin"
        if seed_current_install:
            (kin_home / "bin").mkdir(parents=True)
            executable(
                kin_home / "bin" / "kin",
                "#!/bin/sh\n# old-kin\nprintf 'kin 9.9.9\\n'\n",
            )
            executable(kin_home / "bin" / "kin-daemon", "#!/bin/sh\nprintf 'old-daemon\\n'\n")
        if seed_launcher_stamp:
            (kin_home / "bin").mkdir(parents=True, exist_ok=True)
            (kin_home / "bin" / ".kinlab-kin-version").write_text(
                "8.8.8\n", encoding="utf-8"
            )
        if existing_notifier:
            old_contents = kin_home / "lib" / "KinNotifier.app" / "Contents"
            (old_contents / "MacOS").mkdir(parents=True)
            executable(
                old_contents / "MacOS" / "KinNotifier",
                "#!/bin/sh\nprintf 'old-notifier\\n'\n",
            )
            (old_contents / "Info.plist").write_text("<plist>old</plist>", encoding="utf-8")
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
        if pretend_macos:
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            executable(
                fake_bin / "uname",
                "#!/bin/sh\n"
                "case \"${1:-}\" in\n"
                "  -s) printf 'Darwin\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
            )
            env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
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

    def test_same_version_managed_reinstall_restores_a_missing_bundle(self) -> None:
        result, kin_home = self.run_installer(
            vfs_exit=0,
            pretend_macos=True,
            seed_current_install=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Existing install found: kin 9.9.9 (will be replaced)", result.stdout)
        notifier = (
            kin_home
            / "lib"
            / "KinNotifier.app"
            / "Contents"
            / "MacOS"
            / "KinNotifier"
        )
        self.assertIn("new-notifier", notifier.read_text(encoding="utf-8"))
        self.assertTrue(notifier.stat().st_mode & stat.S_IXUSR)
        self.assertTrue(
            (kin_home / "lib" / "KinNotifier.app" / "Contents" / "Info.plist").is_file()
        )

    def test_malformed_macos_archive_refuses_before_replacing_existing_install(self) -> None:
        result, kin_home = self.run_installer(
            vfs_exit=0,
            pretend_macos=True,
            archive_notifier=False,
            existing_notifier=True,
            seed_current_install=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No installed binary or notification bundle was replaced", result.stderr)
        self.assertIn(
            "kin 9.9.9",
            (kin_home / "bin" / "kin").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "old-notifier",
            (
                kin_home
                / "lib"
                / "KinNotifier.app"
                / "Contents"
                / "MacOS"
                / "KinNotifier"
            ).read_text(encoding="utf-8"),
        )

    def test_symlinked_bundle_ancestor_refuses_before_replacing_install_or_stamp(self) -> None:
        result, kin_home = self.run_installer(
            vfs_exit=0,
            pretend_macos=True,
            symlinked_notifier_ancestry=True,
            existing_notifier=True,
            seed_current_install=True,
            seed_launcher_stamp=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("contains a symlink or special entry", result.stderr)
        self.assertIn("No installed binary or notification bundle was replaced", result.stderr)
        self.assertEqual(
            (kin_home / "bin" / "kin").read_text(encoding="utf-8"),
            "#!/bin/sh\n# old-kin\nprintf 'kin 9.9.9\\n'\n",
        )
        self.assertEqual(
            (kin_home / "bin" / "kin-daemon").read_text(encoding="utf-8"),
            "#!/bin/sh\nprintf 'old-daemon\\n'\n",
        )
        self.assertEqual(
            (
                kin_home
                / "lib"
                / "KinNotifier.app"
                / "Contents"
                / "MacOS"
                / "KinNotifier"
            ).read_text(encoding="utf-8"),
            "#!/bin/sh\nprintf 'old-notifier\\n'\n",
        )
        self.assertEqual(
            (
                kin_home / "lib" / "KinNotifier.app" / "Contents" / "Info.plist"
            ).read_text(encoding="utf-8"),
            "<plist>old</plist>",
        )
        self.assertEqual(
            (kin_home / "bin" / ".kinlab-kin-version").read_text(encoding="utf-8"),
            "8.8.8\n",
        )


if __name__ == "__main__":
    unittest.main()

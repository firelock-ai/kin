#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Tests for the exact public installer parity gate."""

from __future__ import annotations

import json
import unittest

from verify_installer_parity import ParityError, sha256, verify_payloads


TAG = "v0.2.16"
COMMIT = "a" * 40
INSTALL = b"#!/bin/sh\necho kin\n"
INSTALL_PS1 = b'Write-Output "Kin"\n'


def manifest() -> bytes:
    return json.dumps(
        {
            "schema": 1,
            "tag": TAG,
            "sha": COMMIT,
            "install_sha256": sha256(INSTALL),
            "install_ps1_sha256": sha256(INSTALL_PS1),
            "install_generation": "101",
            "install_ps1_generation": "102",
        }
    ).encode()


class InstallerParityTests(unittest.TestCase):
    def verify(self, **overrides: bytes) -> None:
        values = {
            "source_install": INSTALL,
            "source_install_ps1": INSTALL_PS1,
            "public_install": INSTALL,
            "public_install_ps1": INSTALL_PS1,
            "public_manifest": manifest(),
        }
        values.update(overrides)
        verify_payloads(tag=TAG, commit=COMMIT, **values)

    def test_exact_pair_and_manifest_pass(self) -> None:
        self.verify()

    def test_wording_only_powershell_drift_is_not_ready(self) -> None:
        with self.assertRaisesRegex(ParityError, "public install.ps1 hash mismatch"):
            self.verify(public_install_ps1=INSTALL_PS1 + b"# stale wording\n")

    def test_missing_manifest_is_not_ready(self) -> None:
        with self.assertRaisesRegex(ParityError, "current.json is missing or invalid"):
            self.verify(public_manifest=b"")

    def test_manifest_must_bind_exact_tag(self) -> None:
        wrong = json.loads(manifest())
        wrong["tag"] = "v0.2.15"
        with self.assertRaisesRegex(ParityError, "current.json tag"):
            self.verify(public_manifest=json.dumps(wrong).encode())


if __name__ == "__main__":
    unittest.main()

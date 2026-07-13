#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Tests for the exact public installer parity gate."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from verify_installer_parity import (
    ParityError,
    fetch_response,
    sha256,
    verify_payloads,
)


TAG = "v0.2.20"
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
    def verify(self, **overrides: bytes | str | None) -> None:
        values = {
            "source_install": INSTALL,
            "source_install_ps1": INSTALL_PS1,
            "public_install": INSTALL,
            "public_install_ps1": INSTALL_PS1,
            "public_manifest": manifest(),
            "public_install_generation": "101",
            "public_install_ps1_generation": "102",
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
        wrong["tag"] = "v0.2.19"
        with self.assertRaisesRegex(ParityError, "current.json tag"):
            self.verify(public_manifest=json.dumps(wrong).encode())

    def test_manifest_generation_must_match_public_header(self) -> None:
        wrong = json.loads(manifest())
        wrong["install_generation"] = "999"
        with self.assertRaisesRegex(ParityError, "current.json install_generation"):
            self.verify(public_manifest=json.dumps(wrong).encode())

    def test_both_public_generation_headers_are_required(self) -> None:
        with self.assertRaisesRegex(
            ParityError, "missing or invalid x-goog-generation"
        ):
            self.verify(public_install_ps1_generation=None)

    @mock.patch("verify_installer_parity.urllib.request.urlopen")
    def test_fetch_response_captures_generation_header(
        self, urlopen: mock.MagicMock
    ) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = INSTALL
        response.headers.get.return_value = " 777 "
        urlopen.return_value = response

        fetched = fetch_response("https://install.example.test/install", attempts=1)

        self.assertEqual(fetched.body, INSTALL)
        self.assertEqual(fetched.generation, "777")


if __name__ == "__main__":
    unittest.main()

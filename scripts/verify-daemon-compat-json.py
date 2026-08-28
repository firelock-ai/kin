#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Validate the released daemon's compatibility-range JSON contract."""

from __future__ import annotations

import json
import sys
from typing import Any


SCHEMA = "kin.daemon.compat.v2"


def _unsigned_version(payload: dict[str, Any], field: str) -> int:
    value = payload.get(field)
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def validate(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError("compatibility payload must be a JSON object")
    if payload.get("schema") != SCHEMA:
        raise ValueError(f"schema must be {SCHEMA}")

    graph_writer = _unsigned_version(payload, "graph_snapshot_version")
    graph_min = _unsigned_version(
        payload, "graph_snapshot_min_supported_version"
    )
    graph_max = _unsigned_version(
        payload, "graph_snapshot_max_supported_version"
    )
    if not graph_min <= graph_writer or graph_writer != graph_max:
        raise ValueError(
            "graph snapshot writer must equal the advertised reader maximum and not precede its minimum"
        )

    envelope_min = _unsigned_version(
        payload, "gcs_full_authority_envelope_min_supported_version"
    )
    envelope_max = _unsigned_version(
        payload, "gcs_full_authority_envelope_max_supported_version"
    )
    if envelope_min > envelope_max:
        raise ValueError(
            "GCS full-authority envelope minimum must not exceed its maximum"
        )


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        validate(payload)
    except (json.JSONDecodeError, ValueError) as error:
        print(f"error: invalid daemon compatibility contract: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

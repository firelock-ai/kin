// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

"use strict";

const fs = require("fs");

const MAX_COMPONENT_BYTES = 256 * 1024 * 1024;
const SENTINEL_BYTES = 198;
const START = Buffer.from("00894b494e555044415445010d0a1a0a", "hex");
const END = Buffer.from("00894b494e454e445631ff010d0a1a0a", "hex");
const SCHEMA = "kin.update-build.v1";

function fixedAscii(bytes, label) {
  const nul = bytes.indexOf(0);
  const end = nul === -1 ? bytes.length : nul;
  if (end === 0) {
    throw new Error(`static build identity ${label} is empty`);
  }
  if (nul !== -1 && bytes.subarray(nul).some((byte) => byte !== 0)) {
    throw new Error(`static build identity ${label} has nonzero padding`);
  }
  const valueBytes = bytes.subarray(0, end);
  if (valueBytes.some((byte) => byte < 0x21 || byte > 0x7e)) {
    throw new Error(`static build identity ${label} is not canonical ASCII`);
  }
  return valueBytes.toString("ascii");
}

function parseUpdateBuildIdentity(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    throw new TypeError("static build identity parser requires a Buffer");
  }
  if (bytes.length > MAX_COMPONENT_BYTES) {
    throw new Error(`candidate component exceeds the ${MAX_COMPONENT_BYTES}-byte static scan limit`);
  }

  const offsets = [];
  for (let offset = bytes.indexOf(START); offset !== -1; offset = bytes.indexOf(START, offset + 1)) {
    offsets.push(offset);
    if (offsets.length > 1) break;
  }
  if (offsets.length !== 1) {
    throw new Error(`candidate component contains ${offsets.length} static build identity sentinels; expected exactly one`);
  }
  const offset = offsets[0];
  if (offset + SENTINEL_BYTES > bytes.length) {
    throw new Error("candidate component contains a truncated static build identity sentinel");
  }
  const sentinel = bytes.subarray(offset, offset + SENTINEL_BYTES);
  if (!sentinel.subarray(182, 198).equals(END)) {
    throw new Error("candidate component static build identity end marker is invalid");
  }

  const schema = fixedAscii(sentinel.subarray(16, 40), "schema");
  const version = fixedAscii(sentinel.subarray(40, 72), "version");
  const commit = fixedAscii(sentinel.subarray(72, 112), "commit").toLowerCase();
  const cleanByte = sentinel[112];
  const sourceKnownByte = sentinel[113];
  const dependencyProvenance = fixedAscii(
    sentinel.subarray(114, 178),
    "dependency provenance"
  ).toLowerCase();
  const graphSnapshotVersion = sentinel.readUInt32LE(178);

  if (schema !== SCHEMA) throw new Error(`unsupported static build identity schema ${schema}`);
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`invalid static build identity version ${version}`);
  }
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error("static build identity commit is not a full hexadecimal commit");
  }
  if (cleanByte > 1 || sourceKnownByte > 1) {
    throw new Error("static build identity flags are not canonical booleans");
  }
  if (!/^[0-9a-f]{64}$/.test(dependencyProvenance)) {
    throw new Error("static build identity dependency provenance is not SHA-256");
  }
  if (graphSnapshotVersion === 0) {
    throw new Error("static build identity graph snapshot version must be nonzero");
  }

  return {
    schema,
    version,
    commit,
    clean: cleanByte === 1,
    source_known: sourceKnownByte === 1,
    dependency_provenance: dependencyProvenance,
    graph_snapshot_version: graphSnapshotVersion,
  };
}

function readUpdateBuildIdentity(path) {
  const stat = fs.statSync(path);
  if (!stat.isFile()) throw new Error(`candidate component is not a file: ${path}`);
  if (stat.size > MAX_COMPONENT_BYTES) {
    throw new Error(`candidate component exceeds the ${MAX_COMPONENT_BYTES}-byte static scan limit`);
  }
  return parseUpdateBuildIdentity(fs.readFileSync(path));
}

module.exports = {
  MAX_COMPONENT_BYTES,
  SENTINEL_BYTES,
  parseUpdateBuildIdentity,
  readUpdateBuildIdentity,
};

if (require.main === module) {
  if (process.argv.length !== 3) {
    console.error("usage: node scripts/read-update-build-identity.cjs <binary>");
    process.exit(2);
  }
  process.stdout.write(`${JSON.stringify(readUpdateBuildIdentity(process.argv[2]))}\n`);
}

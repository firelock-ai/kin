// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  MAX_COMPONENT_BYTES,
  parseUpdateBuildIdentity,
  readUpdateBuildIdentity,
  SENTINEL_BYTES,
} = require("./read-update-build-identity.cjs");

const START = Buffer.from("00894b494e555044415445010d0a1a0a", "hex");
const END = Buffer.from("00894b494e454e445631ff010d0a1a0a", "hex");

function sentinelFixture() {
  const sentinel = Buffer.alloc(SENTINEL_BYTES);
  START.copy(sentinel, 0);
  sentinel.write("kin.update-build.v1", 16, "ascii");
  sentinel.write("1.2.3", 40, "ascii");
  sentinel.write("a".repeat(40), 72, "ascii");
  sentinel[112] = 1;
  sentinel[113] = 1;
  sentinel.write("b".repeat(64), 114, "ascii");
  sentinel.writeUInt32LE(7, 178);
  END.copy(sentinel, 182);
  return sentinel;
}

function fixture(prefix = Buffer.from("prefix")) {
  return Buffer.concat([prefix, sentinelFixture(), Buffer.from("suffix")]);
}

const EXPECTED = {
  schema: "kin.update-build.v1",
  version: "1.2.3",
  commit: "a".repeat(40),
  clean: true,
  source_known: true,
  dependency_provenance: "b".repeat(64),
  graph_snapshot_version: 7,
};

test("parses canonical identities from ELF, Mach-O, and PE/COFF candidates", () => {
  const candidates = [
    fixture(Buffer.from("7f454c4602010100", "hex")),
    fixture(Buffer.from("cffaedfe0c000001", "hex")),
    fixture(Buffer.from("4d5a900003000000", "hex")),
  ];
  for (const candidate of candidates) {
    assert.deepEqual(parseUpdateBuildIdentity(candidate), EXPECTED);
  }
});

test("rejects missing, duplicate, truncated, and noncanonical sentinels", () => {
  assert.throws(() => parseUpdateBuildIdentity(Buffer.from("none")), /exactly one/);
  const valid = fixture();
  assert.throws(() => parseUpdateBuildIdentity(Buffer.concat([valid, valid])), /2 static/);
  assert.throws(
    () => parseUpdateBuildIdentity(valid.subarray(0, valid.length - 10)),
    /truncated|end marker/
  );

  const offset = valid.indexOf(START);
  const invalidFlag = Buffer.from(valid);
  invalidFlag[offset + 112] = 2;
  assert.throws(() => parseUpdateBuildIdentity(invalidFlag), /canonical booleans/);

  const invalidPadding = Buffer.from(valid);
  invalidPadding[offset + 16 + "kin.update-build.v1".length + 1] = 1;
  assert.throws(() => parseUpdateBuildIdentity(invalidPadding), /nonzero padding/);

  const invalidAscii = Buffer.from(valid);
  invalidAscii[offset + 40] = 0x20;
  assert.throws(() => parseUpdateBuildIdentity(invalidAscii), /canonical ASCII/);

  const invalidEnd = Buffer.from(valid);
  invalidEnd[offset + 197] ^= 0xff;
  assert.throws(() => parseUpdateBuildIdentity(invalidEnd), /end marker/);

  const zeroGraphVersion = Buffer.from(valid);
  zeroGraphVersion.writeUInt32LE(0, offset + 178);
  assert.throws(() => parseUpdateBuildIdentity(zeroGraphVersion), /must be nonzero/);
});

test("keeps the static scan bound explicit", () => {
  assert.equal(MAX_COMPONENT_BYTES, 256 * 1024 * 1024);
  assert.throws(() => parseUpdateBuildIdentity("not a buffer"), /requires a Buffer/);
});

test("reads regular files and rejects non-files or oversized sparse files", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "kin-build-identity-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  const candidate = path.join(directory, "kin");
  fs.writeFileSync(candidate, fixture(Buffer.from("7f454c4602010100", "hex")));
  assert.deepEqual(readUpdateBuildIdentity(candidate), EXPECTED);
  assert.throws(() => readUpdateBuildIdentity(directory), /not a file/);

  const oversized = path.join(directory, "oversized");
  fs.closeSync(fs.openSync(oversized, "w"));
  fs.truncateSync(oversized, MAX_COMPONENT_BYTES + 1);
  assert.throws(() => readUpdateBuildIdentity(oversized), /static scan limit/);
});

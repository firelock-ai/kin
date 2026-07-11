#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import { pathToFileURL } from 'node:url';

const SEMVER = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function parseSemver(value) {
  const match = SEMVER.exec(value);
  if (!match) throw new Error(`invalid semantic version: ${value}`);
  const prerelease = match[4]?.split('.') ?? [];
  for (const identifier of prerelease) {
    if (/^\d+$/.test(identifier) && identifier.length > 1 && identifier.startsWith('0')) {
      throw new Error(`numeric prerelease identifiers may not have leading zeroes: ${value}`);
    }
  }
  return {
    core: [BigInt(match[1]), BigInt(match[2]), BigInt(match[3])],
    prerelease,
  };
}

export function compareSemver(left, right) {
  const a = parseSemver(left);
  const b = parseSemver(right);
  for (let index = 0; index < 3; index += 1) {
    if (a.core[index] !== b.core[index]) return a.core[index] < b.core[index] ? -1 : 1;
  }
  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0;
  if (a.prerelease.length === 0) return 1;
  if (b.prerelease.length === 0) return -1;
  const length = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = a.prerelease[index];
    const rightPart = b.prerelease[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;
    const leftNumeric = /^\d+$/.test(leftPart);
    const rightNumeric = /^\d+$/.test(rightPart);
    if (leftNumeric && rightNumeric) return BigInt(leftPart) < BigInt(rightPart) ? -1 : 1;
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftPart < rightPart ? -1 : 1;
  }
  return 0;
}

export function releaseChannel(version) {
  const parsed = parseSemver(version);
  if (parsed.prerelease.length === 0) return 'latest';
  const channel = parsed.prerelease[0];
  if (!['alpha', 'beta', 'rc'].includes(channel)) {
    throw new Error(`unsupported prerelease channel in ${version}; expected alpha, beta, or rc`);
  }
  return channel;
}

export function assertNotRollback(candidate, current, label = 'release channel') {
  if (!current || current === '<none>' || current === 'null') return;
  if (compareSemver(candidate, current) < 0) {
    throw new Error(`${label} is already ${current}; refusing to roll it back to ${candidate}`);
  }
}

async function main(argv) {
  const [command, ...args] = argv;
  if (command === 'channel' && args.length === 1) {
    console.log(releaseChannel(args[0]));
    return;
  }
  if (command === 'compare' && args.length === 2) {
    console.log(compareSemver(args[0], args[1]));
    return;
  }
  if (command === 'assert-not-rollback' && args.length >= 2 && args.length <= 3) {
    assertNotRollback(args[0], args[1], args[2]);
    console.log(`${args[2] ?? 'release channel'} may advance from ${args[1] || '<none>'} to ${args[0]}`);
    return;
  }
  throw new Error('usage: release-order.mjs channel <version> | compare <a> <b> | assert-not-rollback <candidate> <current-or-empty> [label]');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

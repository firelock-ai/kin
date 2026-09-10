#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Decides whether the Kin registry dependency wave may roll `kin-vfs-core`.
//
// Every other crate in that wave's roll list has one authority: the version the
// Kin registry publishes. `kin-vfs-core` has two, and they must agree, because
// a Kin release ships both halves. The registry requirement in `Cargo.toml` is
// what the Kin binary links against. The immutable kin-vfs checkout commit,
// recorded as a literal in `release.yml` and `rc-build.yml`, is the tree the
// release builds the kin-vfs binary from. `scripts/check-kin-vfs-compat.mjs`
// refuses when they disagree, and it is a required context on every pull
// request.
//
// The wave can write only `Cargo.toml`, `Cargo.lock` and `fuzz/Cargo.lock`
// (`ALLOWED_PATHS` in `scripts/verify-kin-registry-wave-head.py`, enforced by
// the generated snapshot, the admission validator and the landing judge), and
// its App token carries no `workflows` scope. So it can move the registry
// requirement and it can never move the pin. Left alone, it moved one of two
// coupled authorities on every kin-vfs-core publish and produced a pull request
// that could not pass its own required gate: eight wave heads across four
// version steps between 2026-08-31 and 2026-09-10, each ending in a hand-written
// pull request (kin#1223, kin#1344, kin#1431) that moved both together.
//
// The pin is not something a bot should move anyway. It is a reviewed release
// input, and a wave that advanced it would ship a kin-vfs tree nobody read. So
// this holds the coupled crate instead: `kin-vfs-core` joins the roll only when
// the registry's newest installable version is exactly the version the pinned
// checkout builds. The other crates roll either way, so the wave still lands,
// and the reviewed pull request that advances the pin is what releases the next
// kin-vfs-core roll.
//
// The pin is read through `check-kin-vfs-compat.mjs`'s own discovery rather
// than a second reader, so this and the gate it exists to satisfy cannot
// disagree about where the pin lives or what it says.

import fs from 'node:fs/promises';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import {
  VFS_CORE,
  VFS_REPOSITORY,
  fetchPinnedLock,
  lockPackages,
  readPinSources,
  readPinnedVfsCommit,
} from './check-kin-vfs-compat.mjs';

export { VFS_CORE, VFS_REPOSITORY };

// The receiver's `--registry-url`, whose default is the same value
// `.kin-actions/scripts/update-cargo-registry-deps.py` uses. The index path
// below is appended to it exactly as `kin_registry_index.fetch_index` does, so
// this reads the same rows the updater resolves from.
export const REGISTRY_URL = 'https://kinlab.ai';

const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

// Cargo's sparse-index layout, mirroring `kin_registry_index.sparse_index_path`
// so a crate whose name length crosses one of these boundaries is looked up at
// the path the registry actually serves it from.
export function sparseIndexPath(name) {
  const lower = name.toLowerCase();
  if (lower.length === 1) {
    return `1/${lower}`;
  }
  if (lower.length === 2) {
    return `2/${lower}`;
  }
  if (lower.length === 3) {
    return `3/${lower[0]}/${lower}`;
  }
  return `${lower.slice(0, 2)}/${lower.slice(2, 4)}/${lower}`;
}

// A SemVer precedence key, build metadata ignored, a release ordering above any
// prerelease of the same core. Comparable with `compareVersions` below.
export function parseVersion(version) {
  const match = SEMVER.exec(version);
  if (match === null) {
    throw new Error(`invalid SemVer: ${JSON.stringify(version)}`);
  }
  const prerelease = match[4];
  const identifiers =
    prerelease === undefined
      ? []
      : prerelease.split('.').map((identifier) =>
          /^\d+$/.test(identifier) ? [0, Number(identifier)] : [1, identifier],
        );
  return {
    core: [Number(match[1]), Number(match[2]), Number(match[3])],
    release: prerelease === undefined,
    identifiers,
  };
}

export function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  for (let index = 0; index < 3; index += 1) {
    if (a.core[index] !== b.core[index]) {
      return a.core[index] < b.core[index] ? -1 : 1;
    }
  }
  if (a.release !== b.release) {
    return a.release ? 1 : -1;
  }
  const length = Math.max(a.identifiers.length, b.identifiers.length);
  for (let index = 0; index < length; index += 1) {
    const left_ = a.identifiers[index];
    const right_ = b.identifiers[index];
    if (left_ === undefined) {
      return -1;
    }
    if (right_ === undefined) {
      return 1;
    }
    if (left_[0] !== right_[0]) {
      return left_[0] < right_[0] ? -1 : 1;
    }
    if (left_[1] !== right_[1]) {
      return left_[1] < right_[1] ? -1 : 1;
    }
  }
  return 0;
}

// Parses one sparse-index body. Strict on purpose, and for the same reason the
// compat gate is strict: a row this cannot read is a registry answer this
// cannot be trusted to have understood, and reading it loosely would let the
// wave roll to a version nobody validated. An empty successful body is an
// error rather than "no versions", because an unpublished crate returns 404.
export function parseIndex(text, { crate, source }) {
  const records = [];
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim() === '') {
      continue;
    }
    let row;
    try {
      row = JSON.parse(line);
    } catch (cause) {
      throw new Error(
        `malformed registry index row ${index + 1} at ${source}: invalid JSON (${cause.message})`,
        { cause },
      );
    }
    if (row === null || typeof row !== 'object' || Array.isArray(row)) {
      throw new Error(
        `malformed registry index row ${index + 1} at ${source}: expected an object`,
      );
    }
    if (typeof row.name !== 'string' || row.name !== crate) {
      throw new Error(
        `malformed registry index row ${index + 1} at ${source}: crate name ` +
        `${JSON.stringify(row.name)} does not match ${JSON.stringify(crate)}`,
      );
    }
    if (typeof row.vers !== 'string' || row.vers === '') {
      throw new Error(
        `malformed registry index row ${index + 1} at ${source}: missing string 'vers'`,
      );
    }
    parseVersion(row.vers);
    if (typeof row.yanked !== 'boolean') {
      throw new Error(
        `malformed registry index row ${index + 1} at ${source}: missing boolean 'yanked'`,
      );
    }
    records.push({ name: row.name, version: row.vers, yanked: row.yanked });
  }
  if (records.length === 0) {
    throw new Error(
      `malformed registry index at ${source}: empty successful response; an ` +
      'unpublished crate must return HTTP 404',
    );
  }
  return records;
}

// The newest version a consumer could install, so a yanked head does not read
// as the version the pin has to match. Null when every published version is
// yanked, which holds rather than rolling.
export function latestInstallable(records) {
  const installable = records.filter((record) => !record.yanked);
  if (installable.length === 0) {
    return null;
  }
  return installable
    .map((record) => record.version)
    .reduce((best, version) => (compareVersions(version, best) > 0 ? version : best));
}

// Fails closed on anything but a 404. An unreadable registry is not a licence
// to guess: the caller turns a throw into a failed step, never into a roll.
export async function fetchRegistryLatest(
  crate,
  { registryUrl = REGISTRY_URL, fetchImpl = fetch } = {},
) {
  const url = `${registryUrl.replace(/\/+$/, '')}/registry/cargo/${sparseIndexPath(crate)}`;
  let response;
  try {
    response = await fetchImpl(url, {
      headers: { accept: 'text/plain', 'user-agent': 'kin-wave-vfs-core-hold' },
    });
  } catch (cause) {
    throw new Error(`could not read registry index ${url}: ${cause.message}`, { cause });
  }
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(
      `could not read registry index ${url}: HTTP ${response.status} ${response.statusText}`,
    );
  }
  return latestInstallable(parseIndex(await response.text(), { crate, source: url }));
}

// The version the pinned kin-vfs checkout builds: its own local package, the
// one lock entry with no source. Mirrors `compareVfsCore`'s pinned side,
// including its refusal when the count is not exactly one, so the two cannot
// read one lock differently.
export function pinnedCoreVersion(pinnedLock) {
  const pinned = lockPackages(pinnedLock).filter(
    (pkg) => pkg.name === VFS_CORE && pkg.source === null,
  );
  if (pinned.length !== 1) {
    throw new Error(
      `expected one pinned local ${VFS_CORE} in the ${VFS_REPOSITORY} lock; found ${pinned.length}`,
    );
  }
  return pinned[0].version;
}

// The whole rule, pure and separately testable. Roll only on exact agreement.
// "Newer than the pin" is the drift this exists to stop. "Older than the pin"
// is a pin a person moved ahead of a publish, and rolling to something the
// registry happens to have would move the requirement to a third value, so it
// holds too and reports what it saw.
export function decide({ registryLatest, pinnedVersion, pinnedCommit }) {
  if (registryLatest === null) {
    return {
      roll: false,
      reason:
        `the Kin registry publishes no installable ${VFS_CORE}, so there is nothing ` +
        `to roll to; the pinned ${VFS_REPOSITORY} checkout ${pinnedCommit} builds ${pinnedVersion}`,
    };
  }
  if (registryLatest === pinnedVersion) {
    return {
      roll: true,
      reason:
        `the Kin registry's newest installable ${VFS_CORE} is ${registryLatest}, which is ` +
        `what the pinned ${VFS_REPOSITORY} checkout ${pinnedCommit} builds`,
    };
  }
  return {
    roll: false,
    reason:
      `holding ${VFS_CORE} at the pin: the Kin registry's newest installable version is ` +
      `${registryLatest}, but the pinned ${VFS_REPOSITORY} checkout ${pinnedCommit} builds ` +
      `${pinnedVersion}. Rolling would make the requirement disagree with the immutable ` +
      'release input, which is a required gate. Advance the pin in ' +
      '.github/workflows/release.yml and .github/workflows/rc-build.yml to a kin-vfs ' +
      `commit that builds ${registryLatest}, and the next wave rolls it.`,
  };
}

// GitHub reads GITHUB_OUTPUT one key per line, so a value carrying a newline
// would silently become a second key. Reasons are composed on one line above;
// this collapses any control character rather than trusting that.
function outputLine(key, value) {
  return `${key}=${String(value).replace(/[\r\n\t]+/g, ' ').trim()}\n`;
}

export async function main({
  root = process.cwd(),
  env = process.env,
  fetchImpl = fetch,
  log = console.log,
  writeOutput = null,
} = {}) {
  const sources = await readPinSources(root);
  const pinnedCommit = readPinnedVfsCommit(sources);
  const pinnedLock = await fetchPinnedLock(pinnedCommit, {
    token: env.GH_TOKEN || env.GITHUB_TOKEN,
    fetchImpl,
  });
  const pinnedVersion = pinnedCoreVersion(pinnedLock);
  const registryLatest = await fetchRegistryLatest(VFS_CORE, {
    registryUrl: env.KIN_REGISTRY_URL || REGISTRY_URL,
    fetchImpl,
  });
  const verdict = decide({ registryLatest, pinnedVersion, pinnedCommit });

  const emit =
    writeOutput ??
    (env.GITHUB_OUTPUT
      ? async (text) => fs.appendFile(env.GITHUB_OUTPUT, text, 'utf8')
      : async () => {});
  await emit(
    outputLine('kin_vfs_core_roll', verdict.roll ? 'true' : 'false') +
      outputLine('kin_vfs_core_reason', verdict.reason) +
      outputLine('kin_vfs_core_pinned', pinnedVersion) +
      outputLine('kin_vfs_core_registry', registryLatest ?? ''),
  );
  log(
    `${verdict.roll ? 'ROLL' : 'HOLD'} ${VFS_CORE}: ${verdict.reason}`,
  );
  return verdict;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  // Resolved from the working directory, exactly as check-kin-vfs-compat.mjs
  // resolves it, so both read the same tree when the workflow runs them from
  // GITHUB_WORKSPACE.
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exit(1);
  });
}

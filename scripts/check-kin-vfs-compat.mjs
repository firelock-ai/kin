#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Pull-request counterpart to release.yml's Kin/kin-vfs compatibility check.
//
// release.yml compares the kin-vfs-core that Kin resolves from the registry
// against the kin-vfs-core that the pinned kin-vfs checkout builds, and refuses
// the release on a mismatch. That comparison ran nowhere else. ci.yml carried no
// kin-vfs reference at all, so a pull request that moved Kin's kin-vfs-core
// requirement satisfied every required context and failed only after the tag
// existed, where the tag's own workflows are already resolved and no fix lands
// without cutting another tag.
//
// The pinned commit is read out of release.yml rather than recorded again here.
// The pin already has five homes in that file; a sixth living in the gate that
// predicts the release would be the one most likely to drift, and a gate
// checking a different commit than the release uses is worse than no gate.

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

export const VFS_REPOSITORY = 'firelock-ai/kin-vfs';
export const VFS_CORE = 'kin-vfs-core';

const COMMIT_SHA = /^[0-9a-f]{40}$/;

// Every site in release.yml that records the pin: the checkout steps that
// materialize it, and the expected-commit values that provenance and the
// install proof assert against. Requiring them to agree is stronger than
// reading any one of them, because a half-updated pin (checkout moved, proof
// left behind) is exactly the shape that reaches a tag before anyone notices.
export function readPinnedVfsCommit(releaseYaml) {
  const sites = new Map();
  const record = (sha, site) => {
    if (!COMMIT_SHA.test(sha)) {
      throw new Error(
        `${site} records "${sha}", which is not a 40-character commit sha; ` +
        'release inputs must be immutable',
      );
    }
    sites.set(sha, [...(sites.get(sha) ?? []), site]);
  };

  for (const step of releaseYaml.split(/^\s*-\s+name:/m).slice(1)) {
    if (!step.includes(`repository: ${VFS_REPOSITORY}`)) {
      continue;
    }
    const ref = step.match(/^\s*ref:\s*(\S+)/m);
    if (!ref) {
      throw new Error(
        `a ${VFS_REPOSITORY} checkout in release.yml records no ref, so the ` +
        'release input floats with that repository default branch',
      );
    }
    record(ref[1], `${VFS_REPOSITORY} checkout ref`);
  }

  for (const match of releaseYaml.matchAll(
    /^\s*(?:EXPECTED_VFS_COMMIT|expected_vfs_commit):\s*(\S+)/gm,
  )) {
    record(match[1], 'expected_vfs_commit');
  }

  if (sites.size === 0) {
    throw new Error(
      `release.yml records no ${VFS_REPOSITORY} pin, so this gate has nothing ` +
      'to compare against and cannot be trusted to have checked anything',
    );
  }
  if (sites.size > 1) {
    const detail = [...sites.entries()]
      .map(([sha, where]) => `${sha} (${[...new Set(where)].sort().join(', ')})`)
      .sort()
      .join(' and ');
    throw new Error(
      `release.yml records disagreeing ${VFS_REPOSITORY} pins: ${detail}; ` +
      'the release would build one commit and prove another',
    );
  }
  return [...sites.keys()][0];
}

// Mirrors release.yml's own lock reader. Kept deliberately identical so the two
// cannot disagree about what a lock entry is while agreeing about the versions.
export function lockPackages(text) {
  return text
    .split('[[package]]')
    .slice(1)
    .map((block) => ({
      name: block.match(/^name = "([^"]+)"/m)?.[1],
      version: block.match(/^version = "([^"]+)"/m)?.[1],
      source: block.match(/^source = "([^"]+)"/m)?.[1] ?? null,
    }));
}

export function compareVfsCore(kinLock, pinnedLock) {
  const resolved = lockPackages(kinLock).filter(
    (pkg) => pkg.name === VFS_CORE && pkg.source?.startsWith('sparse+'),
  );
  const pinned = lockPackages(pinnedLock).filter(
    (pkg) => pkg.name === VFS_CORE && pkg.source === null,
  );
  if (resolved.length !== 1 || pinned.length !== 1) {
    throw new Error(
      `expected one registry Kin ${VFS_CORE} and one pinned local ${VFS_CORE}; ` +
      `found ${resolved.length} and ${pinned.length}`,
    );
  }
  if (resolved[0].version !== pinned[0].version) {
    throw new Error(
      `Kin resolves ${VFS_CORE} ${resolved[0].version}, but the pinned kin-vfs ` +
      `checkout builds ${pinned[0].version}; advance the immutable kin-vfs pin ` +
      'in .github/workflows/release.yml, or hold this lock change until kin-vfs ' +
      'ships a matching commit. Landing them apart reds the release after the ' +
      'tag exists.',
    );
  }
  return resolved[0].version;
}

// Fails closed. An unreadable pin is not a passing comparison, so a transport
// failure raises here rather than returning something the caller could mistake
// for agreement.
export async function fetchPinnedLock(commit, { token, fetchImpl = fetch } = {}) {
  const url =
    `https://api.github.com/repos/${VFS_REPOSITORY}/contents/Cargo.lock?ref=${commit}`;
  const headers = {
    accept: 'application/vnd.github.raw',
    'user-agent': 'kin-vfs-compat-gate',
    'x-github-api-version': '2022-11-28',
  };
  if (token) {
    headers.authorization = `Bearer ${token}`;
  }

  let response;
  try {
    response = await fetchImpl(url, { headers });
  } catch (cause) {
    throw new Error(
      `could not reach ${VFS_REPOSITORY} to read Cargo.lock at ${commit}: ${cause.message}`,
      { cause },
    );
  }
  if (!response.ok) {
    throw new Error(
      `could not read ${VFS_REPOSITORY} Cargo.lock at ${commit}: ` +
      `HTTP ${response.status} ${response.statusText}`,
    );
  }
  const text = await response.text();
  if (!text.includes('[[package]]')) {
    throw new Error(
      `${VFS_REPOSITORY} Cargo.lock at ${commit} carried no lock packages; ` +
      'refusing to read an empty answer as agreement',
    );
  }
  return text;
}

export async function main({
  root = process.cwd(),
  env = process.env,
  fetchImpl = fetch,
  log = console.log,
} = {}) {
  const releaseYaml = await fs.readFile(
    path.join(root, '.github', 'workflows', 'release.yml'),
    'utf8',
  );
  const commit = readPinnedVfsCommit(releaseYaml);
  const kinLock = await fs.readFile(path.join(root, 'Cargo.lock'), 'utf8');
  const pinnedLock = await fetchPinnedLock(commit, {
    token: env.GH_TOKEN || env.GITHUB_TOKEN,
    fetchImpl,
  });
  const version = compareVfsCore(kinLock, pinnedLock);
  log(`Verified Kin/kin-vfs compatibility at ${VFS_CORE} ${version} (pinned kin-vfs ${commit})`);
  return version;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exit(1);
  });
}

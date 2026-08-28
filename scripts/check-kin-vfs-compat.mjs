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
// The pinned commit is read out of the workflows rather than recorded again
// here. A copy living in the gate that predicts the release would be the one
// most likely to drift, and a gate checking a different commit than the release
// uses is worse than no gate.
//
// The homes are DISCOVERED rather than listed, because listing them is what went
// wrong. This gate used to read release.yml alone and its comment said the pin
// had five homes; a sweep during FIR-2881 found eight. The three it never read
// were rc-build.yml's own checkout ref and EXPECTED_VFS_COMMIT, which build the
// candidate archive the release proof loop grades before the cut, and the exact
// expected_vfs_commit line scripts/test-release-workflow-authority.py asserts.
// A pin move that skipped rc-build.yml would grade one kin-vfs and ship another.
// Discovery means a ninth home is read the day it appears rather than the day it
// breaks a tag.

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
// Files that may record the pin. Every workflow, plus the release-authority
// script whose assertion carries the expected commit as a literal. The gate's
// own source and test are excluded on purpose: a guard that scans the file it
// lives in matches its own patterns and passes on a tree where nothing else
// does.
export const PIN_SOURCE_DIRECTORIES = ['.github/workflows', 'scripts'];
export const PIN_SOURCE_EXCLUSIONS = new Set([
  'scripts/check-kin-vfs-compat.mjs',
  'scripts/check-kin-vfs-compat.test.mjs',
]);

// A bare 40-hex value. `expected_vfs_commit` legitimately appears with no value
// at all (an input declaration), as an empty string (a caller opting out), as a
// shell variable, as `process.env` plumbing and inside a regex literal, all of
// which were read out of the tree before this rule was written. Only a literal
// sha is a pin site; the rest are not sites and are not errors. A checkout ref
// is held to a stricter rule below, because a kin-vfs checkout that floats is
// the failure this gate exists for.
export function collectVfsPinSites(text, file) {
  const found = [];

  for (const step of text.split(/^\s*-\s+name:/m).slice(1)) {
    if (!step.includes(`repository: ${VFS_REPOSITORY}`)) {
      continue;
    }
    const ref = step.match(/^\s*ref:\s*(\S+)/m);
    if (!ref) {
      throw new Error(
        `a ${VFS_REPOSITORY} checkout in ${file} records no ref, so the ` +
        'release input floats with that repository default branch',
      );
    }
    if (!COMMIT_SHA.test(ref[1])) {
      throw new Error(
        `${file} records a ${VFS_REPOSITORY} checkout ref "${ref[1]}", which is ` +
        'not a 40-character commit sha; release inputs must be immutable',
      );
    }
    found.push({ sha: ref[1], site: `${file} ${VFS_REPOSITORY} checkout ref` });
  }

  for (const match of text.matchAll(
    /(?:EXPECTED_VFS_COMMIT|expected_vfs_commit):\s*"?([0-9a-f]{40})"?/g,
  )) {
    found.push({ sha: match[1], site: `${file} expected_vfs_commit` });
  }

  return found;
}

// Every site that records the pin, across every file that records one, required
// to agree. A half-updated pin (release.yml moved, the candidate archive left
// behind) is exactly the shape that reaches a tag before anyone notices, and it
// is the shape this returns an error for rather than a commit.
export function readPinnedVfsCommit(sources) {
  const sites = new Map();
  for (const { path: file, text } of sources) {
    for (const { sha, site } of collectVfsPinSites(text, file)) {
      sites.set(sha, [...(sites.get(sha) ?? []), site]);
    }
  }

  if (sites.size === 0) {
    throw new Error(
      `no ${VFS_REPOSITORY} pin was found in any of ${sources.length} scanned ` +
      'file(s), so this gate has nothing to compare against and cannot be ' +
      'trusted to have checked anything',
    );
  }
  if (sites.size > 1) {
    const detail = [...sites.entries()]
      .map(([sha, where]) => `${sha} (${[...new Set(where)].sort().join(', ')})`)
      .sort()
      .join(' and ');
    throw new Error(
      `disagreeing ${VFS_REPOSITORY} pins: ${detail}; the release would build ` +
      'one commit and prove another',
    );
  }
  return [...sites.keys()][0];
}

// Read every candidate file off disk. Missing directories are not an error, so
// the gate still runs in a checkout that carries one and not the other, but a
// scan that found no file at all is, because zero files scanned and zero
// disagreements look identical from the outside.
export async function readPinSources(root, { fsImpl = fs } = {}) {
  const sources = [];
  for (const dir of PIN_SOURCE_DIRECTORIES) {
    let entries;
    try {
      entries = await fsImpl.readdir(path.join(root, dir));
    } catch {
      continue;
    }
    for (const entry of entries.sort()) {
      const rel = `${dir}/${entry}`;
      if (PIN_SOURCE_EXCLUSIONS.has(rel)) {
        continue;
      }
      if (!/\.(ya?ml|py)$/.test(entry)) {
        continue;
      }
      const text = await fsImpl.readFile(path.join(root, dir, entry), 'utf8');
      if (!text.includes(VFS_REPOSITORY) && !/expected_vfs_commit/i.test(text)) {
        continue;
      }
      sources.push({ path: rel, text });
    }
  }
  if (sources.length === 0) {
    throw new Error(
      'no file mentioning the kin-vfs pin was found; refusing to read an empty ' +
      'scan as agreement',
    );
  }
  return sources;
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
  const sources = await readPinSources(root);
  const commit = readPinnedVfsCommit(sources);
  const kinLock = await fs.readFile(path.join(root, 'Cargo.lock'), 'utf8');
  const pinnedLock = await fetchPinnedLock(commit, {
    token: env.GH_TOKEN || env.GITHUB_TOKEN,
    fetchImpl,
  });
  const version = compareVfsCore(kinLock, pinnedLock);
  // Name how many homes agreed and which files hold them, so a scan that
  // silently narrowed reads differently from one that checked them all. The
  // count is of SITES that recorded a sha, not of files opened: several files
  // mention the pin without recording one, and counting those would report
  // coverage this gate does not have.
  const sites = sources.flatMap(({ path: file, text }) => collectVfsPinSites(text, file));
  const files = [...new Set(sites.map(({ site }) => site.split(' ')[0]))].sort();
  log(
    `Verified Kin/kin-vfs compatibility at ${VFS_CORE} ${version} ` +
    `(pinned kin-vfs ${commit}, agreed across ${sites.length} site(s) in ` +
    `${files.length} file(s): ${files.join(', ')})`,
  );
  return version;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exit(1);
  });
}

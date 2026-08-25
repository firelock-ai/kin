#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import fs from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);

export function readManifestVersion(text) {
  let section = '';
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line.startsWith('[') && line.endsWith(']')) {
      section = line;
      continue;
    }
    const match = line.match(/^version\s*=\s*"([^"]+)"/);
    if (match && (section === '[package]' || section === '[workspace.package]')) {
      return match[1];
    }
  }
  throw new Error('could not read [workspace.package]/[package] version');
}

export function parseVersion(version) {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) {
    throw new Error(`stable release version must be numeric SemVer, got ${version}`);
  }
  return match.slice(1).map(Number);
}

export function classifyPath(path) {
  const normalized = path.replaceAll('\\', '/').replace(/^\.\/+/, '');
  const lower = normalized.toLowerCase();
  const segments = lower.split('/');
  const basename = segments.at(-1) ?? '';

  if (
    lower.startsWith('.github/') ||
    lower.startsWith('docs/') ||
    lower === 'agents.md' ||
    lower === 'claude.md' ||
    lower === 'license' ||
    /\.(md|mdx|markdown|rst|adoc|txt)$/.test(lower)
  ) {
    return 'non-release';
  }

  if (
    segments.some((segment) =>
      ['test', 'tests', 'benches', 'bench', 'examples', 'example', 'fuzz', 'fixtures', 'snapshots']
        .includes(segment)) ||
    /(^test[-_].*|.*[-_.]test\.[^.]+|.*_test\.[^.]+)$/.test(basename)
  ) {
    return 'non-release';
  }

  return 'release';
}

export function requestedBump(labels) {
  const normalized = labels
    .split(/[,\s]+/)
    .map((label) => label.trim().toLowerCase())
    .filter(Boolean);
  const major = normalized.includes('release:major') || normalized.includes('release/major');
  const minor = normalized.includes('release:minor') || normalized.includes('release/minor');
  if (major && minor) {
    throw new Error('release:major and release:minor cannot both be set');
  }
  return major ? 'major' : minor ? 'minor' : 'patch';
}

export function expectedVersion(baseVersion, bump) {
  const [major, minor, patch] = parseVersion(baseVersion);
  if (bump === 'major') return `${major + 1}.0.0`;
  if (bump === 'minor') return `${major}.${minor + 1}.0`;
  return `${major}.${minor}.${patch + 1}`;
}

export function evaluateVersionChange({
  baseVersion,
  headVersion,
  changedPaths,
  labels = '',
}) {
  const releasePaths = changedPaths.filter((path) => classifyPath(path) === 'release');
  const versionMoved = baseVersion !== headVersion;
  const bump = requestedBump(labels);
  const expected = expectedVersion(baseVersion, bump);
  const failures = [];

  if (releasePaths.length > 0 && !versionMoved) {
    failures.push(
      `${releasePaths.length} release-affecting path(s) changed, but the workspace version stayed at ${headVersion}`,
    );
  }
  if (versionMoved && headVersion !== expected) {
    failures.push(
      `${bump} release intent requires ${expected}, but the workspace moved from ${baseVersion} to ${headVersion}`,
    );
  }

  return {
    bump,
    expected,
    failures,
    releasePaths,
    versionMoved,
  };
}

function parseArgs(argv) {
  const args = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key.startsWith('--')) throw new Error(`invalid argument: ${key}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) {
      args.set(key.slice(2), 'true');
    } else {
      args.set(key.slice(2), value);
      index += 1;
    }
  }
  return {
    base: args.get('base') ?? process.env.BASE_SHA ?? '',
    labels: args.get('labels') ?? process.env.PR_LABELS ?? '',
    json: args.get('json') === 'true',
  };
}

async function git(args) {
  const { stdout } = await run('git', args, { maxBuffer: 16 * 1024 * 1024 });
  return stdout;
}

async function resolveBase(explicitBase) {
  if (explicitBase) return explicitBase;
  try {
    return (await git(['rev-parse', 'HEAD^'])).trim();
  } catch {
    throw new Error('no comparison base is available; pass --base or BASE_SHA');
  }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const base = await resolveBase(opts.base);
  const baseManifest = await git(['show', `${base}:Cargo.toml`]);
  const headManifest = await fs.readFile('Cargo.toml', 'utf8');
  const changed = await git(['diff', '--name-only', '-z', `${base}...HEAD`]);
  const changedPaths = changed.split('\0').filter(Boolean);

  const baseVersion = readManifestVersion(baseManifest);
  const headVersion = readManifestVersion(headManifest);
  const result = evaluateVersionChange({
    baseVersion,
    headVersion,
    changedPaths,
    labels: opts.labels,
  });
  const report = {
    base,
    baseVersion,
    headVersion,
    changedPaths: changedPaths.length,
    ...result,
  };

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log('Kin release version gate');
    console.log(`  base              : ${base}`);
    console.log(`  workspace version : ${baseVersion} -> ${headVersion}`);
    console.log(`  requested bump    : ${result.bump} (expected ${result.expected})`);
    console.log(`  changed paths     : ${changedPaths.length}`);
    console.log(`  release paths     : ${result.releasePaths.length}`);
    for (const path of result.releasePaths.slice(0, 30)) console.log(`    - ${path}`);
    if (result.releasePaths.length > 30) {
      console.log(`    ... ${result.releasePaths.length - 30} more`);
    }
    for (const failure of result.failures) console.log(`  FAIL: ${failure}`);
  }

  if (result.failures.length > 0) process.exitCode = 1;
}

// Run only when this file IS the entry point, comparing REAL paths.
//
// The usual idiom compares `import.meta.url` against
// `pathToFileURL(process.argv[1])`. Node resolves symlinks for the first and
// not the second, so invoking this file through a symlinked directory makes
// the two disagree and the gate prints nothing and exits 0. Measured: the same
// invocation against the same commit produced 0 bytes through `/tmp` and the
// full report through `/private/tmp`. release-train.yml runs it from a copy in
// `$RUNNER_TEMP/release-policy`, which is not a symlink today and is the only
// reason the naive form has held.
//
// Unresolvable paths fall to running, not skipping. A gate that silently
// declines to judge is worse than one that fails; a test that runs `main()` by
// mistake fails loudly on the spot.
function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return false;
  const self = fileURLToPath(import.meta.url);
  if (entry === self) return true;
  try {
    return realpathSync(entry) === realpathSync(self);
  } catch {
    return true;
  }
}

if (isDirectRun()) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

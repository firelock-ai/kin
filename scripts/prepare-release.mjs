#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import fs from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { parseVersion, readManifestVersion } from './check-release-version.mjs';

const run = promisify(execFile);
const NPM_MANIFESTS = [
  'packages/kin-mcp/package.json',
  'packages/kin/package.json',
  'packages/boundary-contracts/package.json',
];

function nextVersion(version, bump) {
  const [major, minor, patch] = parseVersion(version);
  if (bump === 'major') return `${major + 1}.0.0`;
  if (bump === 'minor') return `${major}.${minor + 1}.0`;
  if (bump === 'patch') return `${major}.${minor}.${patch + 1}`;
  throw new Error(`bump must be patch, minor, or major; got ${bump}`);
}

function replaceWorkspaceVersion(manifest, from, to) {
  let section = '';
  let replacements = 0;
  const lines = manifest.split('\n').map((raw) => {
    const line = raw.trim();
    if (line.startsWith('[') && line.endsWith(']')) section = line;
    if (section === '[workspace.package]' && line === `version = "${from}"`) {
      replacements += 1;
      return raw.replace(`version = "${from}"`, `version = "${to}"`);
    }
    return raw;
  });
  if (replacements !== 1) {
    throw new Error(`expected one workspace version ${from}, replaced ${replacements}`);
  }
  return lines.join('\n');
}

function replaceSpinePin(manifest, from, to) {
  const pattern = new RegExp(
    `^(kin-spine\\s*=\\s*\\{[^\\n]*version\\s*=\\s*")${from.replaceAll('.', '\\.')}("[^\\n]*\\})$`,
    'm',
  );
  const matches = manifest.match(new RegExp(pattern.source, 'gm')) ?? [];
  if (matches.length !== 1) {
    throw new Error(`expected one kin-spine ${from} path-version pin, found ${matches.length}`);
  }
  return manifest.replace(pattern, `$1${to}$2`);
}

export function updateWorkspaceLock(lock, from, to) {
  const chunks = lock.split('[[package]]');
  if (from === to) {
    const targetEntries = chunks.filter((chunk, index) =>
      index > 0 &&
      !/^source\s*=/m.test(chunk) &&
      /^name = "kin-/m.test(chunk) &&
      new RegExp(`^version = "${to.replaceAll('.', '\\.')}"$`, 'm').test(chunk)
    ).length;
    if (targetEntries === 0) {
      throw new Error(`no local Kin workspace lock entries found at ${to}`);
    }
    return { lock, replacements: 0, targetEntries };
  }

  let replacements = 0;
  const updated = chunks.map((chunk, index) => {
    if (index === 0 || /^source\s*=/m.test(chunk)) return chunk;
    const name = chunk.match(/^name = "([^"]+)"/m)?.[1];
    const version = chunk.match(/^version = "([^"]+)"/m)?.[1];
    if (!name?.startsWith('kin-') || version !== from) return chunk;
    replacements += 1;
    return chunk.replace(
      new RegExp(`^version = "${from.replaceAll('.', '\\.')}"$`, 'm'),
      `version = "${to}"`,
    );
  });
  const targetEntries = chunks.filter((chunk, index) =>
    index > 0 &&
    !/^source\s*=/m.test(chunk) &&
    /^name = "kin-/m.test(chunk) &&
    new RegExp(`^version = "${to.replaceAll('.', '\\.')}"$`, 'm').test(chunk)
  ).length;
  if (replacements === 0 && targetEntries === 0) {
    throw new Error(`no local Kin workspace lock entries found at ${from} or ${to}`);
  }
  return {
    lock: updated.join('[[package]]'),
    replacements,
    targetEntries: targetEntries + replacements,
  };
}

function cleanSubject(subject) {
  return subject
    .replace(/\s+/g, ' ')
    .replace(/[.\s]+$/, '')
    .trim();
}

async function git(args) {
  const { stdout } = await run('git', args, { maxBuffer: 16 * 1024 * 1024 });
  return stdout.trim();
}

async function associatedPullRequest(sha) {
  const repository = process.env.GITHUB_REPOSITORY || 'firelock-ai/kin';
  try {
    const { stdout } = await run(
      'gh',
      [
        'api',
        '-H',
        'Accept: application/vnd.github+json',
        `repos/${repository}/commits/${sha}/pulls`,
        '--jq',
        'map(select(.merged_at != null)) | sort_by(.merged_at) | last | "\\(.title) (#\\(.number))"',
      ],
      { maxBuffer: 1024 * 1024 },
    );
    const value = stdout.trim();
    return value && value !== 'null' ? value : null;
  } catch {
    return null;
  }
}

export async function releaseNotes(baseTag, sourceRef) {
  const log = await git([
    'log',
    '--first-parent',
    '--reverse',
    '--format=%H%x09%s',
    `${baseTag}..${sourceRef}`,
  ]);
  if (!log) return [];

  const notes = [];
  for (const line of log.split('\n')) {
    const separator = line.indexOf('\t');
    const sha = line.slice(0, separator);
    let subject = await associatedPullRequest(sha);
    if (subject === null) subject = line.slice(separator + 1);
    const merge = subject.match(/^Merge pull request #(\d+) from /);
    if (merge) {
      const parents = (await git(['show', '-s', '--format=%P', sha])).split(/\s+/);
      if (parents.length > 1) {
        subject = `${await git(['show', '-s', '--format=%s', parents[1]])} (#${merge[1]})`;
      }
    }
    subject = cleanSubject(subject);
    if (
      subject &&
      !/^Release Kin v\d+\.\d+\.\d+/i.test(subject) &&
      !/^Bump version to \d+\.\d+\.\d+/i.test(subject)
    ) {
      notes.push(subject);
    }
  }
  return [...new Set(notes)];
}

export function upsertChangelogSection(changelog, version, date, notes) {
  if (notes.length === 0) {
    throw new Error('refusing to prepare an empty release changelog');
  }
  const heading = `## [${version}]`;
  const body = [`${heading} - ${date}`, '', '### Changed', ''];
  for (const note of notes) body.push(`- ${note}`);
  const section = `${body.join('\n')}\n`;

  const existingStart = changelog.indexOf(heading);
  if (existingStart !== -1) {
    const after = changelog.slice(existingStart + heading.length);
    const nextOffset = after.search(/\n## \[/);
    const existingEnd = nextOffset === -1
      ? changelog.length
      : existingStart + heading.length + nextOffset + 1;
    return `${changelog.slice(0, existingStart)}${section}\n${changelog.slice(existingEnd)}`;
  }

  const unreleased = '## [Unreleased]';
  const insertion = changelog.indexOf(unreleased);
  if (insertion === -1) throw new Error('CHANGELOG.md is missing ## [Unreleased]');
  const lineEnd = changelog.indexOf('\n', insertion);
  return `${changelog.slice(0, lineEnd + 1)}\n${section}\n${changelog.slice(lineEnd + 1)}`;
}

export function removeChangelogSection(changelog, version) {
  const heading = `## [${version}]`;
  const start = changelog.indexOf(heading);
  if (start === -1) return changelog;
  const after = changelog.slice(start + heading.length);
  const nextOffset = after.search(/\n## \[/);
  const end = nextOffset === -1
    ? changelog.length
    : start + heading.length + nextOffset + 1;
  return `${changelog.slice(0, start)}${changelog.slice(end)}`;
}

function parseArgs(argv) {
  const options = {
    baseTag: '',
    bump: 'patch',
    date: new Date().toISOString().slice(0, 10),
    sourceRef: 'origin/main',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key.startsWith('--') || value === undefined || value.startsWith('--')) {
      throw new Error(`expected --name value, got ${key}`);
    }
    const name = key
      .slice(2)
      .replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    if (!(name in options)) throw new Error(`unknown option: ${key}`);
    options[name] = value;
    index += 1;
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const cargoPath = 'Cargo.toml';
  const cargo = await fs.readFile(cargoPath, 'utf8');
  const sourceCargo = await git(['show', `${options.sourceRef}:Cargo.toml`]);
  const from = readManifestVersion(sourceCargo);
  const baseTag = options.baseTag || `v${from}`;
  if (baseTag !== `v${from}`) {
    throw new Error(`base tag ${baseTag} does not match workspace version ${from}`);
  }
  await git(['rev-parse', '--verify', `${baseTag}^{commit}`]);
  const target = nextVersion(from, options.bump);
  const notes = await releaseNotes(baseTag, options.sourceRef);

  const workingVersion = readManifestVersion(cargo);
  if (workingVersion !== from && workingVersion !== target) {
    parseVersion(workingVersion);
  }
  if (workingVersion !== target) {
    await fs.writeFile(
      cargoPath,
      replaceWorkspaceVersion(cargo, workingVersion, target),
    );
  }

  const cliManifestPath = 'crates/kin-cli/Cargo.toml';
  const cliManifest = await fs.readFile(cliManifestPath, 'utf8');
  if (cliManifest.includes(`kin-spine = { version = "${workingVersion}"`)) {
    if (workingVersion !== target) {
      await fs.writeFile(
        cliManifestPath,
        replaceSpinePin(cliManifest, workingVersion, target),
      );
    }
  } else if (!cliManifest.includes(`kin-spine = { version = "${target}"`)) {
    throw new Error(
      `${cliManifestPath} has neither the ${workingVersion} nor ${target} kin-spine pin`,
    );
  }

  for (const path of NPM_MANIFESTS) {
    const manifest = JSON.parse(await fs.readFile(path, 'utf8'));
    if (manifest.version === workingVersion && workingVersion !== target) {
      manifest.version = target;
      await fs.writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
    } else if (manifest.version !== target) {
      throw new Error(
        `${path} is ${manifest.version}, expected ${workingVersion} or ${target}`,
      );
    }
  }

  const lockPath = 'Cargo.lock';
  const lock = await fs.readFile(lockPath, 'utf8');
  const lockResult = updateWorkspaceLock(lock, workingVersion, target);
  await fs.writeFile(lockPath, lockResult.lock);

  // The fuzz targets live in their own workspace that resolves kin-parser by
  // path, so its lockfile names the workspace version too. Leaving it behind
  // makes the fuzz job's --locked resolution refuse the release commit.
  const fuzzLockPath = 'fuzz/Cargo.lock';
  const fuzzLock = await fs.readFile(fuzzLockPath, 'utf8');
  await fs.writeFile(
    fuzzLockPath,
    updateWorkspaceLock(fuzzLock, workingVersion, target).lock,
  );

  const changelogPath = 'CHANGELOG.md';
  let changelog = await fs.readFile(changelogPath, 'utf8');
  if (workingVersion !== from && workingVersion !== target) {
    changelog = removeChangelogSection(changelog, workingVersion);
  }
  await fs.writeFile(
    changelogPath,
    upsertChangelogSection(changelog, target, options.date, notes),
  );

  if (process.env.GITHUB_OUTPUT) {
    await fs.appendFile(
      process.env.GITHUB_OUTPUT,
      `base_tag=${baseTag}\nbase_version=${from}\nversion=${target}\ntag=v${target}\nnotes=${notes.length}\nlock_entries=${lockResult.targetEntries}\n`,
    );
  }
  console.log(
    `prepared Kin ${target} from ${baseTag}: ${notes.length} notes, `
      + `${lockResult.targetEntries} workspace lock entries`,
  );
}

// Run only when this file IS the entry point, comparing REAL paths.
//
// The usual idiom compares `import.meta.url` against
// `pathToFileURL(process.argv[1])`. Node resolves symlinks for the first and
// not the second, so invoking this file through a symlinked directory makes
// the two disagree and it generates nothing, writes no $GITHUB_OUTPUT, and
// exits 0. release-train.yml runs it from a copy in
// `$RUNNER_TEMP/release-policy`, which is exactly that shape and is not a
// symlink today, which is the only reason the naive form has held.
//
// Unresolvable paths fall to running, not skipping. A generator that silently
// declines to generate leaves the train reading an empty version; a test that
// runs `main()` by mistake fails loudly on the spot.
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

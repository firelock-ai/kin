// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  classifyPath,
  evaluateVersionChange,
  expectedVersion,
  readManifestVersion,
  requestedBump,
} from './check-release-version.mjs';

test('reads a workspace version', () => {
  assert.equal(
    readManifestVersion('[workspace.package]\nversion = "0.3.7"\n'),
    '0.3.7',
  );
});

test('classifies shipped inputs as release-affecting', () => {
  for (const path of [
    'Cargo.toml',
    'Cargo.lock',
    'crates/kin-cli/src/main.rs',
    'packages/kin/index.js',
    'scripts/install.sh',
    'Dockerfile',
    '.cargo/config.toml',
  ]) {
    assert.equal(classifyPath(path), 'release', path);
  }
});

test('classifies policy, docs, and test inputs as non-release', () => {
  for (const path of [
    '.github/workflows/ci.yml',
    'README.md',
    'docs/release-bot.md',
    'crates/kin-cli/tests/repository_tag.rs',
    'scripts/test-release-workflow-authority.py',
    'crates/kin-core/src/snapshots/fixture.json',
  ]) {
    assert.equal(classifyPath(path), 'non-release', path);
  }
});

test('release-affecting changes require the next patch by default', () => {
  const result = evaluateVersionChange({
    baseVersion: '0.3.6',
    headVersion: '0.3.6',
    changedPaths: ['crates/kin-cli/src/main.rs'],
  });
  assert.equal(result.expected, '0.3.7');
  assert.equal(result.failures.length, 1);
});

test('the exact next patch passes', () => {
  const result = evaluateVersionChange({
    baseVersion: '0.3.6',
    headVersion: '0.3.7',
    changedPaths: ['Cargo.toml', 'crates/kin-cli/src/main.rs'],
  });
  assert.deepEqual(result.failures, []);
});

test('docs-only work passes without a bump', () => {
  const result = evaluateVersionChange({
    baseVersion: '0.3.6',
    headVersion: '0.3.6',
    changedPaths: ['README.md', '.github/workflows/ci.yml'],
  });
  assert.deepEqual(result.failures, []);
});

test('minor and major intent are explicit', () => {
  assert.equal(requestedBump('release:minor'), 'minor');
  assert.equal(expectedVersion('0.3.6', 'minor'), '0.4.0');
  assert.equal(requestedBump('release/major'), 'major');
  assert.equal(expectedVersion('0.3.6', 'major'), '1.0.0');
});

test('skipped versions fail closed', () => {
  const result = evaluateVersionChange({
    baseVersion: '0.3.6',
    headVersion: '0.3.8',
    changedPaths: ['Cargo.toml'],
  });
  assert.equal(result.failures.length, 1);
});

// --------------------------------------------------------------------------
// The gate as a pull request runs it.
//
// Every test above exercises a pure function, and this gate's defect was never
// in one: the script has carried the right refusal since before the release
// train existed and simply never ran on a pull request. So the end-to-end path
// gets its own coverage, driven the way ci.yml drives it, through BASE_SHA and
// PR_LABELS rather than through argv.
// --------------------------------------------------------------------------

const GATE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'check-release-version.mjs');

// Fixture commits are throwaway history, so the developer host's commit
// hygiene hooks must not run against them.
function git(root, args) {
  const hooks = path.join(root, '.git', 'fixture-hooks-disabled');
  return execFileSync('git', ['-c', `core.hooksPath=${hooks}`, ...args], {
    cwd: root,
    encoding: 'utf8',
  });
}

function write(root, relative, body) {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, body);
}

function releaseBase(version = '1.2.3') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-version-gate-'));
  git(root, ['init', '--quiet', '--initial-branch=main']);
  git(root, ['config', 'user.name', 'Test']);
  git(root, ['config', 'user.email', 'test@example.invalid']);
  write(root, 'Cargo.toml', `[workspace.package]\nversion = "${version}"\n`);
  write(root, 'crates/kin-cli/src/main.rs', 'fn main() {}\n');
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', 'base']);
  return { root, base: git(root, ['rev-parse', 'HEAD']).trim() };
}

function runGate(root, base, labels) {
  try {
    const stdout = execFileSync(process.execPath, [GATE], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, BASE_SHA: base, PR_LABELS: labels },
    });
    return { code: 0, stdout };
  } catch (error) {
    return { code: error.status, stdout: `${error.stdout ?? ''}${error.stderr ?? ''}` };
  }
}

test('a release-affecting change with no bump is refused end to end', () => {
  const { root, base } = releaseBase();
  write(root, 'crates/kin-cli/src/main.rs', 'fn main() { println!("fix"); }\n');
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', 'fix whose bump was dropped']);

  const run = runGate(root, base, 'release:automated,release:patch');
  assert.equal(run.code, 1);
  assert.match(run.stdout, /1 release-affecting path\(s\) changed/);
  assert.match(run.stdout, /stayed at 1\.2\.3/);
});

test('the same change with its bump passes end to end', () => {
  // The half that matters. A gate that failed on everything would be no gate,
  // and this is the run the release pull request has to be able to make green.
  const { root, base } = releaseBase();
  write(root, 'crates/kin-cli/src/main.rs', 'fn main() { println!("fix"); }\n');
  write(root, 'Cargo.toml', '[workspace.package]\nversion = "1.2.4"\n');
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', 'Release Kin v1.2.4']);

  const run = runGate(root, base, 'release:automated,release:patch');
  assert.equal(run.code, 0);
  assert.match(run.stdout, /1\.2\.3 -> 1\.2\.4/);
});

test('a documentation-only release pull request needs no bump', () => {
  const { root, base } = releaseBase();
  write(root, 'docs/rail.md', 'notes\n');
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', 'document the rail']);

  const run = runGate(root, base, 'release:automated,release:patch');
  assert.equal(run.code, 0);
});

test('a bump that skips a version is refused end to end', () => {
  const { root, base } = releaseBase();
  write(root, 'Cargo.toml', '[workspace.package]\nversion = "1.2.9"\n');
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', 'Release Kin v1.2.9']);

  const run = runGate(root, base, 'release:automated,release:patch');
  assert.equal(run.code, 1);
  assert.match(run.stdout, /requires 1\.2\.4/);
});

test('the gate runs from a copy reached through a symlinked directory', () => {
  // release-train.yml runs this file from a copy in $RUNNER_TEMP/release-policy.
  // The entry-point test used to compare `import.meta.url` against
  // `pathToFileURL(process.argv[1])`, and Node resolves symlinks for the first
  // and not the second, so a copy invoked through one made the gate print
  // nothing and exit 0. Measured against the real release pull request that
  // took 0.5.52 to 0.5.53: 0 bytes through `/tmp`, the full report through
  // `/private/tmp`, same commit and same arguments.
  const { root, base } = releaseBase();
  write(root, 'crates/kin-cli/src/main.rs', 'fn main() { println!("fix"); }\n');
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', 'fix whose bump was dropped']);

  const real = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-version-policy-'));
  const link = `${real}-link`;
  fs.symlinkSync(real, link, 'dir');
  const policy = path.join(link, 'check-release-version.mjs');
  fs.copyFileSync(GATE, policy);

  let code = 0;
  let stdout = '';
  try {
    stdout = execFileSync(process.execPath, [policy], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, BASE_SHA: base, PR_LABELS: 'release:automated' },
    });
  } catch (error) {
    code = error.status;
    stdout = `${error.stdout ?? ''}${error.stderr ?? ''}`;
  }
  assert.notEqual(stdout, '', 'the gate produced no output, so it judged nothing');
  assert.equal(code, 1, 'the gate did not refuse a release-affecting diff with no bump');
});

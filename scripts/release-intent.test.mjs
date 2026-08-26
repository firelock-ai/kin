// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { classifyPath as intentClassifyPath, decideReleaseIntent } from './release-intent.mjs';
import { classifyPath as versionClassifyPath } from './check-release-version.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GATE = path.join(HERE, 'release-intent.mjs');

// --------------------------------------------------------------------------
// The verdict table.
// --------------------------------------------------------------------------

test('an existing tag with nothing after it is still an idempotent no-op', () => {
  const verdict = decideReleaseIntent({ tag: 'v1.2.3', tagExists: true });
  assert.equal(verdict.exitCode, 0);
  assert.equal(verdict.shouldTag, false);
  assert.equal(verdict.stranded, false);
});

test('an existing tag with release-affecting work after it refuses', () => {
  const verdict = decideReleaseIntent({
    tag: 'v1.2.3',
    tagExists: true,
    strandedPaths: ['crates/kin-cli/src/main.rs', 'Cargo.lock'],
    commitsSinceTag: 7,
  });
  assert.equal(verdict.exitCode, 1);
  assert.equal(verdict.shouldTag, false);
  assert.equal(verdict.stranded, true);
  assert.match(verdict.summary, /2 release-affecting path\(s\)/);
  assert.match(verdict.summary, /7 commit\(s\)/);
});

test('documentation after an existing tag is not a stranded release', () => {
  // The caller filters, so this is the shape it hands back for a docs-only
  // range. Asserted here because it is the row that decides whether the gate
  // is usable: a guard that refuses every quiet cycle gets switched off.
  const verdict = decideReleaseIntent({
    tag: 'v1.2.3',
    tagExists: true,
    strandedPaths: [],
    commitsSinceTag: 4,
  });
  assert.equal(verdict.exitCode, 0);
  assert.equal(verdict.stranded, false);
});

test('an absent tag with sound surfaces is ready to cut', () => {
  const verdict = decideReleaseIntent({ tag: 'v1.2.4', tagExists: false });
  assert.equal(verdict.exitCode, 0);
  assert.equal(verdict.shouldTag, true);
});

test('an absent tag with a broken surface refuses', () => {
  const verdict = decideReleaseIntent({
    tag: 'v1.2.4',
    tagExists: false,
    failures: ['npm manifest is 1.2.3, workspace is 1.2.4'],
  });
  assert.equal(verdict.exitCode, 1);
  assert.equal(verdict.shouldTag, false);
  assert.equal(verdict.stranded, false);
});

test('a stranded release outranks an out-of-sync surface in the report', () => {
  // Both are true at once whenever a bump is dropped mid-flight. The stranded
  // diagnosis is the one that names the cause; reporting the surface mismatch
  // instead would send the reader to regenerate files that are already right.
  const verdict = decideReleaseIntent({
    tag: 'v1.2.3',
    tagExists: true,
    failures: ['npm manifest is 1.2.2, workspace is 1.2.3'],
    strandedPaths: ['crates/kin-cli/src/main.rs'],
    commitsSinceTag: 1,
  });
  assert.equal(verdict.stranded, true);
  assert.equal(verdict.exitCode, 1);
});

// --------------------------------------------------------------------------
// The copied classifier, and the two things that keep the copy honest.
// --------------------------------------------------------------------------

// Every branch of the classifier, in both directions. A parity test over a
// corpus that only exercised one branch would agree by accident.
const CLASSIFIER_CORPUS = [
  'Cargo.toml',
  'Cargo.lock',
  'fuzz/Cargo.lock',
  'CHANGELOG.md',
  'crates/kin-cli/Cargo.toml',
  'crates/kin-cli/src/main.rs',
  'crates/kin-core/src/lib.rs',
  'crates/kin-core/tests/roundtrip.rs',
  'crates/kin-core/benches/parse.rs',
  'crates/kin-parser/examples/demo.rs',
  'crates/kin-core/src/snapshots/fixture.json',
  'packages/kin/index.js',
  'packages/kin/package.json',
  'scripts/install.sh',
  'scripts/test-release-workflow-authority.py',
  'scripts/check-release-version.test.mjs',
  'scripts/release_test.py',
  'Dockerfile',
  '.cargo/config.toml',
  '.github/workflows/ci.yml',
  'docs/release-bot.md',
  'README.md',
  'AGENTS.md',
  'CLAUDE.md',
  'LICENSE',
  'notes.txt',
  'design.adoc',
  './Cargo.toml',
  'crates\\kin-cli\\src\\main.rs',
];

test('the copied classifier agrees with the version gate on every branch', () => {
  for (const candidate of CLASSIFIER_CORPUS) {
    assert.equal(
      intentClassifyPath(candidate),
      versionClassifyPath(candidate),
      candidate,
    );
  }
  // The corpus has to be able to disagree. A corpus of one verdict would pass
  // against a classifier that returned that verdict for everything.
  const verdicts = new Set(CLASSIFIER_CORPUS.map(intentClassifyPath));
  assert.deepEqual([...verdicts].sort(), ['non-release', 'release']);
});

test('the gate imports nothing relative, so a single-file copy still runs', () => {
  // release-tag.yml copies this file ALONE into $RUNNER_TEMP under another
  // basename and runs it there. A relative import would resolve to a path that
  // does not exist and the mint would die on module resolution rather than
  // judge the release, which is why the classifier above is a copy.
  const source = fs.readFileSync(GATE, 'utf8');
  const specifiers = [...source.matchAll(/^import\s[^']*'([^']+)'/gm)].map((m) => m[1]);
  assert.ok(specifiers.length > 0, 'no import statements were found to check');
  const relative = specifiers.filter((s) => s.startsWith('.'));
  assert.deepEqual(relative, [], `release-intent.mjs must not import ${relative.join(', ')}`);
});

// --------------------------------------------------------------------------
// The gate as the mint actually invokes it.
// --------------------------------------------------------------------------

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

// A repository carrying every surface release-intent.mjs asserts, released at
// v1.2.3, so the only variable left is what landed after the tag.
function releasedRepository(version = '1.2.3') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-intent-gate-'));
  git(root, ['init', '--quiet', '--initial-branch=main']);
  git(root, ['config', 'user.name', 'Test']);
  git(root, ['config', 'user.email', 'test@example.invalid']);
  write(root, 'Cargo.toml', `[workspace.package]\nversion = "${version}"\n`);
  write(root, 'Cargo.lock', `[[package]]\nname = "kin-core"\nversion = "${version}"\n`);
  write(root, 'fuzz/Cargo.lock', `[[package]]\nname = "kin-parser"\nversion = "${version}"\n`);
  write(
    root,
    'crates/kin-cli/Cargo.toml',
    `[dependencies]\nkin-spine = { path = "../kin-spine", version = "${version}" }\n`,
  );
  write(root, 'CHANGELOG.md', `## [${version}]\n\n- released\n`);
  for (const pkg of ['kin-mcp', 'kin', 'boundary-contracts']) {
    write(root, `packages/${pkg}/package.json`, JSON.stringify({ version }, null, 2));
  }
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', `Release Kin v${version}`]);
  git(root, ['tag', `v${version}`]);
  return root;
}

// Run the gate the way release-tag.yml does: a copy of this file, under a
// different basename, out of a directory that is not the checkout.
function runGateAsMintDoes(root) {
  const policyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-intent-policy-'));
  const policy = path.join(policyDir, 'release-intent-policy.mjs');
  fs.copyFileSync(GATE, policy);
  const outputs = path.join(policyDir, 'intent.outputs');
  fs.writeFileSync(outputs, '');
  const result = execFileSync(process.execPath, [policy], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, GITHUB_OUTPUT: outputs },
    // A non-zero exit is the point of most of these runs, so read the code
    // rather than letting execFileSync throw it away as a stack trace.
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
  });
  return { stdout: result, outputs: fs.readFileSync(outputs, 'utf8'), code: 0 };
}

function runGateExpectingFailure(root) {
  try {
    runGateAsMintDoes(root);
  } catch (error) {
    return { stdout: `${error.stdout ?? ''}${error.stderr ?? ''}`, code: error.status };
  }
  return null;
}

test('a release-affecting commit stranded behind an existing tag refuses loudly', () => {
  const root = releasedRepository();
  write(root, 'crates/kin-cli/src/main.rs', 'fn main() {}\n');
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', 'ship a fix whose version bump was dropped']);

  const failed = runGateExpectingFailure(root);
  assert.ok(failed, 'the gate exited 0 on a release whose bump is missing');
  assert.equal(failed.code, 1);
  assert.match(failed.stdout, /::error::/);
  assert.match(failed.stdout, /1 release-affecting path\(s\)/);
  assert.match(failed.stdout, /should_tag=false/);
});

test('documentation stranded behind an existing tag stays a green no-op', () => {
  // The half that matters. A gate that refused this would refuse every quiet
  // cycle on the fifteen-minute cron and would be turned off within a day.
  const root = releasedRepository();
  write(root, 'docs/release-bot.md', 'notes\n');
  write(root, 'README.md', 'notes\n');
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', 'document the rail']);

  const run = runGateAsMintDoes(root);
  assert.match(run.stdout, /already exists/);
  assert.doesNotMatch(run.stdout, /::error::/);
  assert.match(run.outputs, /should_tag=false/);
});

test('a bumped workspace ahead of its tag is still ready to cut', () => {
  // The stranded check must not fire on the ordinary release path, where the
  // version has moved and its tag does not exist yet.
  const root = releasedRepository();
  for (const [file, body] of [
    ['Cargo.toml', '[workspace.package]\nversion = "1.2.4"\n'],
    ['Cargo.lock', '[[package]]\nname = "kin-core"\nversion = "1.2.4"\n'],
    ['fuzz/Cargo.lock', '[[package]]\nname = "kin-parser"\nversion = "1.2.4"\n'],
    [
      'crates/kin-cli/Cargo.toml',
      '[dependencies]\nkin-spine = { path = "../kin-spine", version = "1.2.4" }\n',
    ],
    ['CHANGELOG.md', '## [1.2.4]\n\n- next\n\n## [1.2.3]\n\n- released\n'],
  ]) {
    write(root, file, body);
  }
  for (const pkg of ['kin-mcp', 'kin', 'boundary-contracts']) {
    write(root, `packages/${pkg}/package.json`, JSON.stringify({ version: '1.2.4' }, null, 2));
  }
  git(root, ['add', '-A']);
  git(root, ['commit', '--quiet', '-m', 'Release Kin v1.2.4']);

  const run = runGateAsMintDoes(root);
  assert.match(run.outputs, /should_tag=true/);
  assert.match(run.outputs, /tag=v1\.2\.4/);
});

test('the gate runs from a copy reached through a symlinked directory', () => {
  // The entry-point test used to compare `import.meta.url` against
  // `pathToFileURL(process.argv[1])`. Node resolves symlinks for the first and
  // not the second, so a copy invoked through one made the two disagree and the
  // gate exited 0 having written no outputs at all. $RUNNER_TEMP is not a
  // symlink today, which is the only reason that shape was survivable.
  const root = releasedRepository();
  const real = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-intent-real-'));
  const link = `${real}-link`;
  fs.symlinkSync(real, link, 'dir');
  const policy = path.join(link, 'release-intent-policy.mjs');
  fs.copyFileSync(GATE, policy);
  const outputs = path.join(real, 'intent.outputs');
  fs.writeFileSync(outputs, '');

  execFileSync(process.execPath, [policy], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, GITHUB_OUTPUT: outputs },
  });
  assert.match(
    fs.readFileSync(outputs, 'utf8'),
    /should_tag=/,
    'the gate wrote no outputs, so the mint would read an empty tag',
  );
});

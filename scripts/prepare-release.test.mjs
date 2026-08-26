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
  removeChangelogSection,
  updateWorkspaceLock,
  upsertChangelogSection,
} from './prepare-release.mjs';

test('updates only local Kin workspace packages in Cargo.lock', () => {
  const source = `version = 4

[[package]]
name = "kin-cli"
version = "0.3.6"

[[package]]
name = "async-stream"
version = "0.3.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "keep"

[[package]]
name = "local-helper"
version = "0.3.6"
`;
  const result = updateWorkspaceLock(source, '0.3.6', '0.4.0');
  assert.equal(result.replacements, 1);
  assert.match(result.lock, /name = "kin-cli"\nversion = "0.4.0"/);
  assert.match(result.lock, /name = "async-stream"\nversion = "0.3.6"/);
  assert.match(result.lock, /name = "local-helper"\nversion = "0.3.6"/);
  assert.match(result.lock, /checksum = "keep"/);
});

test('validates an already prepared workspace lock without double counting', () => {
  const source = `version = 4

[[package]]
name = "kin-cli"
version = "0.4.0"

[[package]]
name = "kin-core"
version = "0.4.0"
`;
  const result = updateWorkspaceLock(source, '0.4.0', '0.4.0');
  assert.equal(result.replacements, 0);
  assert.equal(result.targetEntries, 2);
  assert.equal(result.lock, source);
});

test('inserts a nonempty release section after Unreleased', () => {
  const changelog = '# Changelog\n\n## [Unreleased]\n\n## [0.3.6] - 2026-07-26\n\n- old\n';
  const updated = upsertChangelogSection(
    changelog,
    '0.4.0',
    '2026-07-28',
    ['Add repository authority (#475)'],
  );
  assert.match(
    updated,
    /## \[Unreleased\]\n\n## \[0\.4\.0\] - 2026-07-28\n\n### Changed\n\n- Add repository authority \(#475\)/,
  );
  assert.match(updated, /## \[0\.3\.6\] - 2026-07-26/);
});

test('replaces an existing generated section when the train coalesces', () => {
  const changelog = [
    '# Changelog',
    '',
    '## [Unreleased]',
    '',
    '## [0.4.0] - 2026-07-28',
    '',
    '### Changed',
    '',
    '- old note',
    '',
    '## [0.3.6] - 2026-07-26',
    '',
    '- prior',
    '',
  ].join('\n');
  const updated = upsertChangelogSection(
    changelog,
    '0.4.0',
    '2026-07-29',
    ['new note', 'another note'],
  );
  assert.doesNotMatch(updated, /old note/);
  assert.match(updated, /## \[0\.4\.0\] - 2026-07-29/);
  assert.match(updated, /- another note/);
  assert.equal((updated.match(/## \[0\.4\.0\]/g) ?? []).length, 1);
});

test('removes a superseded generated section when bump intent escalates', () => {
  const changelog = [
    '# Changelog',
    '',
    '## [Unreleased]',
    '',
    '## [0.3.7] - 2026-07-28',
    '',
    '### Changed',
    '',
    '- stale patch train',
    '',
    '## [0.3.6] - 2026-07-26',
    '',
    '- prior',
    '',
  ].join('\n');
  const updated = removeChangelogSection(changelog, '0.3.7');
  assert.doesNotMatch(updated, /0\.3\.7|stale patch train/);
  assert.match(updated, /## \[0\.3\.6\] - 2026-07-26/);
});

test('the fuzz lockfile moves with the workspace version', () => {
  const source = `version = 4

[[package]]
name = "kin-parser"
version = "0.3.6"

[[package]]
name = "kin-parser-fuzz"
version = "0.0.0"

[[package]]
name = "kin-model"
version = "0.7.1"
source = "sparse+https://example.invalid/"
checksum = "keep"
`;
  const result = updateWorkspaceLock(source, '0.3.6', '0.4.0');
  assert.equal(result.replacements, 1);
  assert.match(result.lock, /name = "kin-parser"\nversion = "0.4.0"/);
  // A fuzz target pinned at 0.0.0 and a registry dependency are untouched.
  assert.match(result.lock, /name = "kin-parser-fuzz"\nversion = "0.0.0"/);
  assert.match(result.lock, /name = "kin-model"\nversion = "0.7.1"/);
});

test('the generator runs from a copy reached through a symlinked directory', () => {
  // release-train.yml runs this file from a copy in $RUNNER_TEMP/release-policy.
  // The entry-point test used to compare `import.meta.url` against
  // `pathToFileURL(process.argv[1])`, and Node resolves symlinks for the first
  // and not the second, so a copy invoked through one generated nothing, wrote
  // no $GITHUB_OUTPUT, and exited 0. The train would then read an empty version.
  //
  // Run with no arguments and no repository, so `main()` is reached and fails on
  // its own missing input. The distinction being drawn is between a process that
  // ran and one that never started, and only the second is silent.
  const generator = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    'prepare-release.mjs',
  );
  const real = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-prepare-policy-'));
  const link = `${real}-link`;
  fs.symlinkSync(real, link, 'dir');
  const policy = path.join(link, 'prepare-release.mjs');
  fs.copyFileSync(generator, policy);
  // The sibling this file imports has to come too, exactly as release-train.yml
  // copies all three policy scripts into one directory. Without it node fails on
  // module resolution and writes to stderr, and this test would then pass on
  // that error no matter what the entry point did.
  fs.copyFileSync(
    path.join(path.dirname(generator), 'check-release-version.mjs'),
    path.join(link, 'check-release-version.mjs'),
  );
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-prepare-cwd-'));

  let output = '';
  try {
    output = execFileSync(process.execPath, [policy], {
      cwd: empty,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    output = `${error.stdout ?? ''}${error.stderr ?? ''}`;
  }
  assert.notEqual(output, '', 'the generator produced no output, so it never ran');
});

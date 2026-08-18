// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  applyBump,
  bumpCommand,
  caretCompatible,
  chooseTarget,
  parseDenyDiagnostics,
  parseDenySummary,
  parseIndexEntries,
  parsePatchedVersions,
  parseRequirement,
  planBumps,
  renderIssueBody,
  renderMergeGroupAnnotations,
  renderPullRequestBody,
  satisfies,
} from './advisory-sweep.mjs';

// Real `cargo deny --format json check advisories` output, trimmed to the
// fields the planner reads, captured on 2026-08-18 against main at 320cf57a
// with h2 held at 0.4.15. The trailing records are the two warnings and the
// summary the same run emits, and none of them describes a defect: a planner
// that read them would open a pull request for an advisory deny.toml already
// ignores with a reason.
const DENY_JSON = [
  JSON.stringify({
    type: 'diagnostic',
    fields: {
      code: 'vulnerability',
      advisory: {
        id: 'RUSTSEC-2026-0258',
        package: 'h2',
        title: 'h2 unbounded empty DATA frames',
        url: 'https://github.com/hyperium/hyper/security/advisories/GHSA-q83h-524g-xf6h',
      },
      graphs: [{ Krate: { name: 'h2', version: '0.4.15' } }],
    },
  }),
  JSON.stringify({
    type: 'diagnostic',
    fields: {
      code: 'advisory-not-detected',
      graphs: [],
      labels: [{ span: 'RUSTSEC-2024-0384', message: 'no crate matched advisory criteria' }],
      severity: 'warning',
    },
  }),
  JSON.stringify({
    type: 'diagnostic',
    fields: {
      code: 'unmaintained',
      advisory: { id: 'RUSTSEC-2024-0436', package: 'paste', title: 'paste unmaintained' },
      graphs: [{ Krate: { name: 'paste', version: '1.0.15' } }],
    },
  }),
  JSON.stringify({ type: 'summary', fields: { advisories: { errors: 1, warnings: 2 } } }),
].join('\n');

// The real advisory file cargo-deny fetched, front matter verbatim.
const ADVISORY_MD = `\`\`\`toml
[advisory]
id = "RUSTSEC-2026-0258"
package = "h2"
date = "2026-08-17"
url = "https://github.com/hyperium/hyper/security/advisories/GHSA-q83h-524g-xf6h"

[versions]
patched = [">= 0.4.16"]
\`\`\`

# h2 unbounded empty DATA frames
`;

// Real sparse-index lines for h2 with their published checksums.
const H2_INDEX = [
  JSON.stringify({ name: 'h2', vers: '0.4.14', cksum: 'c'.repeat(64), yanked: false }),
  JSON.stringify({ name: 'h2', vers: '0.4.15', cksum: '6cb093c84e8bd9b188d4c4a8cb6579fc016968d14c99882163cd3ff402a4f155', yanked: false }),
  JSON.stringify({ name: 'h2', vers: '0.4.16', cksum: 'a9f37a958b41b3b19ee2707c06439c0e9e547e847223eb791ecb0cb821c65e27', yanked: false }),
  JSON.stringify({ name: 'h2', vers: '0.4.17', cksum: 'd'.repeat(64), yanked: false }),
].join('\n');

// The h2 block exactly as Cargo.lock carries it, with a neighbour on each side
// so an edit that escapes its own block is visible.
const LOCK = `[[package]]
name = "h1-neighbour"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "${'1'.repeat(64)}"

[[package]]
name = "h2"
version = "0.4.15"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "6cb093c84e8bd9b188d4c4a8cb6579fc016968d14c99882163cd3ff402a4f155"
dependencies = [
 "atomic-waker",
 "bytes",
]

[[package]]
name = "h3-neighbour"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "${'2'.repeat(64)}"
`;

const PLANNER = {
  diagnostics: parseDenyDiagnostics(DENY_JSON),
  readAdvisory: (id) => (id === 'RUSTSEC-2026-0258' ? ADVISORY_MD : null),
  listVersions: () => parseIndexEntries(H2_INDEX),
};

test('only defect diagnostics are actionable', () => {
  const found = parseDenyDiagnostics(DENY_JSON);
  assert.deepEqual(
    found.map((entry) => entry.id),
    ['RUSTSEC-2026-0258'],
    'unmaintained, advisory-not-detected and summary records must not become bumps',
  );
  assert.equal(found[0].crate, 'h2');
  assert.equal(found[0].version, '0.4.15');
});

test('the patched range is read from the advisory front matter', () => {
  assert.deepEqual(parsePatchedVersions(ADVISORY_MD), ['>= 0.4.16']);
  assert.deepEqual(parsePatchedVersions('no front matter here'), []);
});

test('an unreadable requirement is refused rather than treated as satisfied', () => {
  assert.equal(parseRequirement('>= 0.4.16')?.length, 1);
  assert.equal(parseRequirement('>= 0.4.16, < 0.5.0')?.length, 2);
  assert.equal(parseRequirement('whatever upstream says'), null);
});

test('satisfies rejects prereleases and honours conjunctions', () => {
  const range = [parseRequirement('>= 0.4.16, < 0.5.0')];
  assert.equal(satisfies('0.4.16', range), true);
  assert.equal(satisfies('0.4.15', range), false);
  assert.equal(satisfies('0.5.0', range), false);
  assert.equal(satisfies('0.4.17-rc.1', range), false);
});

test('compatibility follows the leftmost non-zero component', () => {
  assert.equal(caretCompatible('0.4.15', '0.4.16'), true);
  assert.equal(caretCompatible('0.4.15', '0.5.0'), false);
  assert.equal(caretCompatible('1.2.3', '1.9.0'), true);
  assert.equal(caretCompatible('1.2.3', '2.0.0'), false);
});

test('the target is the lowest compatible published fix, not the latest', () => {
  const target = chooseTarget({
    current: '0.4.15',
    requirements: [parseRequirement('>= 0.4.16')],
    available: parseIndexEntries(H2_INDEX),
  });
  assert.equal(target.version, '0.4.16');
  assert.equal(target.checksum, 'a9f37a958b41b3b19ee2707c06439c0e9e547e847223eb791ecb0cb821c65e27');
});

test('a yanked fix is not a fix', () => {
  const yanked = H2_INDEX.split('\n').map((line) => {
    const record = JSON.parse(line);
    if (record.vers === '0.4.16') record.yanked = true;
    return JSON.stringify(record);
  }).join('\n');
  const target = chooseTarget({
    current: '0.4.15',
    requirements: [parseRequirement('>= 0.4.16')],
    available: parseIndexEntries(yanked),
  });
  assert.equal(target.version, '0.4.17', 'the sweep must skip a yanked release');
});

test('an advisory whose fix needs a major bump is unfixable, never a silent break', () => {
  const plan = planBumps({
    ...PLANNER,
    readAdvisory: () => ADVISORY_MD.replace('>= 0.4.16', '>= 1.0.0'),
  });
  assert.deepEqual(plan.bumps, []);
  assert.equal(plan.unfixable.length, 1);
  assert.match(plan.unfixable[0].reason, /no semver-compatible published version/);
});

test('an advisory missing from the database is unfixable', () => {
  const plan = planBumps({ ...PLANNER, readAdvisory: () => null });
  assert.deepEqual(plan.bumps, []);
  assert.match(plan.unfixable[0].reason, /is not in the fetched database/);
});

test('the plan names the crate, both versions, the checksum and the advisory', () => {
  const plan = planBumps(PLANNER);
  assert.deepEqual(plan.unfixable, []);
  assert.deepEqual(plan.bumps, [
    {
      crate: 'h2',
      from: '0.4.15',
      to: '0.4.16',
      checksum: 'a9f37a958b41b3b19ee2707c06439c0e9e547e847223eb791ecb0cb821c65e27',
      advisories: ['RUSTSEC-2026-0258'],
    },
  ]);
});

test('the lock edit moves the version and checksum of one entry and nothing else', () => {
  const plan = planBumps(PLANNER);
  const bumped = applyBump(LOCK, plan.bumps[0]);
  const before = LOCK.split('\n');
  const after = bumped.split('\n');
  assert.equal(before.length, after.length, 'a bump must not add or remove lock lines');
  const moved = before
    .map((line, index) => (line === after[index] ? null : index))
    .filter((index) => index !== null);
  assert.equal(moved.length, 2, 'exactly the version and the checksum line move');
  assert.equal(after[moved[0]], 'version = "0.4.16"');
  assert.equal(
    after[moved[1]],
    'checksum = "a9f37a958b41b3b19ee2707c06439c0e9e547e847223eb791ecb0cb821c65e27"',
  );
  assert.ok(bumped.includes('name = "h1-neighbour"\nversion = "1.0.0"'));
  assert.ok(bumped.includes('name = "h3-neighbour"\nversion = "2.0.0"'));
});

test('a lock that already carries the target is refused rather than duplicated', () => {
  const plan = planBumps(PLANNER);
  const already = LOCK.replace('name = "h3-neighbour"\nversion = "2.0.0"', 'name = "h2"\nversion = "0.4.16"');
  assert.throws(() => applyBump(already, plan.bumps[0]), /would duplicate it/);
});

test('a crate that is not a registry entry is refused', () => {
  const plan = planBumps(PLANNER);
  const gitSourced = LOCK.replace(
    'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "6cb093',
    'source = "git+https://example.invalid/h2"\nchecksum = "6cb093',
  );
  assert.throws(() => applyBump(gitSourced, plan.bumps[0]), /does not resolve from the crates.io registry/);
});

test('a missing entry is refused rather than appended', () => {
  const plan = planBumps(PLANNER);
  assert.throws(() => applyBump(LOCK.replace('version = "0.4.15"', 'version = "0.4.13"'), plan.bumps[0]), /no h2 0.4.15 entry/);
});

test('the merge-group annotation names the advisory and the bump command', () => {
  const plan = planBumps(PLANNER);
  const lines = renderMergeGroupAnnotations(plan);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^::error::/);
  assert.match(lines[0], /RUSTSEC-2026-0258/);
  assert.match(lines[0], /cargo update -p h2@0\.4\.15 --precise 0\.4\.16/);
  assert.equal(bumpCommand(plan.bumps[0]), 'cargo update -p h2@0.4.15 --precise 0.4.16');
});

test('a cargo-deny failure with no advisory says so instead of naming one', () => {
  const lines = renderMergeGroupAnnotations({ bumps: [], unfixable: [] });
  assert.equal(lines.length, 1);
  assert.match(lines[0], /bans, licenses, or sources/);
});

test('the rendered bodies name the advisories and carry no assistant trace', () => {
  const plan = planBumps(PLANNER);
  const body = renderPullRequestBody(plan);
  assert.match(body, /h2 0\.4\.15 to 0\.4\.16 for RUSTSEC-2026-0258/);
  assert.doesNotMatch(body, /—/, 'PR bodies become squash commit messages and carry no em dash');
  const issue = renderIssueBody({
    bumps: [],
    unfixable: [{ id: 'RUSTSEC-2026-0999', crate: 'x', version: '1.0.0', reason: 'no fix', url: '' }],
  });
  assert.match(issue, /RUSTSEC-2026-0999 in x 1\.0\.0: no fix/);
});

test('an advisory cargo-deny counted but the planner could not read is not a clean sweep', () => {
  // The failure this guards is a cargo-deny upgrade that moves the diagnostic
  // shape. An unreadable advisory and an absent advisory produce the same empty
  // plan, and only one of them means the tree is clean.
  const unreadable = [
    JSON.stringify({ type: 'diagnostic', fields: { code: 'vulnerability', advisory: {}, graphs: [] } }),
    JSON.stringify({ type: 'summary', fields: { advisories: { errors: 1 } } }),
  ].join('\n');
  assert.deepEqual(parseDenyDiagnostics(unreadable), []);
  assert.equal(parseDenySummary(unreadable).errors, 1);
  assert.equal(parseDenySummary(DENY_JSON).errors, 1);
  assert.equal(parseDenySummary('nothing here').errors, 0);
});

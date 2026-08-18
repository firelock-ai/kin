#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Turn a freshly published RustSec advisory into a lock bump before the merge
// queue turns it into an ejection.
//
// cargo-deny's advisories check is the only check in SAST whose verdict is not
// a function of the merge candidate: it is resolved against the RustSec
// database fetched at run time. On 2026-08-18 RUSTSEC-2026-0258 (h2 0.4.15)
// published between kin#893's own SAST run and its merge-group run, the group
// went red, and the hosted queue dropped an entry that had introduced neither
// h2 nor the advisory, marking nothing on it. The fix was a lockfile-only bump
// that had to land first, so the ejection cost about an hour of release time
// and bought nothing.
//
// This module is the decision half of the sweep that lands that bump on a
// schedule instead. It reads cargo-deny's JSON diagnostics, reads the patched
// range out of the advisory database cargo-deny already fetched, and produces
// a plan: which lock entries to move, and which advisories have no
// semver-compatible fix and therefore belong in an issue rather than in a pull
// request that cannot go green.
//
// The lock edit is a direct entry rewrite rather than `cargo update --precise`
// on purpose. Measured on 2026-08-18 against main at 320cf57a with the pinned
// 1.96.0 toolchain, `cargo update -p h2` reported `Locking 0 packages to
// latest compatible versions` on an unmodified lock and still rewrote eleven
// windows-sys reference lines, so the drag is a property of re-resolving that
// lock at all rather than of the bump. An unattended pull request that carries
// eleven unrelated pin movements is not one anybody should arm auto-merge on.
// The workflow still verifies the hand edit with `cargo metadata --locked`,
// which fails when a hand-written lock is not one cargo would have produced.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

export const REGISTRY_SOURCE = 'registry+https://github.com/rust-lang/crates.io-index';

// cargo-deny codes that describe a defect in a dependency rather than a note
// about the configuration. `unmaintained` is deliberately absent: deny.toml
// ignores those with reasons, and a sweep that opened bumps for them would
// fight the reviewed ignore list.
export const ACTIONABLE_CODES = new Set(['vulnerability', 'unsound']);

export function parseDenyDiagnostics(text) {
  const found = [];
  for (const line of String(text).split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let record;
    try {
      record = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const fields = record?.fields;
    if (!fields || !ACTIONABLE_CODES.has(fields.code)) continue;
    const advisory = fields.advisory ?? {};
    const krate = fields.graphs?.[0]?.Krate;
    if (!advisory.id || !krate?.name || !krate?.version) continue;
    found.push({
      id: advisory.id,
      code: fields.code,
      crate: krate.name,
      version: krate.version,
      title: advisory.title ?? '',
      url: advisory.url ?? '',
    });
  }
  return found;
}

export function parseDenySummary(text) {
  // cargo-deny's last JSON record counts what it found. The planner reads the
  // diagnostics; this reads the count, so a diagnostic shape that changes under
  // a cargo-deny upgrade shows up as a mismatch rather than as a clean sweep.
  // An unreadable advisory and an absent advisory are otherwise the same empty
  // plan, and only one of them is safe.
  let errors = 0;
  for (const line of String(text).split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let record;
    try {
      record = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (record?.type === 'summary' && Number.isInteger(record?.fields?.advisories?.errors)) {
      errors = record.fields.advisories.errors;
    }
  }
  return { errors };
}

export function parsePatchedVersions(markdown) {
  // The advisory front matter is TOML inside a fenced block. Only the
  // `[versions]` table's `patched` array is read, and only its string entries,
  // so a malformed or absent field yields no requirement rather than a guess.
  const match = /^\s*patched\s*=\s*\[([^\]]*)\]/m.exec(String(markdown));
  if (!match) return [];
  return [...match[1].matchAll(/"([^"]+)"/g)].map((entry) => entry[1].trim()).filter(Boolean);
}

export function parseVersion(text) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+](.*))?$/.exec(String(text).trim());
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    pre: match[4] ?? '',
  };
}

export function compareVersions(left, right) {
  const a = typeof left === 'string' ? parseVersion(left) : left;
  const b = typeof right === 'string' ? parseVersion(right) : right;
  if (!a || !b) throw new Error('compareVersions needs two parsable versions');
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return 0;
}

export function parseRequirement(text) {
  // RustSec patched ranges are conjunctions of simple comparators, most often
  // a single `>= X`. Anything this cannot read is reported as unreadable, so
  // an unfamiliar range never silently widens into "everything satisfies it".
  const terms = [];
  for (const raw of String(text).split(',')) {
    const term = raw.trim();
    if (!term) continue;
    const match = /^(>=|<=|>|<|\^|~|=)?\s*(\d+\.\d+\.\d+|\d+\.\d+|\d+)$/.exec(term);
    if (!match) return null;
    const op = match[1] ?? '^';
    const parts = match[2].split('.').map(Number);
    while (parts.length < 3) parts.push(0);
    terms.push({ op, version: { major: parts[0], minor: parts[1], patch: parts[2], pre: '' } });
  }
  return terms.length > 0 ? terms : null;
}

function satisfiesTerm(version, term) {
  const order = compareVersions(version, term.version);
  switch (term.op) {
    case '>=':
      return order >= 0;
    case '>':
      return order > 0;
    case '<=':
      return order <= 0;
    case '<':
      return order < 0;
    case '=':
      return order === 0;
    case '^':
      return order >= 0 && caretCompatible(term.version, version);
    case '~':
      return (
        order >= 0 &&
        version.major === term.version.major &&
        version.minor === term.version.minor
      );
    default:
      return false;
  }
}

export function satisfies(version, requirements) {
  const parsed = typeof version === 'string' ? parseVersion(version) : version;
  if (!parsed || parsed.pre) return false;
  return requirements.every((terms) => terms.every((term) => satisfiesTerm(parsed, term)));
}

export function caretCompatible(current, candidate) {
  // Cargo's compatibility rule: the leftmost non-zero component may not move.
  const a = typeof current === 'string' ? parseVersion(current) : current;
  const b = typeof candidate === 'string' ? parseVersion(candidate) : candidate;
  if (!a || !b) return false;
  if (a.major !== 0) return a.major === b.major;
  if (a.minor !== 0) return b.major === 0 && a.minor === b.minor;
  return b.major === 0 && b.minor === 0;
}

export function chooseTarget({ current, requirements, available }) {
  // The lowest published, unyanked, non-prerelease version that satisfies every
  // patched range, is semver-compatible with what the lock carries today, and
  // is not a downgrade. Lowest rather than latest keeps the diff to the one
  // entry the advisory is about.
  const currentVersion = parseVersion(current);
  if (!currentVersion || requirements.length === 0) return null;
  const ordered = available
    .filter((entry) => !entry.yanked)
    .map((entry) => ({ ...entry, parsed: parseVersion(entry.version) }))
    .filter((entry) => entry.parsed && !entry.parsed.pre)
    .filter((entry) => compareVersions(entry.parsed, currentVersion) > 0)
    .filter((entry) => caretCompatible(currentVersion, entry.parsed))
    .filter((entry) => satisfies(entry.parsed, requirements))
    .sort((left, right) => compareVersions(left.parsed, right.parsed));
  return ordered[0] ?? null;
}

export function findAdvisoryFile(root, id) {
  // Located by walking rather than by rebuilding cargo-deny's hashed database
  // directory name, which is not a documented interface.
  const stack = [root];
  const wanted = `${id}.md`;
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.name === wanted) return full;
    }
  }
  return null;
}

export function planBumps({ diagnostics, readAdvisory, listVersions }) {
  const bumps = new Map();
  const unfixable = [];
  for (const finding of diagnostics) {
    const markdown = readAdvisory(finding.id);
    if (markdown === null || markdown === undefined) {
      unfixable.push({ ...finding, reason: `advisory ${finding.id} is not in the fetched database` });
      continue;
    }
    const patched = parsePatchedVersions(markdown);
    if (patched.length === 0) {
      unfixable.push({ ...finding, reason: 'the advisory names no patched version' });
      continue;
    }
    const requirements = patched.map(parseRequirement);
    if (requirements.some((entry) => entry === null)) {
      unfixable.push({ ...finding, reason: `unreadable patched range: ${patched.join(', ')}` });
      continue;
    }
    const available = listVersions(finding.crate);
    if (!available || available.length === 0) {
      unfixable.push({ ...finding, reason: `no published versions found for ${finding.crate}` });
      continue;
    }
    const target = chooseTarget({ current: finding.version, requirements, available });
    if (!target) {
      unfixable.push({
        ...finding,
        reason: `no semver-compatible published version satisfies ${patched.join(', ')}`,
      });
      continue;
    }
    const key = `${finding.crate}@${finding.version}`;
    const existing = bumps.get(key);
    if (existing) {
      existing.advisories.push(finding.id);
      if (compareVersions(target.version, existing.to) > 0) {
        existing.to = target.version;
        existing.checksum = target.checksum;
      }
      continue;
    }
    bumps.set(key, {
      crate: finding.crate,
      from: finding.version,
      to: target.version,
      checksum: target.checksum,
      advisories: [finding.id],
    });
  }
  return { bumps: [...bumps.values()], unfixable };
}

function packageBlockPattern(crate, version) {
  const escape = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `(\\[\\[package\\]\\]\\nname = "${escape(crate)}"\\nversion = ")${escape(version)}(")`,
  );
}

export function applyBump(lockText, bump) {
  // Refuse rather than guess. A lock that already carries the target version
  // would gain a duplicate entry, and an entry without a checksum line is not
  // a registry crate, so neither is edited in place.
  const pattern = packageBlockPattern(bump.crate, bump.from);
  const match = pattern.exec(lockText);
  if (!match) {
    throw new Error(`Cargo.lock has no ${bump.crate} ${bump.from} entry to bump`);
  }
  if (packageBlockPattern(bump.crate, bump.to).test(lockText)) {
    throw new Error(`Cargo.lock already carries ${bump.crate} ${bump.to}; a direct edit would duplicate it`);
  }
  const blockStart = match.index;
  const nextBlock = lockText.indexOf('\n[[package]]', blockStart + 1);
  const blockEnd = nextBlock === -1 ? lockText.length : nextBlock;
  const block = lockText.slice(blockStart, blockEnd);
  if (!block.includes(`source = "${REGISTRY_SOURCE}"`)) {
    throw new Error(`${bump.crate} ${bump.from} does not resolve from the crates.io registry`);
  }
  const checksumPattern = /\nchecksum = "[0-9a-f]{64}"/;
  if (!checksumPattern.test(block)) {
    throw new Error(`${bump.crate} ${bump.from} carries no checksum line to replace`);
  }
  const bumped = block
    .replace(pattern, `$1${bump.to}$2`)
    .replace(checksumPattern, `\nchecksum = "${bump.checksum}"`);
  return lockText.slice(0, blockStart) + bumped + lockText.slice(blockEnd);
}

export function applyPlan(lockText, plan) {
  let next = lockText;
  for (const bump of plan.bumps) next = applyBump(next, bump);
  return next;
}

export function bumpCommand(bump) {
  return `cargo update -p ${bump.crate}@${bump.from} --precise ${bump.to}`;
}

export function renderMergeGroupAnnotations(plan) {
  const lines = [];
  for (const bump of plan.bumps) {
    lines.push(
      `::error::merge group blocked by ${bump.advisories.join(', ')} in ${bump.crate} ${bump.from}. ` +
        'This advisory published after this pull request\'s own SAST run and is not its change. ' +
        `The advisory sweep opens the lock bump on automation/advisory-bump; by hand it is: ${bumpCommand(bump)}`,
    );
  }
  for (const finding of plan.unfixable) {
    lines.push(
      `::error::merge group blocked by ${finding.id} in ${finding.crate} ${finding.version}, ` +
        `which has no semver-compatible bump: ${finding.reason}`,
    );
  }
  if (lines.length === 0) {
    lines.push(
      '::error::cargo-deny failed but reported no vulnerability or unsound advisory, ' +
        'so the failure is in bans, licenses, or sources and belongs to this change',
    );
  }
  return lines;
}

export function renderPullRequestBody(plan) {
  const ids = plan.bumps.flatMap((bump) => bump.advisories);
  const lines = [
    'Automated advisory bump opened by the scheduled advisory sweep.',
    '',
    'A RustSec advisory that publishes between a pull request\'s own SAST run and its',
    'merge-group run turns the required cargo-deny context red inside the queue, and the',
    'queue then drops an entry that did not cause it and marks nothing on it. Landing the',
    'lock bump on a schedule is what keeps a merge group from ever seeing the advisory.',
    '',
    'Lock entries moved, and nothing else:',
    '',
  ];
  for (const bump of plan.bumps) {
    lines.push(`- ${bump.crate} ${bump.from} to ${bump.to} for ${bump.advisories.join(', ')}`);
  }
  lines.push('');
  lines.push(`Advisory ids: ${ids.join(', ')}`);
  return lines.join('\n');
}

export function renderIssueBody(plan) {
  const lines = [
    'The scheduled advisory sweep found advisories with no semver-compatible bump, so it',
    'opened this issue rather than a pull request that could not go green.',
    '',
  ];
  for (const finding of plan.unfixable) {
    lines.push(`- ${finding.id} in ${finding.crate} ${finding.version}: ${finding.reason}`);
    if (finding.url) lines.push(`  ${finding.url}`);
  }
  lines.push('');
  lines.push(
    'Each needs either an upstream release this workspace can admit, or a reviewed',
    'deny.toml ignore carrying a no-exposure justification and a removal trigger.',
  );
  return lines.join('\n');
}

function readArgs(argv) {
  const options = {
    denyJson: null,
    lock: 'Cargo.lock',
    advisoryDb: null,
    indexDir: null,
    dryRun: false,
    annotateMergeGroup: false,
    planOut: null,
    planIn: null,
    render: null,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length) throw new Error(`${arg} needs a value`);
      return argv[index];
    };
    if (arg === '--deny-json') options.denyJson = next();
    else if (arg === '--lock') options.lock = next();
    else if (arg === '--advisory-db') options.advisoryDb = next();
    else if (arg === '--index-dir') options.indexDir = next();
    else if (arg === '--plan-out') options.planOut = next();
    else if (arg === '--plan-in') options.planIn = next();
    else if (arg === '--render') options.render = next();
    else if (arg === '--dry-run') options.dryRun = true;
    else if (arg === '--annotate-merge-group') options.annotateMergeGroup = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (options.render) {
    if (!options.planIn) throw new Error('--render needs --plan-in');
    if (!RENDERERS.has(options.render)) {
      throw new Error(`unknown --render target: ${options.render}`);
    }
    return options;
  }
  if (!options.denyJson) throw new Error('--deny-json is required');
  return options;
}

function defaultAdvisoryRoot() {
  const cargoHome = process.env.CARGO_HOME || path.join(process.env.HOME ?? '', '.cargo');
  return path.join(cargoHome, 'advisory-dbs');
}

function sparseIndexPath(crate) {
  const name = crate.toLowerCase();
  if (name.length === 1) return `1/${name}`;
  if (name.length === 2) return `2/${name}`;
  if (name.length === 3) return `3/${name[0]}/${name}`;
  return `${name.slice(0, 2)}/${name.slice(2, 4)}/${name}`;
}

export function parseIndexEntries(text) {
  const versions = [];
  for (const line of String(text).split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let record;
    try {
      record = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (!record.vers || !record.cksum) continue;
    versions.push({ version: record.vers, checksum: record.cksum, yanked: Boolean(record.yanked) });
  }
  return versions;
}

async function fetchIndexEntries(crate, indexDir) {
  if (indexDir) {
    const file = path.join(indexDir, `${crate}.json`);
    if (!fs.existsSync(file)) return [];
    return parseIndexEntries(fs.readFileSync(file, 'utf8'));
  }
  const response = await fetch(`https://index.crates.io/${sparseIndexPath(crate)}`);
  if (!response.ok) return [];
  return parseIndexEntries(await response.text());
}

export const RENDERERS = new Map([
  ['pr-body', renderPullRequestBody],
  ['issue-body', renderIssueBody],
  ['annotations', (plan) => renderMergeGroupAnnotations(plan).join('\n')],
]);

async function main(argv) {
  const options = readArgs(argv);
  if (options.render) {
    const plan = JSON.parse(fs.readFileSync(options.planIn, 'utf8'));
    console.log(RENDERERS.get(options.render)(plan));
    return 0;
  }
  const denyText = fs.readFileSync(options.denyJson, 'utf8');
  const diagnostics = parseDenyDiagnostics(denyText);
  const summary = parseDenySummary(denyText);
  const advisoryRoot = options.advisoryDb ?? defaultAdvisoryRoot();
  const versionCache = new Map();
  for (const finding of diagnostics) {
    if (versionCache.has(finding.crate)) continue;
    versionCache.set(finding.crate, await fetchIndexEntries(finding.crate, options.indexDir));
  }
  const plan = planBumps({
    diagnostics,
    readAdvisory: (id) => {
      const file = findAdvisoryFile(advisoryRoot, id);
      return file ? fs.readFileSync(file, 'utf8') : null;
    },
    listVersions: (crate) => versionCache.get(crate) ?? [],
  });

  if (summary.errors > 0 && plan.bumps.length + plan.unfixable.length === 0) {
    throw new Error(
      `cargo-deny reported ${summary.errors} advisory error(s) that this planner read as none; ` +
        'treat the diagnostics as unreadable rather than the tree as clean',
    );
  }

  if (options.annotateMergeGroup) {
    for (const line of renderMergeGroupAnnotations(plan)) console.log(line);
    return 0;
  }

  if (!options.dryRun && plan.bumps.length > 0) {
    const lockText = fs.readFileSync(options.lock, 'utf8');
    fs.writeFileSync(options.lock, applyPlan(lockText, plan), 'utf8');
  }

  const serialized = JSON.stringify(plan, null, 2);
  if (options.planOut) fs.writeFileSync(options.planOut, `${serialized}\n`, 'utf8');
  console.log(serialized);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(`advisory-sweep: ${error.message}`);
      process.exitCode = 1;
    });
}

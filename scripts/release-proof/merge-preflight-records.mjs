#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Merge the per-archive preflight leg records release-cut.yml's preflight job
// uploads into the one preflight.json the mint reads.
//
// The local preflight judges every archive in one run and writes one record.
// Hosted, each archive is judged on the runner that can execute it (macOS for
// the macOS archive, an arm64 and an x86_64 Linux runner for the Linux ones),
// so the legs arrive as separate records under separate artifacts. The evidence
// branch is append-only and keyed by candidate sha, so those records cannot be
// published one after another under one sha: the second would be refused as a
// different answer for the same candidate. They are merged here instead, and
// the merged record is judged by the mint's own gate before anything publishes
// it, so a record this tool writes is a record the mint can accept.
//
// Deterministic on purpose. The publisher treats a byte-identical re-publish as
// a no-op and a different one as tampering, so a merge repeated for the same
// leg records has to reproduce the same bytes: nothing about the merging run
// (its id, its clock) reaches the output, and the legs are ordered by target.

import { readFileSync, writeFileSync } from 'node:fs';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { PREFLIGHT_SCHEMA, judgePreflight } from '../check-release-proof-artifacts.mjs';

export const HOSTED_LANE = 'HOSTED-CI';
const COMMIT_SHA = /^[0-9a-f]{40}$/;

function usage(message) {
  process.stderr.write(
    `${message}\n\n` +
    'usage: merge-preflight-records.mjs --candidate <40-hex sha> --out <file> <leg record>...\n',
  );
  process.exit(2);
}

export function parseArgs(argv) {
  const args = { records: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    switch (flag) {
      case '--candidate': args.candidate = argv[i + 1]; i += 1; break;
      case '--out': args.out = argv[i + 1]; i += 1; break;
      default:
        if (flag.startsWith('--')) usage(`unknown argument: ${flag}`);
        args.records.push(flag);
    }
  }
  if (!args.candidate || !COMMIT_SHA.test(args.candidate)) {
    usage(`--candidate must be a 40-character commit sha, got "${args.candidate ?? ''}"`);
  }
  if (!args.out) usage('--out is required');
  if (args.records.length === 0) usage('at least one leg record is required');
  return args;
}

function requireObject(value, where) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${where} is not a preflight record object`);
  }
  return value;
}

// Every leg record has to be a passing preflight record about this candidate
// on its own before it contributes a leg. A merge that admitted a failing leg
// record and then reported PASS because the other legs passed would be the
// silent half of exactly the class the gate exists to refuse.
export function admitLegRecord(record, candidate, where) {
  requireObject(record, where);
  if (record.schema !== PREFLIGHT_SCHEMA) {
    throw new Error(`${where} carries schema "${record.schema ?? '<none>'}", not ${PREFLIGHT_SCHEMA}`);
  }
  if (record.verdict !== 'PASS') {
    throw new Error(`${where} records verdict ${record.verdict ?? '<none>'}, not PASS`);
  }
  if (record.allow_dirty === true) {
    throw new Error(`${where} was run with allow_dirty and cannot evidence a tag`);
  }
  const legs = Array.isArray(record.legs) ? record.legs : [];
  if (legs.length === 0) {
    throw new Error(`${where} records no legs`);
  }
  for (const leg of legs) {
    requireObject(leg, `${where} leg`);
    const commit = leg?.result?.expected?.commit;
    if (commit !== candidate) {
      throw new Error(
        `${where} leg "${leg.name ?? '<unnamed>'}" judged commit ${commit ?? '<none>'}, not ${candidate}`,
      );
    }
    if (leg.verdict !== 'PASS') {
      throw new Error(`${where} leg "${leg.name ?? '<unnamed>'}" records verdict ${leg.verdict ?? '<none>'}`);
    }
    if (typeof leg.target !== 'string' || !leg.target) {
      throw new Error(`${where} leg "${leg.name ?? '<unnamed>'}" names no target`);
    }
  }
  return legs;
}

// `tooling.source` is `<checkout> @ <ref>`, and the checkout is where the
// tooling was READ, not what it is. Hosted, one candidate is judged on three
// runners, and a macOS runner's checkout is /Users/runner/work/kin/kin while a
// Linux runner's is /home/runner/work/kin/kin. Comparing the raw field called
// three legs of one commit "different tooling" and refused to merge them, which
// on 2026-09-03 failed run 33700686594 with all three legs green on
// 54dc78e3b7ab41b1cac12bf95aa345fbf57eca39 and both sha256 fields identical.
//
// The identity is the ref and the hashes. A source with no ` @ ` is a working
// tree, which names no ref, so it stays compared whole: two working trees are
// not known to be the same bytes.
function toolingIdentity(tooling) {
  if (tooling === null || typeof tooling !== 'object') return JSON.stringify(tooling ?? null);
  const source = typeof tooling.source === 'string' ? tooling.source : null;
  const at = source === null ? -1 : source.lastIndexOf(' @ ');
  return JSON.stringify({ ...tooling, source: at === -1 ? source : source.slice(at + 3) });
}

// Identical sources stay verbatim, so a merge of records from one checkout
// writes exactly the bytes it wrote before. Where they differ only by checkout
// directory, no single one of them is true of the merged record, so it names
// how many checkouts agreed and the ref they agreed on. Deterministic either
// way: the publisher reads a differing document under a sha that already has
// one as tampering.
function mergedTooling(toolings) {
  const first = toolings[0];
  const sources = new Set(toolings.map((entry) => (entry && typeof entry === 'object' ? entry.source : null)));
  if (sources.size === 1) return first;
  const source = typeof first?.source === 'string' ? first.source : '';
  const at = source.lastIndexOf(' @ ');
  const ref = at === -1 ? source : source.slice(at + 3);
  return { ...first, source: `${sources.size} checkouts @ ${ref}` };
}

export function mergeRecords(records, candidate) {
  if (!COMMIT_SHA.test(candidate ?? '')) {
    throw new Error(`"${candidate}" is not a 40-character commit sha`);
  }
  if (!Array.isArray(records) || records.length === 0) {
    throw new Error('no leg records to merge');
  }
  // Order every downstream field off ONE ordering, decided here from the leg
  // targets rather than from the order the artifacts happened to download in.
  // Sorting only the outputs is not enough: `provenance` and `skipped` are
  // concatenations, and merging the same three leg records in two orders
  // produced two different documents. The publisher reads a differing document
  // under a sha that already has one as tampering and refuses it forever, so a
  // re-publish after an interrupted upload would have been unrecoverable.
  const admittedByEntry = records.map((entry, index) => {
    const where = entry.where ?? `record ${index}`;
    return { where, record: entry.record, legs: admitLegRecord(entry.record, candidate, where) };
  });
  admittedByEntry.sort((left, right) => {
    const key = (entry) => entry.legs.map((leg) => leg.target).sort().join(',');
    return key(left).localeCompare(key(right));
  });

  const legs = [];
  const sources = [];
  const tooling = [];
  let cpuEmbed = true;
  admittedByEntry.forEach(({ where, record, legs: admitted }) => {
    for (const leg of admitted) {
      const twin = legs.find((seen) => seen.target === leg.target);
      if (twin) {
        throw new Error(
          `two leg records judged ${leg.target}; which one evidences the candidate is ambiguous`,
        );
      }
      legs.push(leg);
    }
    sources.push({
      run: record.run ?? null,
      host: record.host ?? null,
      lane: record.lane ?? null,
      cpu_embed: record.cpu_embed === true,
      targets: admitted.map((leg) => leg.target).sort(),
    });
    tooling.push(JSON.stringify(record.tooling ?? null));
    if (record.cpu_embed !== true) cpuEmbed = false;
  });
  const identities = new Set(tooling.map((entry) => toolingIdentity(JSON.parse(entry))));
  if (identities.size !== 1) {
    throw new Error(
      'the leg records were produced by different tooling; refusing to merge them into one answer: ' +
      [...identities].sort().join(' vs '),
    );
  }
  const archives = new Map();
  for (const leg of legs) {
    const sha = leg?.result?.archive?.sha256;
    if (typeof sha !== 'string') continue;
    if (archives.has(sha) && archives.get(sha) !== leg.target) {
      throw new Error(`archive sha256 ${sha} is claimed by ${archives.get(sha)} and ${leg.target}`);
    }
    archives.set(sha, leg.target);
  }
  legs.sort((left, right) => left.target.localeCompare(right.target));
  const merged = {
    schema: PREFLIGHT_SCHEMA,
    citable: false,
    lane: HOSTED_LANE,
    run: `merged:${sources.map((source) => source.run ?? 'unknown').join('+')}`,
    host: `github-actions:${sources.map((source) => source.host ?? 'unknown').join('+')}`,
    lock_lane: 'release-proof',
    verdict: 'PASS',
    allow_dirty: false,
    cpu_embed: cpuEmbed,
    tooling: mergedTooling(tooling.map((entry) => JSON.parse(entry))),
    provenance: admittedByEntry.flatMap(({ record }) => (Array.isArray(record.provenance) ? record.provenance : [])),
    skipped: admittedByEntry.flatMap(({ record }) => (Array.isArray(record.skipped) ? record.skipped : [])),
    legs,
    merged_from: sources,
    run_root: null,
    log: null,
  };
  // The mint's own judge, on the bytes about to be published. This is the
  // assertion that turns "the merge looked right" into "the mint accepts it".
  const { archives: judged } = judgePreflight(merged, candidate);
  return { merged, archives: judged };
}

export function main(argv = process.argv.slice(2), { log = console.log } = {}) {
  const args = parseArgs(argv);
  const records = args.records.map((file) => {
    let record;
    try {
      record = JSON.parse(readFileSync(file, 'utf8'));
    } catch (cause) {
      throw new Error(`${file} is not a readable JSON record: ${cause.message}`, { cause });
    }
    return { where: file, record };
  });
  const { merged, archives } = mergeRecords(records, args.candidate);
  writeFileSync(args.out, `${JSON.stringify(merged, null, 2)}\n`);
  log(
    `merged ${merged.legs.length} leg(s) for ${args.candidate} into ${args.out}: ` +
    `${merged.legs.map((leg) => `${leg.target} (${leg.result.archive.sha256.slice(0, 12)})`).join(', ')}; ` +
    `the mint's gate judged ${archives.length} archive(s) PASS`,
  );
  return merged;
}

// Real-path comparison, for the same reason check-release-proof-artifacts.mjs
// gives: a copy run through a symlinked directory would otherwise judge nothing
// and exit 0.
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
  try {
    main();
  } catch (error) {
    console.error(`::error::${error.message}`);
    process.exit(1);
  }
}

export const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
export const GATE_PATH = join(SCRIPT_DIR, '..', 'check-release-proof-artifacts.mjs');

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// The release train's proof-loop gate.
//
// On 2026-08-20 the train ran end to end with nobody at the button: it merged
// its own version bump, tagged v0.5.44, and promoted to Latest, and no
// preflight had judged that candidate and no stranger had run on its bytes.
// The only thing that had ever stood between the autonomous cadence and an
// unproofed cut was a session-local holder monitor. That monitor was correctly
// retired when its pause-era purpose ended, and the autopilot flew through the
// open gate the same evening. A gate that lives in a monitor can always be
// retired correctly again, so this one lives in the train.
//
// Both decision points import this module rather than reimplementing it, so
// they cannot disagree about what counts as evidence while agreeing that they
// checked: release-train.yml holds the version bump when the candidate has
// none, and release.yml refuses to promote a tag that has none.
//
// The gate reads the proof loop's own records, not a summary of them. A
// preflight record names, per leg, the commit that leg judged and the archive
// sha256 it judged there. A stranger run.env names the archive sha256 the
// stranger actually ran. Requiring the stranger's archive to appear among the
// preflight's legs is what links the two: it proves the stranger ran on the
// bytes the preflight judged FOR THIS COMMIT, rather than on some other build
// that merely also exists. Two independent existence checks would not.

import process from 'node:process';
import { pathToFileURL } from 'node:url';

// Records live on an orphan branch rather than on main: they are per-candidate
// evidence, they arrive after the commit they describe, and writing them to
// main would put a commit on main for every proof run, which would itself
// become drift the train then wants to release.
export const EVIDENCE_REF = 'release-evidence';
export const PREFLIGHT_SCHEMA = 'kin.release-preflight.v1';
export const PREFLIGHT_RECORD = 'preflight.json';
export const STRANGER_RECORD = 'stranger.env';

const COMMIT_SHA = /^[0-9a-f]{40}$/;
const ARCHIVE_SHA = /^[0-9a-f]{64}$/;

export function evidencePath(sha, name) {
  if (typeof sha !== 'string' || !COMMIT_SHA.test(sha)) {
    throw new Error(
      `"${sha}" is not a 40-character commit sha; this gate keys on the ` +
      'candidate\'s exact commit, and a loose ref would let it answer about ' +
      'a different build',
    );
  }
  return `evidence/${sha}/${name}`;
}

// The stranger writes a flat key=value run.env rather than JSON. Values may
// contain '=', so split on the first one only.
export function parseRunEnv(text) {
  const out = {};
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }
    const eq = line.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    out[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return out;
}

export function judgePreflight(record, sha) {
  const where = evidencePath(sha, PREFLIGHT_RECORD);
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error(`${where} did not parse as a preflight record`);
  }
  if (record.schema !== PREFLIGHT_SCHEMA) {
    throw new Error(
      `${where} carries schema "${record.schema ?? '<none>'}", not ` +
      `${PREFLIGHT_SCHEMA}; refusing to read an unknown record as evidence`,
    );
  }
  if (record.verdict !== 'PASS') {
    throw new Error(
      `${where} records verdict ${record.verdict ?? '<none>'}, not PASS; ` +
      'the candidate did not clear preflight',
    );
  }
  // Citability is deliberately NOT the test. kin-release-preflight emits
  // citable false and lane DEV-LOCAL on every run by design, so requiring
  // citability would be the mirror of a check that cannot fail: a check that
  // cannot pass, holding every release forever and looking principled doing
  // it. allow_dirty carries the same intent and a real run can clear it.
  if (record.allow_dirty === true) {
    throw new Error(
      `${where} was run with allow_dirty, so it judged a build from ` +
      'uncommitted changes, which is not what any tag can contain',
    );
  }
  const legs = Array.isArray(record.legs) ? record.legs : [];
  if (legs.length === 0) {
    throw new Error(`${where} records no legs, so it judged nothing`);
  }
  const archives = [];
  legs.forEach((leg, index) => {
    const name = leg?.name ?? `leg ${index}`;
    const result = leg?.result ?? {};
    const commit = result?.expected?.commit;
    if (commit !== sha) {
      throw new Error(
        `${where} leg "${name}" judged commit ${commit ?? '<none>'}, not ` +
        `${sha}; the record exists but is about a different build`,
      );
    }
    if (leg?.verdict !== 'PASS') {
      throw new Error(
        `${where} leg "${name}" records verdict ${leg?.verdict ?? '<none>'}, ` +
        'not PASS',
      );
    }
    const archive = result?.archive?.sha256;
    if (typeof archive !== 'string' || !ARCHIVE_SHA.test(archive)) {
      throw new Error(
        `${where} leg "${name}" records no archive sha256, so nothing can ` +
        'link a stranger run to the bytes it judged',
      );
    }
    archives.push(archive);
  });
  return { archives };
}

export function judgeStranger(env, sha, archives) {
  const where = evidencePath(sha, STRANGER_RECORD);
  const archive = env?.archive_sha256;
  if (!archive) {
    throw new Error(
      `${where} carries no archive_sha256, so it does not say which bytes ` +
      'the stranger ran',
    );
  }
  if (!env?.finished_at) {
    throw new Error(
      `${where} carries no finished_at, so the stranger run did not ` +
      'complete and its verdict is unknown',
    );
  }
  if (!archives.includes(archive)) {
    throw new Error(
      `${where} ran archive sha256 ${archive}, which no preflight leg for ` +
      `${sha} judged (${archives.join(', ')}); the stranger ran, but not on ` +
      'these bytes',
    );
  }
  return { archive };
}

// Fails closed. An unreadable record is not a passing check, so a transport
// failure raises here rather than returning something a caller could mistake
// for evidence. Absence and unreadability raise different messages on purpose:
// one means the proof loop never ran, the other means we cannot tell.
export async function fetchEvidence(
  sha,
  name,
  { repository, token, fetchImpl = fetch } = {},
) {
  const path = evidencePath(sha, name);
  const url =
    `https://api.github.com/repos/${repository}/contents/${path}?ref=${EVIDENCE_REF}`;
  const headers = {
    accept: 'application/vnd.github.raw',
    'user-agent': 'kin-release-proof-gate',
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
      `could not reach ${repository} to read ${path} on ${EVIDENCE_REF}: ${cause.message}`,
      { cause },
    );
  }
  if (response.status === 404) {
    throw new Error(
      `${path} does not exist on the ${EVIDENCE_REF} branch of ${repository}; ` +
      'the proof loop has not recorded this candidate, so it cannot be released',
    );
  }
  if (!response.ok) {
    throw new Error(
      `could not read ${path} on ${EVIDENCE_REF}: ` +
      `HTTP ${response.status} ${response.statusText}`,
    );
  }
  return response.text();
}

// A squash merge mints a new commit, so the sha a tag points at is never the
// sha the proof loop judged. Preflight runs on the release branch head, and the
// tag lands on the squash of that branch onto main: v0.5.44's tag commit
// a4ffe620 is kin#986's squash, while the preflight for that line judged the
// release-next head. Resolving the originating pull request's head is what
// connects the two, and it is the only link that survives a squash, because the
// squash shares no sha, no parent and no tree with the branch it flattened.
//
// A commit with no originating pull request resolves to nothing and the caller
// refuses it. That is the intended answer for a tag minted through a path the
// train does not own, including a hand-pushed one, which is exactly the case
// this gate's second decision point exists to catch.
export async function resolveCandidateSha(
  commitSha,
  { repository, token, fetchImpl = fetch } = {},
) {
  if (typeof commitSha !== 'string' || !COMMIT_SHA.test(commitSha)) {
    throw new Error(`"${commitSha}" is not a 40-character commit sha`);
  }
  const url = `https://api.github.com/repos/${repository}/commits/${commitSha}/pulls`;
  const headers = {
    accept: 'application/vnd.github+json',
    'user-agent': 'kin-release-proof-gate',
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
      `could not reach ${repository} to resolve the pull request behind ${commitSha}: ${cause.message}`,
      { cause },
    );
  }
  if (!response.ok) {
    throw new Error(
      `could not resolve the pull request behind ${commitSha}: ` +
      `HTTP ${response.status} ${response.statusText}`,
    );
  }
  const pulls = await response.json();
  const merged = (Array.isArray(pulls) ? pulls : []).filter(
    (pull) => pull?.merge_commit_sha === commitSha && COMMIT_SHA.test(pull?.head?.sha ?? ''),
  );
  if (merged.length === 0) {
    throw new Error(
      `no merged pull request produced ${commitSha}, so there is no candidate ` +
      'branch head whose proof records could be found; a tag minted outside ' +
      'the release train carries no evidence by construction',
    );
  }
  if (merged.length > 1) {
    const names = merged.map((pull) => `#${pull.number}`).join(', ');
    throw new Error(
      `${commitSha} is claimed as the merge commit of more than one pull ` +
      `request (${names}); refusing to guess which candidate was proven`,
    );
  }
  return merged[0].head.sha;
}

// Two callers, one judge. CANDIDATE_SHA names the candidate directly, which is
// what the release train has before it merges. RESOLVE_FROM_COMMIT names a
// landed commit to bridge through its merged pull request, which is what the
// promote gate has: by then the candidate has been squashed and its sha is
// gone from history.
export async function main({
  sha = process.env.CANDIDATE_SHA,
  resolveFromCommit = process.env.RESOLVE_FROM_COMMIT,
  repository = process.env.GITHUB_REPOSITORY,
  env = process.env,
  fetchImpl = fetch,
  log = console.log,
} = {}) {
  if (!repository) {
    throw new Error('no repository given; set GITHUB_REPOSITORY');
  }
  const token = env.GH_TOKEN || env.GITHUB_TOKEN;
  const options = { repository, token, fetchImpl };

  if (!sha && resolveFromCommit) {
    sha = await resolveCandidateSha(resolveFromCommit, options);
    log(`Resolved candidate ${sha} from landed commit ${resolveFromCommit}`);
  }
  if (!sha) {
    throw new Error(
      'no candidate given; set CANDIDATE_SHA, or RESOLVE_FROM_COMMIT to bridge ' +
      'a landed commit through the pull request that produced it',
    );
  }

  const preflightText = await fetchEvidence(sha, PREFLIGHT_RECORD, options);
  let preflight;
  try {
    preflight = JSON.parse(preflightText);
  } catch (cause) {
    throw new Error(
      `${evidencePath(sha, PREFLIGHT_RECORD)} is not valid JSON: ${cause.message}`,
      { cause },
    );
  }
  const { archives } = judgePreflight(preflight, sha);

  const strangerText = await fetchEvidence(sha, STRANGER_RECORD, options);
  const { archive } = judgeStranger(parseRunEnv(strangerText), sha, archives);

  log(
    `Verified release proof artifacts for ${sha}: preflight PASS across ` +
    `${archives.length} leg(s), stranger ran archive sha256 ${archive}`,
  );
  return { sha, archives, archive };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exit(1);
  });
}

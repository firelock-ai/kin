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
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Records live on an orphan branch rather than on main: they are per-candidate
// evidence, they arrive after the commit they describe, and writing them to
// main would put a commit on main for every proof run, which would itself
// become drift the train then wants to release.
export const EVIDENCE_REF = 'release-evidence';
export const PREFLIGHT_SCHEMA = 'kin.release-preflight.v1';
export const PREFLIGHT_RECORD = 'preflight.json';
export const STRANGER_RECORD = 'stranger.env';
// A primetime release must make it through the three distinct first-contact
// surfaces Kin asks a developer to trust: a new repository, a brownfield
// repository, and the version-control replacement path. `kin-stranger` writes
// these names into run.env, so this is a contract with the proof harness rather
// than a prose convention in a release note.
export const REQUIRED_STRANGER_ARMS = Object.freeze(['green', 'brown', 'vcs']);
// The release train's version bump branch, and the ONLY branch whose head ever
// carried proof records. It bounds the bridge below. release-train.yml declares
// the same literal, and the authority suite pins the two together so they
// cannot drift into a bridge that resolves somewhere nothing was ever proven.
export const BUMP_BRANCH = 'automation/release-next';

const COMMIT_SHA = /^[0-9a-f]{40}$/;
const ARCHIVE_SHA = /^[0-9a-f]{64}$/;

function armList(env, field, { allowEmpty = false } = {}) {
  if (!Object.prototype.hasOwnProperty.call(env ?? {}, field)) {
    throw new Error(`stranger record carries no ${field}, so its arm coverage is unknown`);
  }
  const raw = env[field];
  if (typeof raw !== 'string') {
    throw new Error(`stranger record carries non-text ${field}, so its arm coverage is unknown`);
  }
  const arms = raw.split(',').map((arm) => arm.trim()).filter(Boolean);
  if (!allowEmpty && arms.length === 0) {
    throw new Error(`stranger record carries no ${field}, so its arm coverage is unknown`);
  }
  if (new Set(arms).size !== arms.length) {
    throw new Error(`stranger record repeats an arm in ${field}, so its coverage is ambiguous`);
  }
  return arms;
}

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
    const key = line.slice(0, eq);
    if (Object.prototype.hasOwnProperty.call(out, key)) {
      throw new Error(
        `stranger record repeats key "${key}", so its evidence is ambiguous`,
      );
    }
    out[key] = line.slice(eq + 1);
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

// What a satisfied gate does and does not say.
//
// A record may still contain useful findings. This gate does not decide that
// Kin is defect-free. It does decide that all three required first-contact arms
// completed their two phases on the same archived bytes the preflight judged.
// That distinction is intentional: an unfinished arm cannot be treated as a
// finding, because it has not supplied a result that a human can review.
//
// `finished_at` alone is insufficient. The v0.6.3 record reached that terminal
// field with `arms_complete=` and all three arms in `arms_incomplete`; accepting
// it let a partial local-model run look like release evidence. Require the
// harness's explicit coverage fields, refuse any incomplete arm, and preserve
// the complete arm set in the returned result for callers and logs.
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

  const requested = armList(env, 'arms');
  // An empty completed list is distinct from an absent field: the latter
  // makes coverage unknowable, while the former is an explicit statement that
  // none completed. Keep it long enough to name an incomplete arm when one is
  // recorded, then reject it below if no arm is complete.
  const completed = armList(env, 'arms_complete', { allowEmpty: true });
  const incomplete = armList(env, 'arms_incomplete', { allowEmpty: true });
  const requestedSet = new Set(requested);

  const missingRequired = REQUIRED_STRANGER_ARMS.filter((arm) => !requestedSet.has(arm));
  if (missingRequired.length > 0) {
    throw new Error(
      `${where} omits required stranger arm(s) ${missingRequired.join(', ')}, ` +
      'so the release lacks complete first-contact coverage',
    );
  }

  const unexpectedCompleted = completed.filter((arm) => !requestedSet.has(arm));
  if (unexpectedCompleted.length > 0) {
    throw new Error(
      `${where} marks undeclared arm(s) ${unexpectedCompleted.join(', ')} complete, ` +
      'so its coverage record is inconsistent',
    );
  }
  const unexpectedIncomplete = incomplete.filter((arm) => !requestedSet.has(arm));
  if (unexpectedIncomplete.length > 0) {
    throw new Error(
      `${where} marks undeclared arm(s) ${unexpectedIncomplete.join(', ')} incomplete, ` +
      'so its coverage record is inconsistent',
    );
  }
  if (incomplete.length > 0) {
    throw new Error(
      `${where} records incomplete stranger arm(s) ${incomplete.join(', ')}, ` +
      'so the stranger proof did not finish',
    );
  }
  const missingCompleted = requested.filter((arm) => !completed.includes(arm));
  if (missingCompleted.length > 0) {
    throw new Error(
      `${where} does not mark requested arm(s) ${missingCompleted.join(', ')} complete, ` +
      'so the stranger proof did not finish',
    );
  }
  return { archive, arms: requested };
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
    const absent = new Error(
      `${path} does not exist on the ${EVIDENCE_REF} branch of ${repository}; ` +
      'the proof loop has not recorded this candidate, so it cannot be released',
    );
    // Absence is the one condition a caller may act on differently, and the
    // flag is what keeps that decision from being a string match on a message.
    // Unreadability deliberately carries no flag: "we could not tell" must
    // never widen a search.
    absent.evidenceAbsent = true;
    throw absent;
  }
  if (!response.ok) {
    throw new Error(
      `could not read ${path} on ${EVIDENCE_REF}: ` +
      `HTTP ${response.status} ${response.statusText}`,
    );
  }
  return response.text();
}

// The bridge for tags cut before the candidate became a main commit.
//
// Under that older scheme the proof loop judged the release branch head and the
// tag landed on the squash of that branch onto main, so the two never shared a
// sha: v0.5.44's tag commit a4ffe620 is kin#986's squash, while the preflight
// for that line judged the release-next head. Resolving the originating pull
// request's head is the only link that survives a squash, because the squash
// shares no sha, no parent and no tree with the branch it flattened.
//
// Tags cut after the rekey point at the candidate itself and never reach this
// function, because their direct key resolves. Neither does a recovery re-run
// of a pre-rekey tag, which is the reason this comment used to give and it was
// wrong: a tag run resolves its workflows AND its scripts from the tag, so
// re-running one executes that tag's own frozen release.yml and its own frozen
// copy of this file. No edit here can reach it.
//
// What keeps the bridge is a rekeyed tag whose record went absent after the
// fact. The evidence branch is append-only by construction and unprotected in
// practice, so that is reachable, and the bound below turns it into a refusal
// that names where the tag came from rather than only the file that was
// missing. The promote gate compares the sha this returns against the sha it
// is promoting, so a bridged answer can shape a refusal and can no longer
// admit one.
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
  const produced = (Array.isArray(pulls) ? pulls : []).filter(
    (pull) => pull?.merge_commit_sha === commitSha && COMMIT_SHA.test(pull?.head?.sha ?? ''),
  );
  // Bounded to the bump branch. Under the current scheme the tagged commit is
  // the candidate, so a tag reaching this function is one whose direct record
  // was absent, and every ordinary main commit is the squash of some feature
  // pull request whose head never carried a record. Without this bound the
  // bridge would happily answer about that head, which is a promote gate
  // looking somewhere nothing was ever proven. Checked against every tag this
  // bridge exists for: v0.5.44, v0.5.45 and v0.5.46 each resolve through a
  // pull request from this branch.
  const merged = produced.filter((pull) => pull?.head?.ref === BUMP_BRANCH);
  if (merged.length === 0) {
    if (produced.length === 0) {
      throw new Error(
        `no merged pull request produced ${commitSha}, so there is no candidate ` +
        'branch head whose proof records could be found; a tag minted outside ' +
        'the release train carries no evidence by construction',
      );
    }
    const refs = [
      ...new Set(produced.map((pull) => pull?.head?.ref ?? '<none>')),
    ].join(', ');
    throw new Error(
      `${commitSha} was produced by a pull request from ${refs}, not from ` +
      `${BUMP_BRANCH}; only the release train's bump branch ever carried proof ` +
      'records, so bridging anywhere else would answer about a build nobody ' +
      'proved',
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

// Find the candidate whose records this run is about, and read the first one.
//
// CANDIDATE_SHA names it directly, and that is what both live callers have: the
// tag mint knows the main commit it selected, and the promote gate knows the
// commit the tag points at, which under the current scheme is the same object.
//
// RESOLVE_FROM_COMMIT is the bridge to a pull request head, which is the only
// link that survives a squash: a squash shares no sha, no parent and no tree
// with the branch it flattened. It is not what recovers a tag cut before the
// rekey, because such a run resolves its workflows and its scripts from the
// tag and never reaches this file. It stays because a tag whose direct record
// went absent should refuse by naming where it came from, and because the
// promote gate refuses anyway unless the sha returned here is the sha it
// promotes.
//
// Order matters and so does what may trigger it. The direct key is tried first,
// and only an ABSENT record falls through to the bridge. An unreadable record,
// a transport failure or a server error still fails closed right here, because
// a check that widens its search when it cannot tell is a check that reports
// success for the wrong reason.
async function locateCandidate({ sha, resolveFromCommit, options, log }) {
  if (sha) {
    try {
      return {
        sha,
        preflightText: await fetchEvidence(sha, PREFLIGHT_RECORD, options),
      };
    } catch (error) {
      if (!error.evidenceAbsent || !resolveFromCommit) {
        throw error;
      }
      log(
        `No preflight record under ${sha}; bridging landed commit ` +
        `${resolveFromCommit} through the pull request that produced it`,
      );
    }
  }
  if (!resolveFromCommit) {
    throw new Error(
      'no candidate given; set CANDIDATE_SHA, or RESOLVE_FROM_COMMIT to bridge ' +
      'a landed commit through the pull request that produced it',
    );
  }
  const bridged = await resolveCandidateSha(resolveFromCommit, options);
  log(`Resolved candidate ${bridged} from landed commit ${resolveFromCommit}`);
  return {
    sha: bridged,
    preflightText: await fetchEvidence(bridged, PREFLIGHT_RECORD, options),
  };
}

// Two callers, one judge.
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

  let preflightText;
  ({ sha, preflightText } = await locateCandidate({
    sha,
    resolveFromCommit,
    options,
    log,
  }));

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
  const { archive, arms } = judgeStranger(parseRunEnv(strangerText), sha, archives);

  log(
    `Verified release proof artifacts for ${sha}: preflight PASS across ` +
    `${archives.length} leg(s), stranger completed ${arms.join(', ')} on archive sha256 ${archive}`,
  );
  return { sha, archives, archive };
}

// Run only when this file IS the entry point, comparing REAL paths.
//
// The usual idiom compares `import.meta.url` against
// `pathToFileURL(process.argv[1])`. Node resolves symlinks for the first and
// not the second, so invoking this file through a symlinked directory makes the
// two disagree and the gate reads nothing, judges nothing, and exits 0.
// release-tag.yml copies it to $RUNNER_TEMP and runs it from there, which is
// exactly that shape; $RUNNER_TEMP is not a symlink today, and that is the only
// reason the naive form has held. Measured on this file: run from the checkout
// it exits 1 with `::error::no repository given`, and run from a symlinked copy
// it exits 0 having written nothing at all.
//
// Unresolvable paths fall to running, not skipping. A proof gate that silently
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
    console.error(`::error::${error.message}`);
    process.exit(1);
  });
}

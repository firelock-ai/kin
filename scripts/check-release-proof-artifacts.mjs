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
// stranger actually ran. Requiring the stranger's archive to appear in a record
// the release chain wrote FOR THIS COMMIT is what links the two, rather than
// two independent existence checks, which would let a stranger run on some
// other build that merely also exists satisfy this candidate.
//
// There are two such records and the gate accepts either, because there are two
// sets of bytes a stranger can honestly run and both belong to this commit. The
// preflight's legs are the rc-build archives the machine proof judged. The
// release's own release-provenance.json names the archives release.yml built
// and published AT THE TAG, which are different bytes by construction: the tag
// build is a fresh one, so the archive a developer downloads is never a
// preflight leg. Requiring the preflight link alone therefore made the
// released-byte proof of any release unable to lift that release's own pending
// notice, which is what v0.6.7 measured on 2026-09-04: three complete arms on
// the public Linux aarch64 archive, refused as "not on these bytes".

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
// What a caller may require. 'all' is the historical contract and stays the
// default, so a caller that says nothing is judged exactly as it was before
// this mode existed. 'preflight' is the release TAG's contract: the machine
// proof must exist, and a missing first-contact record is reported as pending
// rather than thrown, because a tag that cannot be cut cannot be proven either
// and the fleet spent 2026-09-02 discovering that a stranger the account's
// weekly limit stopped is a release nobody can ship.
//
// The narrowing is exactly one condition wide. An unreadable stranger record, a
// record about another build, a record with an incomplete arm and a record on
// bytes no preflight leg judged all still refuse in BOTH modes. Only ABSENCE
// becomes pending, and only under 'preflight'. "We could not tell" must never
// widen into "proceed".
export const REQUIRE_MODES = Object.freeze(['all', 'preflight']);
// The stranger record's own statement of which driver produced it.
// bin/kin-stranger writes driver_endpoint on every run; records written before
// that key existed carry only `endpoint`, which says the same thing under a
// name a gate would have to know to look for.
export const DRIVER_ENDPOINT_FIELD = 'driver_endpoint';
export const LEGACY_DRIVER_ENDPOINT_FIELD = 'endpoint';
// The endpoint whose proof this release chain was designed around. Every other
// value is a real record and a weaker one, and the difference has to reach the
// operator rather than being flattened into "a stranger ran".
export const REFERENCE_DRIVER_ENDPOINT = 'account';
// The release train's version bump branch, and the ONLY branch whose head ever
// carried proof records. It bounds the bridge below. release-train.yml declares
// the same literal, and the authority suite pins the two together so they
// cannot drift into a bridge that resolves somewhere nothing was ever proven.
export const BUMP_BRANCH = 'automation/release-next';
// The release's own signed receipt. release.yml writes and attests it onto
// every release beside a sha256 sidecar, and it is the second record that can
// link a stranger run to this candidate's bytes.
export const PROVENANCE_ASSET = 'release-provenance.json';

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
// Which driver produced this record, said out loud.
//
// A local-model stranger and an opus stranger both write a stranger.env with
// the same keys, the same arms and the same archive sha256. Before this
// function the gate read those two records identically and logged one sentence
// for both, so a release proven by a 4-bit model on this laptop and a release
// proven by the account were indistinguishable to every downstream reader. The
// findings such a run reports are real; what does not carry over is the
// ABSENCE of findings, and a record that cannot say which driver produced it
// cannot support that distinction at all.
//
// Absence and emptiness are different answers on purpose. A record with neither
// key was written by a tool too old to say, which is a knowable historical
// fact; a record carrying `driver_endpoint=` claims to answer and does not, and
// a field that answers with nothing is worse than one that is missing, because
// only the second is obviously unanswered.
export function readDriverEndpoint(env, sha) {
  const where = evidencePath(sha, STRANGER_RECORD);
  const present = (field) =>
    Object.prototype.hasOwnProperty.call(env ?? {}, field);
  const read = (field) => {
    const raw = env[field];
    if (typeof raw !== 'string') {
      throw new Error(
        `${where} carries a non-text ${field}, so which driver produced it is unknown`,
      );
    }
    const value = raw.trim();
    if (!value) {
      throw new Error(
        `${where} carries an empty ${field}; a record that claims to name its ` +
        'driver and names nothing is not evidence about which driver ran',
      );
    }
    return value;
  };

  const hasCurrent = present(DRIVER_ENDPOINT_FIELD);
  const hasLegacy = present(LEGACY_DRIVER_ENDPOINT_FIELD);
  if (!hasCurrent && !hasLegacy) {
    // Not an error. Every record published before bin/kin-stranger learned the
    // key is shaped this way, and refusing them would rewrite history rather
    // than describe it.
    return { endpoint: null, field: null, reference: false };
  }
  const current = hasCurrent ? read(DRIVER_ENDPOINT_FIELD) : null;
  const legacy = hasLegacy ? read(LEGACY_DRIVER_ENDPOINT_FIELD) : null;
  if (current !== null && legacy !== null && current !== legacy) {
    throw new Error(
      `${where} records ${DRIVER_ENDPOINT_FIELD}=${current} and ` +
      `${LEGACY_DRIVER_ENDPOINT_FIELD}=${legacy}; the record disagrees with ` +
      'itself about which driver produced it, so neither value can be believed',
    );
  }
  const endpoint = current ?? legacy;
  return {
    endpoint,
    field: current !== null ? DRIVER_ENDPOINT_FIELD : LEGACY_DRIVER_ENDPOINT_FIELD,
    reference: endpoint === REFERENCE_DRIVER_ENDPOINT,
  };
}

// One sentence naming the driver, for a log line and for a release note.
// Written here rather than at each caller so the mint, the promotion gate and
// the release body cannot describe the same record three different ways.
export function describeDriver(driver) {
  if (!driver || driver.endpoint === null) {
    return 'by a driver the record does not name (written before the harness recorded one)';
  }
  if (driver.reference) {
    return `on the ${driver.endpoint} endpoint`;
  }
  return (
    `on the ${driver.endpoint} endpoint, which is a WEAKER stranger than the ` +
    `${REFERENCE_DRIVER_ENDPOINT} one: its findings stand, an empty finding ` +
    'list from it does not'
  );
}

// The bytes a stranger record claims, and whether it finished claiming them.
//
// Split out of judgeStranger so main() can read them without judging anything
// else: which receipt has to be fetched depends on the archive, and fetching
// the release provenance for every candidate would put a network read on the
// ordinary path that the preflight legs already answer.
export function readStrangerArchive(env, sha) {
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
  return archive;
}

// `provenance` is the release receipt, and its three states are distinct on
// purpose. null means it was never consulted, because the preflight legs
// already answered or because a caller is judging without a transport, and the
// refusal then names only the legs. A receipt with a tag means a release of
// this commit was found and read. A receipt whose tag is null means the search
// ran and no published release of this commit carries one, which a refusal has
// to say out loud rather than reporting as though only the preflight was ever
// asked.
export function judgeStranger(env, sha, archives, provenance = null) {
  const where = evidencePath(sha, STRANGER_RECORD);
  const archive = readStrangerArchive(env, sha);
  if (!archives.includes(archive) && !(provenance?.archives ?? []).includes(archive)) {
    let shipped = '';
    if (provenance) {
      shipped = provenance.tag === null
        ? `, and no published release of ${sha} carries a ${PROVENANCE_ASSET}`
        : `, and release ${provenance.tag} shipped ` +
          `(${provenance.archives.join(', ')})`;
    }
    throw new Error(
      `${where} ran archive sha256 ${archive}, which no preflight leg for ` +
      `${sha} judged (${archives.join(', ')})${shipped}; the stranger ran, ` +
      'but not on these bytes',
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
  return { archive, arms: requested, driver: readDriverEndpoint(env, sha) };
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

// One authenticated read of the GitHub API, in the shape the two readers below
// need. Written beside fetchEvidence rather than folded into it because that
// function reads a file off a branch and reports a 404 as a flag a caller may
// act on, while these read the release surface and treat every non-OK answer
// the same way: fail closed, because a release we could not read is not a
// release that agrees with us.
function apiHeaders(token, accept) {
  const headers = {
    accept,
    'user-agent': 'kin-release-proof-gate',
    'x-github-api-version': '2022-11-28',
  };
  if (token) {
    headers.authorization = `Bearer ${token}`;
  }
  return headers;
}

async function apiRead(url, what, { token, fetchImpl = fetch } = {}, accept) {
  let response;
  try {
    response = await fetchImpl(url, { headers: apiHeaders(token, accept) });
  } catch (cause) {
    throw new Error(`could not reach GitHub to ${what}: ${cause.message}`, { cause });
  }
  if (!response.ok) {
    throw new Error(
      `could not ${what}: HTTP ${response.status} ${response.statusText}`,
    );
  }
  return response;
}

const apiJson = async (url, what, options) =>
  (await apiRead(url, what, options, 'application/vnd.github+json')).json();

// Resolve a tag to the commit it names, dereferencing an annotated tag. The
// same two steps scripts/release-promotion-plan.mjs takes, and written here
// rather than imported from it: release-tag.yml runs THIS FILE ALONE out of
// $RUNNER_TEMP (`git show refs/remotes/origin/main:scripts/...` into a temp
// path), so a relative import of a sibling script would not exist there and the
// gate would fail to load on a release night.
//
// A tag that resolves to no commit sha answers null rather than throwing,
// because the caller is searching a listing for the ONE tag that names this
// candidate: a ref it cannot resolve is not that tag, and refusing the whole
// judgement over an unrelated malformed ref would make an old tag able to hold
// every future release.
async function resolveReleaseTagCommit(tag, options) {
  const base = `https://api.github.com/repos/${options.repository}`;
  const ref = await apiJson(
    `${base}/git/ref/tags/${encodeURIComponent(tag)}`,
    `resolve the tag ${tag} of ${options.repository}`,
    options,
  );
  let sha = ref?.object?.sha;
  if (ref?.object?.type === 'tag' && COMMIT_SHA.test(sha ?? '')) {
    sha = (
      await apiJson(
        `${base}/git/tags/${sha}`,
        `dereference the annotated tag ${tag} of ${options.repository}`,
        options,
      )
    )?.object?.sha;
  }
  return COMMIT_SHA.test(sha ?? '') ? sha : null;
}

// What a release's own receipt says about the bytes it shipped.
//
// Two statements have to agree before this record links anything, and they are
// independent. The release's TAG must resolve to the candidate, which is the
// caller's half. The record itself must say it is about that commit, which is
// this half: `kin.commit` at the top and `kin.commit` on every artifact. A
// release whose tag points at this candidate while its provenance describes
// another build is REFUSED rather than skipped, because a receipt that
// disagrees with the release carrying it is evidence of tampering and not of
// absence, and quietly moving on to the next release would let the disagreement
// pick the answer.
export function judgeReleaseProvenance(record, sha, tag) {
  const where = `${PROVENANCE_ASSET} on release ${tag}`;
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error(`${where} did not parse as a release provenance record`);
  }
  const commit = record?.kin?.commit;
  if (commit !== sha) {
    throw new Error(
      `${where} records commit ${commit ?? '<none>'}, not ${sha}; the release ` +
      'exists but its provenance is about a different build',
    );
  }
  const artifacts = Array.isArray(record.artifacts) ? record.artifacts : [];
  const archives = [];
  artifacts.forEach((artifact, index) => {
    const name = artifact?.artifact ?? artifact?.target ?? `artifact ${index}`;
    const built = artifact?.kin?.commit;
    if (built !== sha) {
      throw new Error(
        `${where} artifact "${name}" records commit ${built ?? '<none>'}, not ` +
        `${sha}; the record exists but that artifact is about a different build`,
      );
    }
    const archive = artifact?.archive?.sha256;
    if (typeof archive !== 'string' || !ARCHIVE_SHA.test(archive)) {
      throw new Error(
        `${where} artifact "${name}" records no archive sha256, so nothing ` +
        'can link a stranger run to the bytes it shipped',
      );
    }
    archives.push(archive);
  });
  if (archives.length === 0) {
    throw new Error(
      `${where} lists no artifacts, so it names no released bytes`,
    );
  }
  return { tag, commit, archives };
}

// Find the release of this candidate and read the bytes it shipped.
//
// Newest first, which is the order GitHub lists releases in, stopping at the
// first release whose tag resolves to the candidate. A re-tag of the same
// commit publishes a NEWER release, and the bytes on offer are that one's, so
// taking the newest match is reading the current answer rather than guessing
// between two.
//
// Draft releases are skipped because nothing about them is a claim yet, and a
// release carrying no PROVENANCE_ASSET is skipped BEFORE its tag is resolved,
// which is what keeps the cost of this search at one extra request in the
// ordinary case: the candidate's own release is at the top of the listing.
// Returning a receipt whose tag is null rather than throwing is deliberate, so
// the caller's refusal can name both the legs it checked and the release
// surface it searched.
export async function findReleaseProvenance(sha, options = {}) {
  const { repository } = options;
  const base = `https://api.github.com/repos/${repository}`;
  for (let page = 1; ; page += 1) {
    const releases = await apiJson(
      `${base}/releases?per_page=100&page=${page}`,
      `list the releases of ${repository}`,
      options,
    );
    if (!Array.isArray(releases)) {
      throw new Error(
        `release listing page ${page} of ${repository} did not come back as ` +
        `an array, so no release can be resolved to ${sha}`,
      );
    }
    for (const release of releases) {
      if (release?.draft === true) continue;
      const tag = typeof release?.tag_name === 'string' ? release.tag_name : '';
      if (!tag) continue;
      const asset = (Array.isArray(release?.assets) ? release.assets : []).find(
        (entry) => entry?.name === PROVENANCE_ASSET && typeof entry?.url === 'string',
      );
      if (!asset) continue;
      if ((await resolveReleaseTagCommit(tag, options)) !== sha) continue;
      const response = await apiRead(
        asset.url,
        `read ${PROVENANCE_ASSET} from release ${tag}`,
        options,
        'application/octet-stream',
      );
      const text = await response.text();
      let record;
      try {
        record = JSON.parse(text);
      } catch (cause) {
        throw new Error(
          `${PROVENANCE_ASSET} on release ${tag} is not valid JSON: ${cause.message}`,
          { cause },
        );
      }
      return judgeReleaseProvenance(record, sha, tag);
    }
    // A full final page is indistinguishable from a truncated listing without
    // one more request, which is the same reason buildPlan pages this way.
    if (releases.length < 100) {
      return { tag: null, commit: null, archives: [] };
    }
  }
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

// Three callers, one judge.
//
// `require` is the only thing that differs between them, and it moves exactly
// one condition: whether an ABSENT stranger record is a refusal or a reported
// pending state. Everything else about the stranger record is judged the same
// way in both modes, because the failure this gate exists to stop is a release
// claiming coverage it does not have, and a wrong record is that failure while
// a missing one is a known gap.
export async function main({
  sha = process.env.CANDIDATE_SHA,
  resolveFromCommit = process.env.RESOLVE_FROM_COMMIT,
  repository = process.env.GITHUB_REPOSITORY,
  require: requireMode = process.env.KIN_RELEASE_REQUIRE || 'all',
  env = process.env,
  fetchImpl = fetch,
  log = console.log,
} = {}) {
  if (!repository) {
    throw new Error('no repository given; set GITHUB_REPOSITORY');
  }
  // An unknown mode refuses rather than defaulting. A typo that silently fell
  // back to 'all' would look like a working gate on the day someone meant to
  // relax it, and a typo that silently fell back to 'preflight' would ship an
  // unproven release; refusing is the only answer that is wrong in neither
  // direction.
  if (!REQUIRE_MODES.includes(requireMode)) {
    throw new Error(
      `unknown require mode "${requireMode}"; this gate knows ` +
      `${REQUIRE_MODES.join(' and ')}`,
    );
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

  let strangerText;
  try {
    strangerText = await fetchEvidence(sha, STRANGER_RECORD, options);
  } catch (error) {
    // Only absence, and only under 'preflight'. `evidenceAbsent` is set by
    // fetchEvidence on a 404 alone; a transport failure and an unreadable
    // response deliberately carry no flag, so they land in the rethrow below
    // in both modes.
    if (!error.evidenceAbsent || requireMode !== 'preflight') {
      throw error;
    }
    const stranger = {
      state: 'pending',
      arms: [],
      archive: null,
      driver: { endpoint: null, field: null, reference: false },
    };
    log(
      `Verified the machine proof for ${sha}: preflight PASS across ` +
      `${archives.length} leg(s). FIRST-CONTACT PROOF IS PENDING: no ` +
      `${STRANGER_RECORD} exists under this candidate, so nothing here has ` +
      `been through the ${REQUIRED_STRANGER_ARMS.join(', ')} arms and this ` +
      'release may not be described as first-contact proven',
    );
    return { sha, archives, archive: null, stranger };
  }

  const record = parseRunEnv(strangerText);
  // Read the bytes the record names before deciding which receipt has to
  // answer for them. A stranger run on the candidate's rc-build archive is
  // linked by the preflight legs already in hand and costs no request; only a
  // run on other bytes reaches the release's own provenance, which is the
  // released-byte case this gate used to refuse outright.
  const provenance = archives.includes(readStrangerArchive(record, sha))
    ? null
    : await findReleaseProvenance(sha, options);
  const { archive, arms, driver } = judgeStranger(record, sha, archives, provenance);
  const link = provenance === null ? 'preflight' : 'release-provenance';
  const stranger = { state: 'complete', arms, archive, driver, link };

  log(
    `Verified release proof artifacts for ${sha}: preflight PASS across ` +
    `${archives.length} leg(s), stranger completed ${arms.join(', ')} on archive sha256 ${archive}, ` +
    `linked to this candidate by ${
      provenance === null
        ? 'a preflight leg'
        : `release ${provenance.tag}'s ${PROVENANCE_ASSET}`
    }, driven ${describeDriver(driver)}`,
  );
  return { sha, archives, archive, stranger };
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

#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Decides which published releases are now allowed to become GitHub Latest, and
// when a release that is still waiting has waited long enough to be worth
// alarming about.
//
// This module exists because of a shape the release rail did not have before
// 2026-09-02. The tag gate used to require first-contact proof, so a release
// either had it or did not exist; there was nothing to promote later. Now a
// candidate that clears the machine preflight is tagged and published as a
// prerelease, and the stranger record arrives afterwards, from a run that may
// be driven by a local model on a laptop. Something has to notice that arrival
// and finish the job with nobody at the button, or "non-blocking" would just
// mean "stuck one step further along".
//
// Every decision here is a pure function of what the workflow read, so each
// state the rail can reach is testable without a rail. The workflow does the
// reading, the judging and the writing; it never makes the judgement itself,
// which is the same division scripts/release-hold-alarm.mjs uses and for the
// same reason.

import { realpathSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

// The one title the alarm ever uses. It names the CONDITION, not the tag,
// because the tag moves while the condition does not and a title that moves
// opens a second issue every time it does. release-promote.yml repeats this
// string and the release authority suite asserts the two agree.
export const ALARM_TITLE = 'Release published without first-contact proof';

// The marker release.yml writes into a held release's own body. Repeated here
// so the promotion can take it back out, and asserted equal by the authority
// suite so a promoted release cannot keep claiming it is unproven.
export const PENDING_MARKER = '<!-- kin-first-contact-proof -->';

// How long a release may sit unpromoted before it is worth an issue. The
// promoter ticks four times an hour, and a stranger run on this fleet takes
// hours rather than minutes, so an alarm inside one cycle would ring on every
// healthy release. Six hours is long enough that a normal proof run finishes
// first and short enough that a forgotten one is found the same day.
export const DEFAULT_ALARM_AFTER_MINUTES = 360;

// How long a release that is ALREADY Latest may go unmeasured before it is
// worth an issue. Longer than the held threshold on purpose, because the two
// states are not equally urgent and one alarm for both would be noise.
//
// A held release is stuck: nothing reaches an installer until somebody acts,
// and six hours is the right impatience. A promoted release shipped. Its only
// gap is that nobody has measured what a first-time user meets, and under the
// rule of 2026-09-03 that gap is expected on every release the stranger has
// not reached yet. Alarming on it inside a day would ring on every healthy
// release and train every reader to skim the one issue that matters.
export const DEFAULT_PROMOTED_ALARM_AFTER_MINUTES = 1440;

const STABLE_TAG = /^v\d+\.\d+\.\d+$/;

// Which releases this promoter is even allowed to touch.
//
// Draft releases are excluded because they are not published and nothing about
// them is a claim yet. Prerelease TAGS (anything carrying a hyphen) are
// excluded because they are meant to stay prereleases; promoting one would be
// the bug, not the fix. What remains is the exact set this design creates: a
// stable tag, published, still marked prerelease.
export function selectCandidates(releases) {
  if (!Array.isArray(releases)) {
    throw new Error('the release listing did not come back as an array, so nothing can be selected from it');
  }
  return releases
    .filter((release) => release && typeof release.tag_name === 'string')
    .filter((release) => STABLE_TAG.test(release.tag_name))
    .filter((release) => release.draft !== true)
    // Either shape this chain can leave behind. Keying on the prerelease flag
    // ALONE is what went blind on 2026-09-04: once release.yml stopped holding
    // Latest, no release was ever a prerelease again, this sweep selected
    // nothing, and both the notice-stripping and the alarm went quiet with no
    // signal that they had. v0.6.6 was the first release to sit in exactly that
    // state. A notice-bearing release is this chain's business whether or not
    // it is still held.
    .filter(
      (release) =>
        release.prerelease === true ||
        (typeof release.body === 'string' && release.body.includes(PENDING_MARKER)),
    )
    .map((release) => ({
      tag: release.tag_name,
      publishedAt: release.published_at ?? null,
      // Whether THIS design held it, as opposed to a human marking a stable tag
      // as a prerelease for some other reason. A release with no marker is
      // reported and never promoted: the promoter finishes what the release
      // chain started and does not overrule a person.
      held: typeof release.body === 'string' && release.body.includes(PENDING_MARKER),
      // Already GitHub Latest. Such a release needs its notice taken out and
      // nothing else: flipping it again would move Latest onto whatever tag
      // this sweep happened to reach, which for an older release is a
      // rollback, and asserting it IS Latest afterwards would fail on any
      // release but the newest.
      promoted: release.prerelease !== true,
    }));
}

function minutesSince(iso, now) {
  if (typeof iso !== 'string' || !iso) return null;
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return null;
  return (now - then) / 60000;
}

// Turn one judgement per candidate into the four lists the workflow acts on.
//
// A judgement is `{ tag, publishedAt, held, promoted, proven, reason }`.
// `proven` true means the full gate passed for that tag's commit. `proven`
// false with a reason is every other answer, and the reason is carried
// verbatim into the alarm, because "which record was missing" is the first
// thing a reader needs and a generic "not proven" sends them to read three
// logs.
//
// A proven candidate goes to ONE of two lists, and the split is not cosmetic.
// `promote` is a release still held as a prerelease: it needs the npm ordering
// checks, the notice taken out, the flip to Latest, and the readback.
// `clearNotice` is a release that is already Latest and only carries a stale
// notice: it needs the notice taken out and nothing else. Running the promote
// path on one of those would move GitHub Latest onto whichever tag the sweep
// reached, which for anything but the newest release is a rollback.
export function planPromotion(
  judgements,
  {
    now = Date.now(),
    alarmAfterMinutes = DEFAULT_ALARM_AFTER_MINUTES,
    promotedAlarmAfterMinutes = DEFAULT_PROMOTED_ALARM_AFTER_MINUTES,
    openIssue = null,
  } = {},
) {
  const promote = [];
  const clearNotice = [];
  const waiting = [];
  const foreign = [];
  for (const judgement of judgements ?? []) {
    if (!judgement || typeof judgement.tag !== 'string' || !judgement.tag) {
      throw new Error('a promotion judgement names no tag, so it cannot be acted on');
    }
    if (!judgement.held) {
      // Not ours to promote. Reported so a stable prerelease nobody explained
      // is still visible, never acted on.
      foreign.push({ tag: judgement.tag, reason: 'this release carries no first-contact hold marker' });
      continue;
    }
    if (judgement.proven === true) {
      const entry = { tag: judgement.tag, driver: judgement.driver ?? null };
      (judgement.promoted === true ? clearNotice : promote).push(entry);
      continue;
    }
    waiting.push({
      tag: judgement.tag,
      reason: judgement.reason || 'the proof gate gave no reason',
      minutes: minutesSince(judgement.publishedAt, now),
      promoted: judgement.promoted === true,
    });
  }

  // Alarm only on a release that has waited past its own threshold. A release
  // whose publication time cannot be read counts as overdue rather than as
  // fresh: an unreadable timestamp must not buy silence.
  //
  // Two thresholds, because the two waiting states are not the same finding. A
  // held release is stuck and six hours is the right impatience. A promoted one
  // shipped and is merely unmeasured, which since 2026-09-04 is the normal
  // state of every release the stranger has not reached, so it gets a day
  // before it is worth anybody's attention.
  const overdue = waiting.filter((entry) => {
    const threshold = entry.promoted ? promotedAlarmAfterMinutes : alarmAfterMinutes;
    return entry.minutes === null || entry.minutes >= threshold;
  });
  let alarm = 'none';
  if (overdue.length > 0) {
    alarm = openIssue ? 'update' : 'open';
  } else if (openIssue && waiting.length === 0) {
    // Closed only when nothing is waiting at all, not merely when nothing is
    // overdue. A release that is inside the window is still unproven, and
    // closing on it would reopen the alarm an hour later.
    alarm = 'close';
  }
  return { promote, clearNotice, waiting, foreign, overdue, alarm };
}

// One gate refusal, rendered safely into one Markdown table cell.
//
// The reason is data: it comes from whatever the proof gate said, which is a
// sentence assembled from a record on an append-only branch. Two characters in
// it break the table it lands in, and escaping only one of them is worse than
// escaping neither.
//
// Backslash FIRST, then pipe, and both in a single pass so the escapes this
// adds cannot themselves be escaped. A reason containing `a\|b` escaped for the
// pipe alone becomes `a\\|b`, which Markdown renders as a literal backslash
// followed by an unescaped delimiter, and the row silently gains a column.
// Found by CodeQL on this pull request, not by a test, which is why the test
// beneath it now uses that exact input.
//
// Whitespace collapses last. A gate message may carry a newline, and a newline
// inside a table row ends the row.
function tableCell(text) {
  return String(text ?? '')
    .replace(/[\\|]/g, '\\$&')
    .replace(/\s+/g, ' ')
    .trim();
}

export function buildBody(
  overdue,
  {
    alarmAfterMinutes = DEFAULT_ALARM_AFTER_MINUTES,
    promotedAlarmAfterMinutes = DEFAULT_PROMOTED_ALARM_AFTER_MINUTES,
  } = {},
) {
  // The `state` column is the whole point of this table now. Before
  // 2026-09-04 every row meant the same thing, a release stuck off Latest, and
  // the prose above could say so once. Two states share this alarm today and
  // they need different things done about them, so a body that described only
  // the held one would misreport whichever row a reader happened to act on.
  const lines = [
    'These published releases have not been through the green, brown and vcs stranger arms, so none of them may be described as first-contact proven.',
    '',
    `A release still **held** off GitHub Latest is stuck and appears here after ${alarmAfterMinutes} minutes. One that is already **Latest** shipped on its machine preflight alone under the rule of 2026-09-03 and appears here after ${promotedAlarmAfterMinutes} minutes, because nobody has measured what a first-time user meets and its release body still says so.`,
    '',
    '| tag | state | waiting | what the gate said |',
    '| --- | --- | --- | --- |',
  ];
  for (const entry of overdue) {
    const waited = entry.minutes === null ? 'unknown' : `${Math.floor(entry.minutes)} min`;
    const state = entry.promoted ? 'Latest, unmeasured' : 'held, not Latest';
    lines.push(`| \`${entry.tag}\` | ${state} | ${waited} | ${tableCell(entry.reason)} |`);
  }
  lines.push(
    '',
    'To clear one: run the stranger on that candidate with all three arms and let it publish. `bin/kin-stranger` against the archive or the published npm bytes is the ordinary way to do that, and the hosted job is optional. On its next tick the promoter takes a held release to Latest, and takes the pending notice out of one that is already Latest.',
    '',
    'A local-model run is allowed and is a weaker stranger; the record says which driver produced it and every reader of this rail is told.',
    '',
    'This issue closes itself when no published release is waiting.',
  );
  return lines.join('\n');
}


// ── reading the rail ──────────────────────────────────────────────────────
//
// Everything above is a pure function of what was read. This is the reading,
// kept in the same file and behind the same direct-run guard the proof gate
// uses, so the promoter workflow stays three short shell steps and every line
// of judgement below is reachable from a test with stub transports.

const COMMIT_SHA = /^[0-9a-f]{40}$/;

// Resolve a tag to the commit it names, dereferencing an annotated tag.
// release-tag.yml writes lightweight tags, so the first read usually answers;
// the second exists because a hand-pushed annotated tag would otherwise
// resolve to the tag object's sha and key the evidence lookup at a sha no
// preflight ever judged.
export async function resolveTagCommit(tag, api) {
  const ref = await api(`/git/ref/tags/${tag}`);
  let sha = ref?.object?.sha;
  if (ref?.object?.type === 'tag') {
    sha = (await api(`/git/tags/${sha}`))?.object?.sha;
  }
  if (!COMMIT_SHA.test(sha ?? '')) {
    throw new Error(`${tag} does not resolve to a commit sha`);
  }
  return sha;
}

export async function buildPlan({
  repository,
  api,
  judge,
  alarmTitle = ALARM_TITLE,
  now = Date.now(),
  log = () => {},
}) {
  if (!repository) {
    throw new Error('no repository given; set GITHUB_REPOSITORY');
  }
  const releases = [];
  // Read the complete listing before judging any release. A full final page
  // needs one more request to distinguish it from a truncated listing.
  for (let page = 1; ; page += 1) {
    const entries = await api(`/releases?per_page=100&page=${page}`);
    if (!Array.isArray(entries)) {
      throw new Error(`release listing page ${page} did not come back as an array`);
    }
    releases.push(...entries);
    if (entries.length < 100) break;
  }
  const candidates = selectCandidates(releases);
  log(`${candidates.length} published stable release(s) are not GitHub Latest`);

  const judgements = [];
  for (const candidate of candidates) {
    const judgement = { ...candidate, sha: null, proven: false, reason: '', driver: null };
    try {
      judgement.sha = await resolveTagCommit(candidate.tag, api);
      const result = await judge(judgement.sha);
      judgement.proven = true;
      judgement.driver = result?.stranger?.driver?.endpoint ?? 'unrecorded';
    } catch (error) {
      // Every refusal is a reason to WAIT, never a reason to fail this sweep.
      // A missing stranger record is the expected state of a held release, and
      // a promoter that went red on it would page a human four times an hour
      // about a rail that is behaving exactly as designed.
      judgement.reason = error.message;
    }
    judgements.push(judgement);
  }

  const issues = await api('/issues?state=open&per_page=100&labels=release-proof');
  const openIssue =
    (Array.isArray(issues) ? issues : []).find((issue) => issue?.title === alarmTitle) ?? null;
  const plan = planPromotion(judgements, { now, openIssue });
  return { ...plan, openIssue: openIssue?.number ?? null, judgements };
}

function githubApi(repository, token, fetchImpl = fetch) {
  const headers = {
    accept: 'application/vnd.github+json',
    'user-agent': 'kin-release-promoter',
    'x-github-api-version': '2022-11-28',
  };
  if (token) {
    headers.authorization = `Bearer ${token}`;
  }
  return async (path) => {
    const response = await fetchImpl(`https://api.github.com/repos/${repository}${path}`, {
      headers,
    });
    if (!response.ok) {
      throw new Error(
        `GET ${path} failed: HTTP ${response.status} ${response.statusText}`,
      );
    }
    return response.json();
  };
}

export async function main({
  repository = process.env.GITHUB_REPOSITORY,
  token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN,
  out = process.env.KIN_PROMOTION_PLAN,
  fetchImpl = fetch,
  log = (line) => process.stderr.write(`${line}\n`),
} = {}) {
  if (!out) {
    throw new Error('no plan path given; set KIN_PROMOTION_PLAN');
  }
  const api = githubApi(repository, token, fetchImpl);
  const { main: judgeCandidate } = await import('./check-release-proof-artifacts.mjs');
  const plan = await buildPlan({
    repository,
    api,
    judge: (sha) =>
      judgeCandidate({
        sha,
        repository,
        // Spelled out rather than left to the gate's default. This is the
        // decision point that reaches GitHub Latest, so it must require
        // everything; inheriting the mode from the environment would let a
        // stray KIN_RELEASE_REQUIRE in a workflow promote a release on the
        // machine proof alone, which is the exact failure the two-tier design
        // exists to prevent.
        require: 'all',
        env: { GH_TOKEN: token },
        fetchImpl,
        log: (line) => log(`  ${line}`),
      }),
    log,
  });
  writeFileSync(out, JSON.stringify(plan, null, 2));
  log(JSON.stringify({ promote: plan.promote, waiting: plan.waiting, alarm: plan.alarm }, null, 2));
  return plan;
}

// Same real-path comparison the proof gate uses, and for the same reason: the
// naive `import.meta.url` versus `argv[1]` form disagrees when the file is
// reached through a symlinked directory, and this file would then read
// nothing, plan nothing and exit 0.
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

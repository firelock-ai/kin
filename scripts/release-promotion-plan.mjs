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
    .filter((release) => release.prerelease === true)
    .map((release) => ({
      tag: release.tag_name,
      publishedAt: release.published_at ?? null,
      // Whether THIS design held it, as opposed to a human marking a stable tag
      // as a prerelease for some other reason. A release with no marker is
      // reported and never promoted: the promoter finishes what the release
      // chain started and does not overrule a person.
      held: typeof release.body === 'string' && release.body.includes(PENDING_MARKER),
    }));
}

function minutesSince(iso, now) {
  if (typeof iso !== 'string' || !iso) return null;
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return null;
  return (now - then) / 60000;
}

// Turn one judgement per candidate into the three lists the workflow acts on.
//
// A judgement is `{ tag, publishedAt, held, proven, reason }`. `proven` true
// means the full gate passed for that tag's commit. `proven` false with a
// reason is every other answer, and the reason is carried verbatim into the
// alarm, because "which record was missing" is the first thing a reader needs
// and a generic "not proven" sends them to read three logs.
export function planPromotion(
  judgements,
  { now = Date.now(), alarmAfterMinutes = DEFAULT_ALARM_AFTER_MINUTES, openIssue = null } = {},
) {
  const promote = [];
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
      promote.push({ tag: judgement.tag, driver: judgement.driver ?? null });
      continue;
    }
    waiting.push({
      tag: judgement.tag,
      reason: judgement.reason || 'the proof gate gave no reason',
      minutes: minutesSince(judgement.publishedAt, now),
    });
  }

  // Alarm only on a release that has waited past the threshold. A release
  // whose publication time cannot be read counts as overdue rather than as
  // fresh: an unreadable timestamp must not buy silence.
  const overdue = waiting.filter(
    (entry) => entry.minutes === null || entry.minutes >= alarmAfterMinutes,
  );
  let alarm = 'none';
  if (overdue.length > 0) {
    alarm = openIssue ? 'update' : 'open';
  } else if (openIssue && waiting.length === 0) {
    // Closed only when nothing is waiting at all, not merely when nothing is
    // overdue. A release that is inside the window is still unproven, and
    // closing on it would reopen the alarm an hour later.
    alarm = 'close';
  }
  return { promote, waiting, foreign, overdue, alarm };
}

export function buildBody(overdue, { alarmAfterMinutes = DEFAULT_ALARM_AFTER_MINUTES } = {}) {
  const lines = [
    `These releases are published, are not GitHub Latest, and have been waiting more than ${alarmAfterMinutes} minutes for first-contact proof.`,
    '',
    'Each one cleared the machine preflight on its own bytes. None has been through the green, brown and vcs stranger arms, so none may be described as first-contact proven, and none will become Latest until its `stranger.env` lands under its commit on the `release-evidence` branch.',
    '',
    '| tag | waiting | what the gate said |',
    '| --- | --- | --- |',
  ];
  for (const entry of overdue) {
    const waited = entry.minutes === null ? 'unknown' : `${Math.floor(entry.minutes)} min`;
    lines.push(`| \`${entry.tag}\` | ${waited} | ${entry.reason.replace(/\|/g, '\\|')} |`);
  }
  lines.push(
    '',
    'To clear one: run the stranger on that candidate with all three arms, let it publish, and the promoter takes Latest on its next tick. A local-model run is allowed and is a weaker stranger; the record says which driver produced it and every reader of this rail is told.',
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
  const releases = await api('/releases?per_page=100');
  // A full page is a refusal, not an answer. A promoter that silently read
  // only the newest hundred releases would go quiet exactly when the list
  // grew past them, and it would look identical to a healthy rail.
  if (Array.isArray(releases) && releases.length === 100) {
    throw new Error(
      'the release listing filled a whole page, so it may be truncated; page ' +
      'it before trusting this sweep',
    );
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

#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// The three reads release-promote.yml makes of the plan it just wrote.
//
// They live in a file rather than inside YAML strings because an inline
// validator in a workflow is unreachable by `node --check` and by every test in
// this repository, and the first draft of that workflow carried a syntax error
// no gate here would have caught. A workflow step should be a line that names
// what it wants, not a program.

import { readFileSync, writeFileSync } from 'node:fs';
import process from 'node:process';

import { ALARM_TITLE, PENDING_MARKER, buildBody } from './release-promotion-plan.mjs';

function readPlan(path = process.env.KIN_PROMOTION_PLAN) {
  if (!path) {
    throw new Error('no plan path given; set KIN_PROMOTION_PLAN');
  }
  return JSON.parse(readFileSync(path, 'utf8'));
}

// One line per release to promote, tab separated, so the caller can read it
// with `while IFS=$'\t' read -r` and never word-split a value.
export function renderPromotions(plan) {
  return (plan.promote ?? [])
    .map((entry) => `${entry.tag}\t${entry.driver ?? 'unrecorded'}`)
    .join('\n');
}

// The releases that are already Latest and only carry a stale pending notice.
//
// A separate list rather than a flag on the promotion lines, because the two
// need different work done to them and a workflow reading one list would have
// to branch on a column to avoid flipping GitHub Latest onto an older tag.
// Same tab-separated shape, so the workflow reads it the same way.
export function renderNoticeClears(plan) {
  return (plan.clearNotice ?? [])
    .map((entry) => `${entry.tag}\t${entry.driver ?? 'unrecorded'}`)
    .join('\n');
}

// action, issue number and title on one tab-separated line, with the body
// written to its own file. The title travels with the decision because the
// alarm's title is the only thing that makes a second run update the first
// run's issue rather than open a second one.
//
// The number is 0 rather than empty when no issue is open, and that is not
// cosmetic. Bash treats a tab set as IFS as whitespace and COLLAPSES runs of
// it, so `open\t\tTitle` read with `IFS=$'\t' read -r action number title`
// binds number to the title and leaves title empty. Measured, not assumed. A
// never-empty field is the only shape that survives that read, and the two
// branches that use the number are only reachable when a real issue exists.
export const NO_OPEN_ISSUE = '0';

export function renderAlarm(plan, bodyPath) {
  const overdue = plan.overdue ?? [];
  writeFileSync(bodyPath, overdue.length ? buildBody(overdue) : '');
  const number = plan.openIssue ?? NO_OPEN_ISSUE;
  const action = plan.alarm ?? 'none';
  if ((action === 'update' || action === 'close') && String(number) === NO_OPEN_ISSUE) {
    throw new Error(
      `the plan asks to ${action} an alarm issue and names none, so there is ` +
      'nothing to act on',
    );
  }
  return [action, number, ALARM_TITLE].join('\t');
}

// Take the pending notice back out of a promoted release's body.
//
// A promoted release that still says its proof is pending is a false claim in
// the other direction, and the marker is what the next sweep keys on, so
// leaving it would make a promoted release look held forever.
export function stripPendingNotice(text) {
  const at = String(text).indexOf(PENDING_MARKER);
  if (at === -1) {
    return String(text);
  }
  const lines = String(text).slice(at).split('\n');
  // The marker line, then the quoted block that follows it: everything up to
  // the first line that is neither a quote nor blank. Bounded by the block this
  // release chain writes, so a body a human edited underneath keeps its text.
  let cut = 1;
  while (cut < lines.length && (lines[cut].startsWith('>') || lines[cut].trim() === '')) {
    cut += 1;
  }
  return String(text).slice(0, at) + lines.slice(cut).join('\n');
}

async function readStdin() {
  let text = '';
  for await (const chunk of process.stdin) {
    text += chunk;
  }
  return text;
}

export async function run(argv) {
  const [command, ...rest] = argv;
  switch (command) {
    case 'notice-clears':
      return `${renderNoticeClears(readPlan())}\n`;
    case 'promotions':
      return `${renderPromotions(readPlan())}\n`;
    case 'alarm': {
      const flag = rest.indexOf('--body');
      if (flag === -1 || !rest[flag + 1]) {
        throw new Error('alarm needs --body <path> to write the issue text to');
      }
      return `${renderAlarm(readPlan(), rest[flag + 1])}\n`;
    }
    case 'strip-notice':
      return stripPendingNotice(await readStdin());
    default:
      throw new Error(
        `unknown command ${JSON.stringify(command ?? '')}; this reader knows ` +
        'promotions, notice-clears, alarm and strip-notice',
      );
  }
}

if (process.argv[1] && process.argv[1].endsWith('read-promotion-plan.mjs')) {
  run(process.argv.slice(2))
    .then((out) => process.stdout.write(out))
    .catch((error) => {
      console.error(`::error::${error.message}`);
      process.exit(1);
    });
}

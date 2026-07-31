#!/usr/bin/env node

// resolve-release-intent.mjs — resolve the SemVer intent for the next Kin
// release from immutable evidence only.
//
// The intent is read from `Kin-Release-Intent:` git trailers on the
// first-parent commits between the prior stable tag and the release head.
// Pull-request labels and dispatch payloads are deliberately ignored: both stay
// editable after a merge, so a later scheduled run could resolve a lower bump
// than an earlier one and quietly rewrite a prepared minor or major release
// back to a patch. A commit message cannot be edited once it is on protected
// main, so the same range always resolves to the same intent.
//
// The trailer reaches the commit through the pull-request body, which the
// repository's squash-only PR_TITLE + PR_BODY merge policy copies verbatim into
// the squash message. The release train asserts that policy before trusting
// this resolution.
//
// Absent evidence means `patch`. The highest intent in the range wins, and the
// range only grows, so the resolution is monotone by construction.

import fs from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const TRAILER_KEY = 'Kin-Release-Intent';
const INTENTS = ['patch', 'minor', 'major'];
const RANK = new Map(INTENTS.map((intent, index) => [intent, index]));
// Every line that mentions the key at all, so a mention that git does not parse
// as a trailer (wrong position, wrong separator) is caught rather than ignored.
const RAW_MENTION = /^[ \t]*Kin-Release-Intent\b[^\r\n]*$/gim;
const PARSED_TRAILER = /^Kin-Release-Intent:\s*(\S+)\s*$/i;

function parseArgs(argv) {
  const args = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key.startsWith('--') || value === undefined || value.startsWith('--')) {
      throw new Error(`invalid argument sequence near ${key}`);
    }
    args.set(key.slice(2), value);
    index += 1;
  }
  return args;
}

function git(args, options = {}) {
  return execFileSync('git', ['--no-replace-objects', ...args], {
    cwd: options.root,
    encoding: 'utf8',
    input: options.input,
  });
}

function commitIntent(root, commit) {
  const message = git(['show', '-s', '--format=%B', commit], { root });
  const mentions = message.match(RAW_MENTION) ?? [];
  const parsed = execFileSync('git', ['interpret-trailers', '--parse'], {
    cwd: root,
    encoding: 'utf8',
    input: message,
  })
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  const intents = parsed.flatMap((line) => {
    const match = PARSED_TRAILER.exec(line);
    return match ? [match[1].toLowerCase()] : [];
  });

  if (mentions.length !== intents.length) {
    throw new Error(`${commit} has malformed or non-footer ${TRAILER_KEY} evidence`);
  }
  if (intents.length > 1) {
    throw new Error(`${commit} has duplicate ${TRAILER_KEY} trailers`);
  }
  if (intents.length === 0) return null;

  const intent = intents[0];
  if (!RANK.has(intent)) {
    throw new Error(`${commit} has invalid ${TRAILER_KEY}: ${intent}`);
  }
  return intent;
}

export function resolveReleaseIntent({ root = process.cwd(), baseRef, headRef = 'HEAD' }) {
  const ancestor = spawnSync(
    'git',
    ['--no-replace-objects', 'merge-base', '--is-ancestor', baseRef, headRef],
    { cwd: root, encoding: 'utf8' },
  );
  if (ancestor.status !== 0) {
    throw new Error(`${baseRef} is not an ancestor of ${headRef}`);
  }

  const commits = git(
    ['rev-list', '--first-parent', '--reverse', `${baseRef}..${headRef}`],
    { root },
  )
    .split('\n')
    .map((commit) => commit.trim())
    .filter(Boolean);

  const evidence = [];
  let intent = 'patch';
  for (const commit of commits) {
    const found = commitIntent(root, commit);
    if (found === null) continue;
    evidence.push({ commit, intent: found });
    if (RANK.get(found) > RANK.get(intent)) intent = found;
  }
  return { baseRef, headRef, intent, evidence };
}

function emitOutputs(result) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  fs.appendFileSync(
    file,
    [`intent=${result.intent}`, `evidence_json=${JSON.stringify(result.evidence)}`, ''].join('\n'),
  );
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const baseRef = args.get('base-ref');
  const headRef = args.get('head-ref') ?? 'HEAD';
  if (!baseRef) throw new Error('--base-ref is required');
  const result = resolveReleaseIntent({ baseRef, headRef });
  emitOutputs(result);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  fs.realpathSync(fileURLToPath(import.meta.url)) === fs.realpathSync(process.argv[1]);

if (invokedDirectly) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`resolve-release-intent: ${error.message}\n`);
    process.exitCode = 1;
  }
}

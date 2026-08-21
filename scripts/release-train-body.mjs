#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

/**
 * Merge the release train's own text into a release pull-request body without
 * disturbing what an operator wrote around it.
 *
 * This repository squashes with the pull-request body as the commit message,
 * and the merge queue mints that message when the entry is admitted. So the
 * release body is not a description of the release, it is the release's
 * permanent commit message, and every disclosure the release doctrine requires
 * lives in it. The train reconciles on a four-times-an-hour schedule and used
 * to rewrite the whole body to its own generic line on every cycle, which
 * discards anything a human added and, if a cycle lands between the edit and
 * queue admission, ships a release whose message carries none of it.
 *
 * The train therefore owns one delimited region and nothing else. Text above
 * or below the markers survives byte for byte, including its line endings. A
 * body with no region gets one at the top; a body whose markers are missing a
 * partner or repeat is refused rather than guessed at, because a wrong guess
 * here destroys the operator text this exists to protect.
 */

import fs from 'node:fs';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const BEGIN_MARKER = '<!-- kin-release-train:begin -->';
export const END_MARKER = '<!-- kin-release-train:end -->';

/** Wrap the train's text in its markers. */
export function renderRegion(region) {
  const text = String(region).replace(/^\n+/, '').replace(/\s+$/, '');
  return `${BEGIN_MARKER}\n${text}\n${END_MARKER}`;
}

function countOccurrences(haystack, needle) {
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index >= 0) {
    count += 1;
    index = haystack.indexOf(needle, index + needle.length);
  }
  return count;
}

/**
 * Merge `region` into `current`, returning what happened and the body to write.
 *
 * `changed` is the caller's whole decision: false means do not touch the body
 * at all, which covers both an already-current region and a body this function
 * refuses to rewrite.
 */
export function mergeBody({ current = '', region }) {
  if (typeof region !== 'string' || region.trim() === '') {
    throw new Error('release train body region must be non-empty text');
  }
  const body = typeof current === 'string' ? current : '';
  const rendered = renderRegion(region);
  const begins = countOccurrences(body, BEGIN_MARKER);
  const ends = countOccurrences(body, END_MARKER);

  if (begins === 0 && ends === 0) {
    // A body the train has never marked. The legacy shape is the train's own
    // generic line at the top followed by whatever an operator appended, and
    // absorbing that exact line into the region is not a loss of anyone's
    // text: the train wrote it. Anything that merely resembles it is operator
    // text and stays where it is.
    const legacy = String(region).trim();
    let rest = body;
    let status = 'region-added';
    if (rest.startsWith(legacy)) {
      rest = rest.slice(legacy.length).replace(/^[\r\n]+/, '');
      status = 'legacy-region-adopted';
    }
    const merged = rest.trim() === '' ? rendered : `${rendered}\n\n${rest}`;
    return {
      changed: merged !== body,
      status,
      body: merged,
      detail:
        status === 'legacy-region-adopted'
          ? 'the train-authored opening line became the delimited region'
          : 'the delimited region was added above the existing body',
    };
  }

  if (begins !== 1 || ends !== 1) {
    return {
      changed: false,
      status: 'unmergeable',
      body: null,
      detail: `body carries ${begins} begin and ${ends} end release-train markers, so the region the train owns is ambiguous`,
    };
  }

  const begin = body.indexOf(BEGIN_MARKER);
  const end = body.indexOf(END_MARKER);
  if (end < begin) {
    return {
      changed: false,
      status: 'unmergeable',
      body: null,
      detail: 'body carries the release-train end marker before its begin marker',
    };
  }

  const merged = body.slice(0, begin) + rendered + body.slice(end + END_MARKER.length);
  return {
    changed: merged !== body,
    status: 'region-replaced',
    body: merged,
    detail:
      merged === body
        ? 'the delimited region already carries this text'
        : 'the delimited region was replaced and nothing outside it moved',
  };
}

function readOption(argv, name) {
  const index = argv.indexOf(name);
  if (index < 0) {
    return null;
  }
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) {
    throw new Error(`${name} needs a file path`);
  }
  return value;
}

function main(argv) {
  const regionPath = readOption(argv, '--region');
  const currentJsonPath = readOption(argv, '--current-json');
  const outPath = readOption(argv, '--out');
  if (!regionPath || !outPath) {
    throw new Error(
      'usage: release-train-body.mjs --region <file> --out <file> [--current-json <file>]',
    );
  }

  let current = '';
  if (currentJsonPath) {
    // The body arrives as JSON rather than as raw text so no shell or jq step
    // can add, strip, or re-encode a byte of what the operator wrote.
    const parsed = JSON.parse(fs.readFileSync(currentJsonPath, 'utf8'));
    if (typeof parsed.body !== 'string') {
      throw new Error('pull-request JSON carries no body string, so the current body was never read');
    }
    current = parsed.body;
  }

  const result = mergeBody({
    current,
    region: fs.readFileSync(regionPath, 'utf8'),
  });
  if (result.body !== null) {
    fs.writeFileSync(outPath, result.body);
  }
  process.stdout.write(
    `${JSON.stringify({
      changed: result.changed,
      status: result.status,
      detail: result.detail,
    })}\n`,
  );
}

/**
 * Whether this file is the program being run rather than an imported module.
 *
 * Compare resolved paths, not the URL against a raw argv string: a runner that
 * copies this script under a symlinked directory (every macOS $TMPDIR is one)
 * makes those two spellings differ, and the mismatch is silent. The script
 * would read its arguments, write nothing, and exit 0, which the caller then
 * reads as an empty merge result.
 */
function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) {
    return false;
  }
  try {
    return fs.realpathSync(entry) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`::error::${error.message}\n`);
    process.exit(1);
  }
}

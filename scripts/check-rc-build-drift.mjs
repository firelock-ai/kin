#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// rc-build.yml builds release-candidate archives from release.yml's build job.
// It is a copy, because the alternative was refactoring the one workflow whose
// mistakes cannot be repaired after the fact: a tag run resolves its workflows
// from the tag. A copy that nothing checks is worse than no copy, because it
// keeps reporting success while the thing it mirrors moves. This is the check
// that makes the copy hold.
//
// It does not compare the two files loosely. It rebuilds what rc-build.yml's
// shared step block MUST be, by taking release.yml's build steps, dropping the
// step groups rc-build.yml deliberately omits, and applying the exact textual
// deltas declared below. The result must equal rc-build.yml byte for byte. A
// step added to release.yml, a step edited in either file, a reordered step, or
// a delta whose anchor no longer exists all fail here and name what moved.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const RELEASE_WORKFLOW = ".github/workflows/release.yml";
export const RC_WORKFLOW = ".github/workflows/rc-build.yml";

// The six macOS signing and notarization steps. rc-build.yml declares no
// environment and reads no secret, on purpose: a workflow_dispatch can target
// branch-controlled workflow code, which must never reach the Apple or
// package-publish credentials. Without those credentials these steps have
// nothing to do, so they are absent rather than inert.
//
// A seventh entry, "Cache Cargo registry and build artifacts", used to sit at
// the head of this list. release.yml no longer carries that step: it never
// restored, because a tag-scoped cache entry is unreadable from the next tag,
// and a restore that did work would assemble published bytes partly from cache
// contents nobody reviewed. Both workflows now compile cold, so the difference
// this entry described no longer exists and listing it here would report the
// omission list as stale.
export const OMITTED_STEPS = [
  "Resolve macOS signing credential availability",
  "Import code signing certificate (macOS)",
  "Sign macOS binaries",
  "Stage signed binaries for notarization (macOS)",
  "Notarize macOS binaries (notarytool)",
  "Upload signed binaries for Linux notarization",
];

// Steps rc-build.yml has and release.yml does not. Both exist because a
// candidate has no tag: one resolves the version a tag would have supplied, the
// other reports which bytes the run produced so a consumer can find them.
export const ADDED_STEPS = [
  "Resolve the release-candidate identity",
  "Summarize the candidate archives",
];

// Every difference inside a shared step, as an exact anchor and its
// replacement. Each anchor must appear exactly once in release.yml's build
// steps; an anchor that stops matching is itself drift and fails below.
export const DELTAS = [
  {
    label: "archive-docs-version-windows",
    from: `          node scripts/write-release-archive-docs.mjs "$env:ARTIFACT" "$env:TARGET" ($env:GITHUB_REF_NAME -replace '^v', '')
`,
    to: `          node scripts/write-release-archive-docs.mjs "$env:ARTIFACT" "$env:TARGET" $env:RC_VERSION
`,
  },
  {
    label: "archive-docs-version",
    from: `          node scripts/write-release-archive-docs.mjs "$ARTIFACT" "$TARGET" "\${GITHUB_REF_NAME#v}"
`,
    to: `          node scripts/write-release-archive-docs.mjs "$ARTIFACT" "$TARGET" "$RC_VERSION"
`,
  },
  {
    label: "apt",
    from: `        run: sudo apt-get update && sudo apt-get install -y musl-tools
`,
    to: `        # DELTA(apt): bounded through the shared helper. An unbounded apt call
        # holds a job until the runner timeout when a mirror stalls (FIR-2391).
        run: ./scripts/ci-apt-install.sh musl-tools
`,
  },
  {
    label: "notifier-version",
    from: `            "\${GITHUB_REF_NAME#v}"
`,
    to: `            "$RC_VERSION"
`,
  },
  {
    label: "provenance-version",
    from: `
          const expectedVersion = process.env.GITHUB_REF_NAME.replace(/^v/, "");`,
    to: `
          // DELTA(version): a candidate has no tag, so the version both static
          // build identities must agree on is the workspace package version the
          // job resolved. The cross-check between kin and kin-daemon is intact;
          // what a candidate cannot assert is agreement with a tag name.
          const expectedVersion = process.env.RC_VERSION;`,
  },
  {
    label: "provenance-tag",
    from: `            schema_version: 2,
            release_tag: process.env.GITHUB_REF_NAME,
            artifact,`,
    to: `            schema_version: 2,
            // DELTA(identity): a candidate manifest names the ref and sha it was
            // built from. It carries no release_tag, so it can never be mistaken
            // for a published release's provenance.
            release_candidate: {
              ref: process.env.RC_REF,
              version: process.env.RC_VERSION,
            },
            artifact,`,
  },
  {
    label: "upload",
    from: `      - name: Upload artifact
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.0
        with:
          name: \${{ matrix.artifact }}
          path: |`,
    to: `      - name: Upload artifact
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.0
        with:
          name: \${{ matrix.artifact }}
          # DELTA(retention): a candidate is short-lived scratch, and an empty
          # upload must fail here rather than surface as a missing archive in
          # whatever consumes the run.
          retention-days: 7
          if-no-files-found: error
          path: |`,
  },
];

// rc-build.yml declares skip_vfs on every row. Three shared steps read it, and
// release.yml gets the key from the windows row rc-build.yml does not carry, so
// without it actionlint rejects those steps against a matrix type with no such
// property. The value matches what those steps already saw on every row here.
const RC_ONLY_MATRIX_KEYS = ["skip_vfs"];

export function buildJobBody(text, workflow) {
  const lines = text.split("\n");
  const start = lines.findIndex((line) => line === "  build:");
  if (start === -1) throw new Error(`${workflow}: no build job`);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^  [A-Za-z_][A-Za-z0-9_-]*:\s*$/.test(lines[i])) {
      end = i;
      break;
    }
  }
  // The comment block introducing the next job sits above that job's key and
  // documents it, not the last step of this one. Without this the release
  // build job's final step absorbs notarize_linux's header and can never
  // match a candidate step that has no such neighbour.
  while (end > start && /^ {2}#/.test(lines[end - 1])) end -= 1;
  return lines.slice(start, end).join("\n");
}

// A step is its "- name:" line, its body, and the run of comment lines directly
// above it. Both workflows document a step in the comment block that precedes
// it, so a comment belongs to the step it describes rather than to the one
// before. Trailing blank lines are trimmed, so where a blank line falls between
// steps is not treated as drift.
export function splitSteps(jobBody, workflow) {
  const lines = jobBody.split("\n");
  const starts = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (!lines[i].startsWith("      - name: ")) continue;
    let start = i;
    while (start > 0 && /^ {6}#/.test(lines[start - 1])) start -= 1;
    starts.push({ start, nameLine: i });
  }
  if (starts.length === 0) throw new Error(`${workflow}: build job has no steps`);
  return starts.map(({ start, nameLine }, index) => {
    const end = index + 1 < starts.length ? starts[index + 1].start : lines.length;
    return {
      name: lines[nameLine].slice("      - name: ".length),
      body: lines.slice(start, end).join("\n").replace(/\s+$/, ""),
    };
  });
}

export function matrixRows(jobBody, workflow) {
  const lines = jobBody.split("\n");
  const start = lines.findIndex((line) => line === "        include:");
  if (start === -1) throw new Error(`${workflow}: build job has no matrix include`);
  const rows = [];
  let current = null;
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^\s*#/.test(line) || line.trim() === "") continue;
    if (line.startsWith("          - ")) {
      current = [`${line.slice("          - ".length)}`];
      rows.push(current);
      continue;
    }
    if (line.startsWith("            ")) {
      if (!current) throw new Error(`${workflow}: matrix key before any row`);
      current.push(line.trim());
      continue;
    }
    break;
  }
  return new Map(
    rows.map((row) => {
      const artifact = row.find((entry) => entry.startsWith("artifact:"));
      if (!artifact) throw new Error(`${workflow}: a matrix row names no artifact`);
      return [artifact.slice("artifact:".length).trim(), row];
    })
  );
}

export function check(releaseText, rcText) {
  const problems = [];
  const releaseJob = buildJobBody(releaseText, RELEASE_WORKFLOW);
  const rcJob = buildJobBody(rcText, RC_WORKFLOW);
  const releaseSteps = splitSteps(releaseJob, RELEASE_WORKFLOW);
  const rcSteps = splitSteps(rcJob, RC_WORKFLOW);
  const releaseNames = releaseSteps.map((step) => step.name);
  const rcNames = rcSteps.map((step) => step.name);

  for (const name of OMITTED_STEPS) {
    if (!releaseNames.includes(name)) {
      problems.push(`omitted step "${name}" no longer exists in ${RELEASE_WORKFLOW}; the omission list is stale`);
    }
    if (rcNames.includes(name)) {
      problems.push(`step "${name}" is listed as omitted but ${RC_WORKFLOW} carries it`);
    }
  }
  for (const name of ADDED_STEPS) {
    if (!rcNames.includes(name)) {
      problems.push(`added step "${name}" is missing from ${RC_WORKFLOW}`);
    }
    if (releaseNames.includes(name)) {
      problems.push(`step "${name}" is listed as candidate-only but ${RELEASE_WORKFLOW} carries it too`);
    }
  }

  let expected = releaseSteps
    .filter((step) => !OMITTED_STEPS.includes(step.name))
    .map((step) => step.body)
    .join("\n");
  for (const delta of DELTAS) {
    const seen = expected.split(delta.from).length - 1;
    if (seen !== 1) {
      problems.push(`delta "${delta.label}" matched ${seen} times in ${RELEASE_WORKFLOW}'s shared steps, expected exactly 1`);
      continue;
    }
    expected = expected.replace(delta.from, delta.to);
  }
  const actual = rcSteps
    .filter((step) => !ADDED_STEPS.includes(step.name))
    .map((step) => step.body)
    .join("\n");

  if (expected !== actual) {
    const expectedLines = expected.split("\n");
    const actualLines = actual.split("\n");
    let i = 0;
    while (i < expectedLines.length && i < actualLines.length && expectedLines[i] === actualLines[i]) i += 1;
    let step = "(before any step)";
    for (let back = i; back >= 0; back -= 1) {
      const match = /^ {6}- name: (.*)$/.exec(actualLines[back] ?? expectedLines[back] ?? "");
      if (match) { step = match[1]; break; }
    }
    problems.push(
      `${RC_WORKFLOW} no longer mirrors ${RELEASE_WORKFLOW}'s build steps.\n` +
        `  first difference in step "${step}"\n` +
        `  release.yml (with deltas applied): ${JSON.stringify(expectedLines[i] ?? "(end of block)")}\n` +
        `  rc-build.yml:                      ${JSON.stringify(actualLines[i] ?? "(end of block)")}`
    );
  }

  const releaseRows = matrixRows(releaseJob, RELEASE_WORKFLOW);
  const rcRows = matrixRows(rcJob, RC_WORKFLOW);
  for (const [artifact, rcRow] of rcRows) {
    const releaseRow = releaseRows.get(artifact);
    if (!releaseRow) {
      problems.push(`${RC_WORKFLOW} builds ${artifact}, which ${RELEASE_WORKFLOW} does not publish`);
      continue;
    }
    const trimmed = rcRow.filter((entry) => !RC_ONLY_MATRIX_KEYS.some((key) => entry.startsWith(`${key}:`)));
    if (JSON.stringify(trimmed) !== JSON.stringify(releaseRow)) {
      problems.push(
        `${RC_WORKFLOW}'s ${artifact} matrix row differs from ${RELEASE_WORKFLOW}'s.\n` +
          `  release.yml:  ${JSON.stringify(releaseRow)}\n` +
          `  rc-build.yml: ${JSON.stringify(trimmed)}`
      );
    }
  }
  return problems;
}

export function checkFiles(root = ROOT) {
  return check(
    readFileSync(join(root, RELEASE_WORKFLOW), "utf8"),
    readFileSync(join(root, RC_WORKFLOW), "utf8")
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const problems = checkFiles();
  if (problems.length > 0) {
    for (const problem of problems) {
      console.error(`::error::${problem}`);
    }
    console.error(
      `\n${RC_WORKFLOW} mirrors ${RELEASE_WORKFLOW}'s build job so release-candidate archives are built by the release's own steps.\n` +
        `Re-copy the changed step into ${RC_WORKFLOW}, or record the difference in DELTAS in ${"scripts/check-rc-build-drift.mjs"}.`
    );
    process.exit(1);
  }
  console.log(
    `${RC_WORKFLOW} mirrors ${RELEASE_WORKFLOW}'s build job: ` +
      `${OMITTED_STEPS.length} steps omitted, ${ADDED_STEPS.length} candidate-only, ${DELTAS.length} deltas applied.`
  );
}

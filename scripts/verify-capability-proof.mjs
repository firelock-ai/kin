#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// The portable half of the Public Install Proof's capability contract, so it
// can run against a binary built from a branch instead of only against a
// published release.
//
// The proof is the best gate Kin has and it had the worst feedback loop. It
// installs from get.kinlab.dev with no checkout and no secrets, which is the
// point, and it therefore runs only once a tag exists. A change that breaks it
// lands green, ships, and fences the release it ships in. That is what happened
// to v0.5.18: a readiness classifier started reporting `pending` on a host that
// could never make progress, the proof caught it correctly at tag time, and the
// tag could not be repaired because a tag run resolves its workflows from the
// tag.
//
// What moves here is only what a branch build can honestly assert. Release
// provenance stays in the proof: a canary binary is not the release binary and
// must never claim to prove anything about one. What is left is the part that
// broke, and it is the part that needs no release at all.

import { readFileSync } from "node:fs";

// Every check id the install proof requires by name. A rename or a removal
// makes the proof fail at tag time with nothing on main to warn about it, so the
// canary requires the same ids to be present. The expected STATUS per id is
// deliberately not copied: a canary host is not an installed host, and asserting
// a status this environment cannot produce would fail for the environment rather
// than for the change. Presence is what a rename breaks, and presence is what is
// portable. The release authority suite pins this list against the proof's own
// inline table, so the two cannot drift.
export const REQUIRED_CHECK_IDS = [
  "kin_binary",
  "kin_daemon_binary",
  "daemon_running",
  "repo_init",
  "shell_path",
  "setup_ledger",
  "registry_authority",
  "vfs_projection",
  "mcp_client_claude",
  "mcp_client_cursor",
  "mcp_client_codex",
  "mcp_client_gemini",
  "mcp_client_windsurf",
  "mcp_client_antigravity",
  "mcp_client_antigravity_workspace",
  "semantic_query_readiness",
];

export const READINESS_ID = "semantic_query_readiness";

export class CapabilityProofError extends Error {}

function fail(message) {
  throw new CapabilityProofError(message);
}

// Byte-for-byte the rule the install proof applies to every health report it
// reads. The aggregate is not an independent opinion: it is a function of the
// checks, and a report whose summary disagrees with its own contents is the
// failure mode that hides every other one.
export function validateHealthReport(report, reportPath) {
  if (!report || typeof report !== "object" || !Array.isArray(report.checks)) {
    fail(`${reportPath}: checks is missing or malformed`);
  }
  const checks = new Map(report.checks.map((check) => [check.id, check]));
  if (checks.size !== report.checks.length) {
    fail(`${reportPath}: duplicate health-check ids are not authoritative`);
  }
  const expectedHealthy = !report.checks.some(
    (check) =>
      check.status === "missing" ||
      check.status === "misconfigured" ||
      (check.id === READINESS_ID && check.status === "stale"),
  );
  if (report.healthy !== expectedHealthy) {
    fail(
      `${reportPath}: aggregate healthy=${report.healthy} disagrees with checks; ` +
        `expected ${expectedHealthy}`,
    );
  }
  return checks;
}

export function assertRequiredChecksPresent(checks, reportPath) {
  const absent = REQUIRED_CHECK_IDS.filter((id) => !checks.has(id));
  if (absent.length > 0) {
    fail(
      `${reportPath}: the install proof requires health checks this build does not ` +
        `report: ${absent.join(", ")}. A renamed or removed check fails the proof at ` +
        "tag time, where no fix on main can reach it.",
    );
  }
}

export function assertNoHardFailures(report, reportPath) {
  const hard = report.checks.filter(
    (check) => check.status === "missing" || check.status === "misconfigured",
  );
  if (hard.length > 0) {
    fail(
      `${reportPath}: hard failures: ${hard.map((check) => check.id).join(", ")}`,
    );
  }
}

// The whole status vocabulary `HealthStatus` serializes, in snake_case. The
// proof compares these as strings, so a variant renamed on the Rust side stops
// matching silently and every comparison the proof makes goes quietly false.
// Reading a status outside this set is that rename, caught before a tag exists.
export const HEALTH_STATUSES = [
  "healthy",
  "missing",
  "stale",
  "misconfigured",
  "pending",
  "degraded",
  "unsupported",
];

// What `pending` is allowed to mean.
//
// Pending must mean work is actually moving toward ready. Where nothing can
// move, `pending` is a claim the host will never make good on, and it is the
// exact lie that fenced v0.5.18: on a runner the readiness check sat pending
// forever, the proof required healthy, and every cut after it failed the same
// way. The judgement is made against the coverage counters rather than against
// the readiness field's own word for itself, because a classifier that lies is
// not a witness to its own honesty.
//
// Coverage carries exactly `state`, `source`, `reason`, `indexed`, `pending`,
// and `total`. Nothing here reads a field the daemon does not publish.
//
//   settled      observed, total above zero, pending zero, indexed equal to
//                total. The proof's post-embed assertion requires `healthy`
//                here, so anything else fails the release gate at tag time.
//   nothing      observed with a total of zero. There is no work that could
//                ever resolve a `pending`, which is the structural-zero
//                honesty class sitting in the release gate.
//   working      observed with work outstanding. `pending` is correct, and so
//                is `healthy` when the pass finished between the two reads.
//   unobserved   a window rather than a shortfall. Conclude nothing.
export function assertReadinessCoherent(checks, coverage, reportPath) {
  const readiness = checks.get(READINESS_ID)?.status;
  if (readiness === undefined) {
    fail(`${reportPath}: ${READINESS_ID} is missing`);
  }
  if (!HEALTH_STATUSES.includes(readiness)) {
    fail(
      `${reportPath}: ${READINESS_ID} reports ${readiness}, which is not a status ` +
        "this build's health vocabulary defines. The proof compares these as " +
        "strings, so a renamed variant makes every comparison quietly false.",
    );
  }
  const state = coverage?.state;
  if (state === undefined) {
    fail(
      `${reportPath}: embedding coverage carries no state, so readiness cannot be ` +
        "judged against it. An unread coverage is not an empty one.",
    );
  }

  if (state !== "observed") {
    return readiness;
  }

  if (!Number.isInteger(coverage.total)) {
    fail(
      `${reportPath}: observed embedding coverage carries no whole total ` +
        `(${JSON.stringify(coverage)}), so it observed nothing it can be held to.`,
    );
  }

  if (coverage.total === 0) {
    if (readiness === "pending") {
      fail(
        `${reportPath}: ${READINESS_ID} is pending against a store with nothing to ` +
          "embed, so no amount of waiting resolves it. Pending has to mean work is " +
          "moving toward ready; where nothing can move, say unsupported.",
      );
    }
    return readiness;
  }

  const settled = coverage.pending === 0 && coverage.indexed === coverage.total;
  if (settled && readiness !== "healthy") {
    fail(
      `${reportPath}: ${READINESS_ID} is ${readiness} on a settled store ` +
        `(${JSON.stringify(coverage)}). The install proof requires healthy here, so ` +
        "this fails the release gate at tag time, where no fix on main can reach it.",
    );
  }
  return readiness;
}

export function verifyReport(report, coverage, reportPath) {
  const checks = validateHealthReport(report, reportPath);
  assertRequiredChecksPresent(checks, reportPath);
  assertNoHardFailures(report, reportPath);
  const readiness = assertReadinessCoherent(checks, coverage, reportPath);
  return { checks, readiness };
}

// Which of the coverage regimes a capture was judged under. An `unobserved`
// coverage is a window the proof settles over rather than asserts into, so
// nothing about readiness follows from it. That tolerance is correct and it is
// also the one way this check could pass while proving nothing, which is why the
// regime is printed and why `--require-observed` exists.
export function coverageRegime(coverage) {
  if (coverage?.state !== "observed") return "unobserved";
  if (!Number.isInteger(coverage.total)) return "unobserved";
  if (coverage.total === 0) return "nothing-to-embed";
  return coverage.pending === 0 && coverage.indexed === coverage.total
    ? "settled"
    : "working";
}

function parseArgs(argv) {
  const args = { reports: [], status: null, requireObserved: false };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--report") args.reports.push(argv[++index]);
    else if (flag === "--status") args.status = argv[++index];
    else if (flag === "--require-observed") args.requireObserved = true;
    else throw new Error(`unknown argument: ${flag}`);
  }
  if (args.reports.length === 0) throw new Error("at least one --report <path> is required");
  if (!args.status) throw new Error("--status <path> is required");
  return args;
}

function main(argv) {
  const args = parseArgs(argv);
  const status = JSON.parse(readFileSync(args.status, "utf8"));
  const coverage = status.embedding_coverage;
  const regime = coverageRegime(coverage);
  if (args.requireObserved && regime === "unobserved") {
    throw new Error(
      "embedding coverage was never observed, so this run judged readiness " +
        "against nothing and proved nothing. A check that cannot fail is not " +
        `evidence. Coverage read: ${JSON.stringify(coverage)}`,
    );
  }
  for (const reportPath of args.reports) {
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    const { readiness } = verifyReport(report, coverage, reportPath);
    process.stdout.write(
      `${reportPath}: capability contract holds under the ${regime} regime, ` +
        `${READINESS_ID}=${readiness}\n`,
    );
  }
  process.stdout.write(
    `coverage regime: ${regime}\ncoverage: ${JSON.stringify(coverage)}\n` +
      "the branch build satisfies the portable half of the install proof's " +
      "capability contract\n",
  );
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}

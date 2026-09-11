#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Decides whether a held release train has been quiet for long enough to be
// worth alarming about. The decision is a pure function of the recent hold
// markers and the currently open alarm issue, so it can be tested against every
// state the rail reaches without running a rail. The workflow around it does
// the reading and the writing and never makes the judgement itself.
//
// A hold is a correct decision. The failure this exists to prevent is a hold
// nobody can see: the train concluded success while declining to mint, carried
// its reason in a log notice, and sat for roughly twenty hours with nine merged
// pull requests behind it. Concluding is not reporting.

import { readFileSync } from "node:fs";

// The one title the alarm ever uses. It carries no tag and no count, because
// the tag moves while the condition does not, and a title that moves opens a
// second issue every time it does. The release train workflow and the release
// sentinel prompt both repeat this string, and the release authority suite
// asserts all three agree, so a rename cannot land in one of them alone.
export const ALARM_TITLE = "Release rail is held with releasable drift";

// Roughly an hour of a train that ticks at 7, 22, 37, and 52 past the hour. Low
// enough that a captain hears about a real hold inside one coffee, high enough
// that a single cycle spent mid-reconcile never rings.
export const DEFAULT_THRESHOLD = 4;

export const MARKER_SCHEMA = "kin.release-hold.v1";

// The one workflow state in which a staged hold is work in flight rather than a
// rail standing still. Read from the Actions API by the job that runs this
// script, and passed in, so this file stays a pure function over its inputs.
export const CUT_STATE_ACTIVE = "active";

// A marker this reader cannot vouch for is not a quiet rail and it is not a
// held one either. It breaks the streak and it never closes an open alarm,
// because an unreadable observation and an observed all-clear are different
// findings and only one of them is safe to act on.
function classify(marker, cutState) {
  if (!marker || typeof marker !== "object") return "unreadable";
  if (marker.unreadable === true) return "unreadable";
  if (marker.schema !== MARKER_SCHEMA) return "unreadable";
  if (marker.state === "failed" && marker.reason === "reconcile_failed") return "failed";
  if (marker.state === "clear") return "clear";
  if (marker.state !== "held") return "unreadable";
  if (!Number.isInteger(marker.drift) || marker.drift < 0) return "unreadable";
  // A staged hold is the cut proving a candidate, not the train declining to
  // mint, but only while the workflow that owns that transition is switched on.
  // Measured on the v0.7.15 release: the bump merged at 21:32:11Z and four
  // consecutive `tag_staged` markers arrived by 21:53:09Z, 9m33s apart end to
  // end, because every one of those cycles was a `workflow_run` firing on a
  // completed CI run somewhere in the fleet rather than the quarter-hourly
  // cron. The cut had not even chosen a candidate yet: its own decision line
  // still read "no complete green sha carries 0.7.15 yet; still being graded",
  // and its candidate build alone takes about fifty minutes. So the threshold
  // counts runs, whose rate is fleet traffic, and no count can be tuned to a
  // release's latency.
  //
  // `cutState` is what keeps this from silencing the failure the body below
  // documents. On 2026-09-07 a staged hold alarmed truthfully because
  // release-cut.yml was switched off, so the staged tag was never going to be
  // minted. That is the FIRST thing the staged body tells a reader to check,
  // and this is that check promoted into the decision: staged is progress only
  // while the cut is `active`, and a cut that is disabled, or whose state could
  // not be read, counts exactly as it did before.
  if (marker.reason === STAGED_REASON && cutState === CUT_STATE_ACTIVE) {
    return "staged_in_progress";
  }
  return marker.drift > 0 ? "held_with_drift" : "held_idle";
}

function leadingHeldWithDrift(markers, cutState) {
  let count = 0;
  for (const marker of markers) {
    if (classify(marker, cutState) !== "held_with_drift") break;
    count += 1;
  }
  return count;
}

function plural(count, singular) {
  return count === 1 ? singular : `${singular}s`;
}

function describeFailedRelease(marker) {
  const id = marker.failed_release_run_id;
  const url = marker.failed_release_run_url;
  if (!id) {
    return (
      "No failed Release run was found for that tag, so the tag may have never " +
      "been cut, or its run may have aged out of the window this read covers. " +
      "Check the Release workflow before assuming either."
    );
  }
  return `The Release run that owns it is ${url || `run ${id}`} (id ${id}).`;
}

// The one hold reason that means the blocking tag does not exist.
//
// Both exits this body used to name unconditionally assume the tag is real.
// Recovery retries the Release run that tag produced, and abandonment records
// the tag in `scripts/abandoned-release-tags.json`, whose entries carry a `sha`
// and a `failed_release_run_id`. A tag nobody ever created has neither, so a
// reader who tries either one spends the trip and arrives nowhere.
//
// The train already tells the two apart and this reader used to throw that away.
// `.github/workflows/release-train.yml` fetches every tag
// (`git fetch origin "+refs/tags/*:refs/tags/*"`) BEFORE it decides, and only
// then writes this reason, under `if ! git rev-parse --verify --quiet
// "${tag}^{commit}"`. So the code is a proof taken against a complete tag set
// that the tag this alarm names was never cut. `tag_not_finalized`, the other
// reason that reaches this body, is written when a tag does exist and is not
// GitHub Latest, and both original exits apply there unchanged.
//
// This is not a cosmetic wrong. On 2026-09-07 the alarm fired truthfully and on
// time, and a captain and a lane still spent about forty minutes establishing
// that a workflow switch was off, because the body sent them to a Release run
// that had never started and to a tag that had never been created. The real
// cause was reachable in two API calls that nothing told them to make.
export const STAGED_REASON = "tag_staged";

export function buildBody(marker, consecutive, threshold, cutState) {
  const drift = marker.drift;
  const blocking = marker.blocking_tag || "an unresolved tag";
  const latest = marker.latest_tag || "an unread Latest";
  const lines = [];

  lines.push(
    `The release train has declined to mint for ${consecutive} consecutive ` +
      `${plural(consecutive, "cycle")} while ${drift} reviewed ` +
      `${plural(drift, "commit")} sat on main waiting to ship. Each of those ` +
      "runs concluded success, so nothing about the run history says the rail " +
      "stopped moving. This issue is the part that says it.",
  );
  lines.push("");
  lines.push(`Blocking tag: \`${blocking}\`. GitHub Latest is \`${latest}\`.`);
  lines.push(`Releasable drift: ${drift} ${plural(drift, "commit")} beyond \`${marker.base_tag || blocking}\`.`);
  lines.push(`Hold reason reported by the train: ${marker.detail || marker.reason || "unreported"}.`);
  lines.push(`Most recent train run: ${marker.run_url || `run ${marker.run_id ?? "unknown"}`}.`);
  lines.push("");
  if (marker.reason === STAGED_REASON) {
    lines.push(
      `\`${blocking}\` was never cut. The train reports it as staged on main, ` +
        "which it writes only after fetching every tag and finding that ref " +
        "absent. This is a tag that does not exist, not a tag whose release " +
        "failed.",
    );
    lines.push("");
    lines.push(
      "The two usual exits do not apply, and both will waste the trip. " +
        "Recovery retries the Release run that owns a tag, and no Release run " +
        "has ever started for this one. Abandonment records a tag in " +
        "`scripts/abandoned-release-tags.json`, whose entries carry a `sha` " +
        "and a `failed_release_run_id` that an uncut tag cannot supply.",
    );
    lines.push("");
    lines.push(
      "What is stuck is candidate selection. " +
        "`.github/workflows/release-tag.yml` tags the newest reviewed main " +
        "commit in the staged version's range carrying " +
        "`evidence/<sha>/preflight.json` on the `release-evidence` branch. " +
        "With no such commit it reports having no candidate and exits 0, " +
        "which is why every mint run reads green while the rail stands still.",
    );
    lines.push("");
    lines.push(
      "The only automated publisher of that record is `Release Cut`, " +
        "`.github/workflows/release-cut.yml`, which this fleet operates as a " +
        "switch rather than leaving on. Read these two before looking " +
        "anywhere else:",
    );
    lines.push("");
    lines.push("```");
    lines.push(
      "gh api repos/{owner}/{repo}/actions/workflows/release-cut.yml --jq .state",
    );
    lines.push(
      'gh api "repos/{owner}/{repo}/git/trees/release-evidence?recursive=1" \\',
    );
    lines.push(
      "  --jq '[.tree[].path | select(endswith(\"preflight.json\"))] | length'",
    );
    lines.push("```");
    lines.push("");
    // This paragraph used to assert `disabled_manually` outright, which made
    // the issue state a diagnosis nothing had measured: kin#1750 told a reader
    // the cut was switched off while the API read it `active`. The job now
    // reads that state before deciding, so the body reports what it read.
    const readState = cutState || "unreadable";
    if (readState === "disabled_manually" || readState === "disabled_inactivity") {
      lines.push(
        `This alarm read that workflow's state as \`${readState}\`, and that is ` +
          "the whole answer: no candidate can exist until it is enabled. " +
          "Enabling it opens a window in which the cut proves whatever is " +
          "newest and green, so it is a decision to take deliberately rather " +
          "than an automatic repair.",
      );
    } else {
      lines.push(
        `This alarm read that workflow's state as \`${readState}\`, so a switch ` +
          "that is off is not the answer here, and the two commands above are " +
          "where to start instead. A staged hold never reaches this body while " +
          "that state reads `active`, so either the read failed or the cut " +
          "changed state between the read and now.",
      );
    }
  } else {
    lines.push(describeFailedRelease(marker));
    lines.push("");
    lines.push("There are two ways out, and both of them move the rail.");
    lines.push("");
    lines.push(
      "Recover the release. If the defect that blocks the tag can still be " +
        "reached, fix it and let Release Recovery retry the tag. A tag run " +
        "resolves its workflows from the tag, so confirm the fix is reachable " +
        "from the tagged tree before spending a retry on it.",
    );
    lines.push("");
    lines.push(
      "Record the abandonment. If the defect is frozen into the tag, add the " +
        "tag to `scripts/abandoned-release-tags.json` with all five required " +
        "fields, prove the entry with `python3 " +
        "scripts/select-admissible-release-tag.py`, and land it. The train steps " +
        "past a tag only on a reviewed record.",
    );
  }
  lines.push("");
  lines.push(
    `This issue closes itself on the next cycle that mints, and it stays quiet ` +
      `until a hold carries drift for ${threshold} consecutive cycles, so it ` +
      "never rings for a rail that is merely idle.",
  );
  return lines.join("\n");
}

export function decide({ markers, issue, threshold = DEFAULT_THRESHOLD, cutState = null }) {
  const list = Array.isArray(markers) ? markers : [];
  const open = issue && typeof issue === "object" && issue.number ? issue : null;
  const newest = list[0];
  const state = classify(newest, cutState);

  if (state === "unreadable") {
    return {
      action: "quiet",
      reason: "newest_marker_unreadable",
      // An open alarm is deliberately left alone. Closing on an unreadable read
      // would disarm the alarm in exactly the state that most needs it armed.
      detail:
        "The newest release-train hold marker could not be read, so the rail's " +
        "state is unknown. An unknown never opens an alarm and never closes one.",
    };
  }

  if (state === "failed") {
    return {
      action: open ? "update" : "open",
      reason: "reconcile_failed",
      ...(open ? { issue: open.number } : {}),
      title: ALARM_TITLE,
      body: `Release reconciliation did not complete successfully. No release progress is established by this cycle.\n\n` +
        `Inspect the failed step in ${newest.run_url || `run ${newest.run_id ?? "unknown"}`}.\n\n` +
        `Repair that failure through the reviewed release workflow. This alarm does not authorize a new candidate, retry or tag abandonment.`,
    };
  }

  if (state === "clear") {
    if (open) {
      return {
        action: "close",
        reason: "train_minted",
        issue: open.number,
        comment:
          "The release train is minting again, so the hold this issue tracked " +
          "is over. Closing on the train's own all-clear rather than on a " +
          "reader's judgement.",
      };
    }
    return { action: "quiet", reason: "rail_healthy", detail: "The train resolved drift and proceeded." };
  }

  if (state === "staged_in_progress") {
    // Quiet, and an open alarm is left exactly where it is. Only the train's own
    // all-clear closes one, and a staged hold is not an all-clear.
    return {
      action: "quiet",
      reason: "staged_in_progress",
      detail:
        "The next version is staged on main and the cut is switched on, so a " +
        "workflow owns this transition and the rail is moving. A staged hold " +
        "counts toward the alarm only while release-cut.yml is not active.",
    };
  }

  if (state === "held_idle") {
    return {
      action: "quiet",
      reason: "held_without_drift",
      detail:
        "The rail is held with nothing to release. A held rail with zero drift " +
        "is idle, and idle is not an alarm.",
    };
  }

  const consecutive = leadingHeldWithDrift(list, cutState);
  if (consecutive < threshold) {
    return {
      action: "quiet",
      reason: "below_threshold",
      consecutive,
      threshold,
      detail:
        `The rail has held with drift for ${consecutive} consecutive ` +
        `${plural(consecutive, "cycle")}, under the ${threshold} it takes to alarm.`,
    };
  }

  const body = buildBody(newest, consecutive, threshold, cutState);
  if (open) {
    return {
      action: "update",
      reason: "hold_persists",
      issue: open.number,
      consecutive,
      threshold,
      title: ALARM_TITLE,
      body,
    };
  }
  return {
    action: "open",
    reason: "hold_established",
    consecutive,
    threshold,
    title: ALARM_TITLE,
    body,
  };
}

function parseArgs(argv) {
  const args = { markers: null, issue: null, threshold: DEFAULT_THRESHOLD, cutState: null };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--markers") args.markers = argv[++index];
    else if (flag === "--issue") args.issue = argv[++index];
    else if (flag === "--threshold") args.threshold = Number.parseInt(argv[++index], 10);
    // Absent, or any value but "active", leaves a staged hold counting exactly
    // as it did before, so a caller that cannot read the cut's state never
    // quiets the alarm by omission.
    else if (flag === "--cut-state") args.cutState = argv[++index] ?? null;
    else throw new Error(`unknown argument: ${flag}`);
  }
  if (!args.markers) throw new Error("--markers <path> is required");
  if (!Number.isInteger(args.threshold) || args.threshold < 1) {
    throw new Error("--threshold must be a positive integer");
  }
  return args;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function main(argv) {
  const args = parseArgs(argv);
  const markers = readJson(args.markers);
  // "none" is how the caller says it looked for an open alarm and found none,
  // which is a different statement from having never looked. An absent path
  // would be the second, so the caller has to spell the first.
  const issue = !args.issue || args.issue === "none" ? null : readJson(args.issue);
  process.stdout.write(`${JSON.stringify(decide({ markers, issue, threshold: args.threshold, cutState: args.cutState }), null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}

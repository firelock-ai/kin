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

// A marker this reader cannot vouch for is not a quiet rail and it is not a
// held one either. It breaks the streak and it never closes an open alarm,
// because an unreadable observation and an observed all-clear are different
// findings and only one of them is safe to act on.
function classify(marker) {
  if (!marker || typeof marker !== "object") return "unreadable";
  if (marker.unreadable === true) return "unreadable";
  if (marker.schema !== MARKER_SCHEMA) return "unreadable";
  if (marker.state === "clear") return "clear";
  if (marker.state !== "held") return "unreadable";
  if (!Number.isInteger(marker.drift) || marker.drift < 0) return "unreadable";
  return marker.drift > 0 ? "held_with_drift" : "held_idle";
}

function leadingHeldWithDrift(markers) {
  let count = 0;
  for (const marker of markers) {
    if (classify(marker) !== "held_with_drift") break;
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

export function buildBody(marker, consecutive, threshold) {
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
  lines.push("");
  lines.push(
    `This issue closes itself on the next cycle that mints, and it stays quiet ` +
      `until a hold carries drift for ${threshold} consecutive cycles, so it ` +
      "never rings for a rail that is merely idle.",
  );
  return lines.join("\n");
}

export function decide({ markers, issue, threshold = DEFAULT_THRESHOLD }) {
  const list = Array.isArray(markers) ? markers : [];
  const open = issue && typeof issue === "object" && issue.number ? issue : null;
  const newest = list[0];
  const state = classify(newest);

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

  if (state === "held_idle") {
    return {
      action: "quiet",
      reason: "held_without_drift",
      detail:
        "The rail is held with nothing to release. A held rail with zero drift " +
        "is idle, and idle is not an alarm.",
    };
  }

  const consecutive = leadingHeldWithDrift(list);
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

  const body = buildBody(newest, consecutive, threshold);
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
  const args = { markers: null, issue: null, threshold: DEFAULT_THRESHOLD };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--markers") args.markers = argv[++index];
    else if (flag === "--issue") args.issue = argv[++index];
    else if (flag === "--threshold") args.threshold = Number.parseInt(argv[++index], 10);
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
  process.stdout.write(`${JSON.stringify(decide({ markers, issue, threshold: args.threshold }), null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}

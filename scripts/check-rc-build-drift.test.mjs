#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// A drift check that cannot fail is not evidence. Every case below breaks the
// relationship in one specific way and requires the named complaint, so the
// green run above them means the two workflows actually agree.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import {
  check,
  checkFiles,
  splitSteps,
  buildJobBody,
  RELEASE_WORKFLOW,
  RC_WORKFLOW,
} from "./check-rc-build-drift.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const release = readFileSync(join(ROOT, RELEASE_WORKFLOW), "utf8");
const rc = readFileSync(join(ROOT, RC_WORKFLOW), "utf8");

const only = (problems) => {
  assert.equal(problems.length, 1, `expected one problem, got:\n${problems.join("\n")}`);
  return problems[0];
};

test("the workflows in the tree agree", () => {
  assert.deepEqual(checkFiles(ROOT), []);
});

test("the build job stops before the next job's header comment", () => {
  const steps = splitSteps(buildJobBody(release, RELEASE_WORKFLOW), RELEASE_WORKFLOW);
  const last = steps[steps.length - 1];
  assert.equal(last.name, "Upload artifact");
  assert.ok(!last.body.includes("notarize_linux"));
  assert.ok(!/^ {2}#/m.test(last.body));
});

test("a comment block above a step belongs to that step", () => {
  const steps = splitSteps(buildJobBody(rc, RC_WORKFLOW), RC_WORKFLOW);
  const added = steps.find((step) => step.name === "Resolve the release-candidate identity");
  assert.ok(added.body.startsWith("      # ADDED:"), added.body.slice(0, 80));
  const checkout = steps.find((step) => step.name === "Checkout");
  assert.ok(!checkout.body.includes("# ADDED:"));
});

test("a step added to release.yml is reported", () => {
  const mutated = release.replace(
    "      - name: Package (Unix)",
    "      - name: Sneak in a release step\n        run: echo drift\n\n      - name: Package (Unix)"
  );
  assert.notEqual(mutated, release);
  assert.match(only(check(mutated, rc)), /no longer mirrors/);
  assert.match(only(check(mutated, rc)), /Sneak in a release step/);
});

test("a shared step edited in rc-build.yml is reported, and names the step", () => {
  const mutated = rc.replace(
    "        run: ./scripts/ci-apt-install.sh musl-tools",
    "        run: ./scripts/ci-apt-install.sh musl-tools libssl-dev"
  );
  assert.notEqual(mutated, rc);
  const problem = only(check(release, mutated));
  assert.match(problem, /no longer mirrors/);
  assert.match(problem, /Install musl C toolchain \(Linux musl\)/);
});

test("a shared step edited in release.yml is reported", () => {
  const mutated = release.replace(
    "          cargo build --locked --release --target \"$TARGET\" -p kin-cli -p kin-daemon",
    "          cargo build --locked --release --target \"$TARGET\" -p kin-cli -p kin-daemon -p kin-extra"
  );
  assert.notEqual(mutated, release);
  const problem = only(check(mutated, rc));
  assert.match(problem, /Build kin-cli \+ kin-daemon \(native\)/);
});

test("an omitted signing step appearing in rc-build.yml is reported", () => {
  const signing = splitSteps(buildJobBody(release, RELEASE_WORKFLOW), RELEASE_WORKFLOW)
    .find((step) => step.name === "Sign macOS binaries");
  const mutated = rc.replace(
    "      - name: Package (Unix)",
    `${signing.body}\n\n      - name: Package (Unix)`
  );
  assert.notEqual(mutated, rc);
  const problems = check(release, mutated);
  assert.ok(
    problems.some((problem) => /listed as omitted but .* carries it/.test(problem)),
    problems.join("\n")
  );
});

test("an omitted step that release.yml no longer has is reported as stale", () => {
  const mutated = release.replace("      - name: Sign macOS binaries", "      - name: Sign macOS binaries renamed");
  assert.notEqual(mutated, release);
  const problems = check(mutated, rc);
  assert.ok(
    problems.some((problem) => /omission list is stale/.test(problem)),
    problems.join("\n")
  );
});

test("a candidate-only step missing from rc-build.yml is reported", () => {
  const mutated = rc.replace("      - name: Summarize the candidate archives", "      - name: Summarise the candidate archives");
  assert.notEqual(mutated, rc);
  const problems = check(release, mutated);
  assert.ok(
    problems.some((problem) => /added step "Summarize the candidate archives" is missing/.test(problem)),
    problems.join("\n")
  );
});

test("a delta whose anchor stopped matching is reported by label", () => {
  const mutated = release.replace(
    "        run: sudo apt-get update && sudo apt-get install -y musl-tools",
    "        run: sudo apt-get update && sudo apt-get install -y musl-tools pkg-config"
  );
  assert.notEqual(mutated, release);
  const problems = check(mutated, rc);
  // Two complaints, and both are wanted: the delta stopped applying, and the
  // block it would have produced no longer matches.
  assert.ok(
    problems.some((problem) => /delta "apt" matched 0 times/.test(problem)),
    problems.join("\n")
  );
  assert.ok(
    problems.some((problem) => /Install musl C toolchain/.test(problem)),
    problems.join("\n")
  );
});

test("a matrix row that moved in release.yml is reported", () => {
  const mutated = release.replace("          - os: ubuntu-24.04-arm", "          - os: ubuntu-26.04-arm");
  assert.notEqual(mutated, release);
  const problems = check(release === mutated ? release : mutated, rc);
  assert.ok(
    problems.some((problem) => /kin-linux-aarch64 matrix row differs/.test(problem)),
    problems.join("\n")
  );
});

test("an rc-build target release.yml does not publish is reported", () => {
  const mutated = rc.replace("            artifact: kin-macos-aarch64", "            artifact: kin-freebsd-aarch64");
  assert.notEqual(mutated, rc);
  const problems = check(release, mutated);
  assert.ok(
    problems.some((problem) => /builds kin-freebsd-aarch64, which .* does not publish/.test(problem)),
    problems.join("\n")
  );
});

// The properties that make rc-build.yml safe to dispatch on an arbitrary ref.
// Each is one line to break and none of them is visible in a diff of the build
// steps, which is what the mirror check covers.

test("rc-build.yml reads no secret and declares no environment", () => {
  assert.equal(rc.match(/secrets\./g), null);
  assert.equal(rc.match(/^\s*environment:/m), null);
});

test("rc-build.yml grants no permission beyond contents: read", () => {
  const block = /\npermissions:\n((?: {2}\S.*\n)+)/.exec(rc);
  assert.ok(block, "rc-build.yml declares no permissions block");
  assert.deepEqual(block[1].trimEnd().split("\n"), ["  contents: read"]);
});

test("rc-build.yml writes to no Actions cache", () => {
  // A dispatch builds whatever ref it is handed, so a cache write here would
  // poison what CI and release builds restore from, and would put unreviewed
  // cache contents into the bytes under proof.
  assert.equal(rc.match(/actions\/cache/g), null);
  assert.equal(rc.match(/rust-cache/g), null);
});

test("rc-build.yml publishes nothing", () => {
  for (const forbidden of ["npm publish", "gh release", "cargo publish", "docker push", "softprops/action-gh-release"]) {
    assert.equal(rc.includes(forbidden), false, `rc-build.yml contains ${forbidden}`);
  }
});

test("rc-build.yml is dispatch-only", () => {
  const triggers = /\non:\n((?:(?: {2}\S.*| {4}.*|)\n)+?)(?=\npermissions:)/.exec(rc);
  assert.ok(triggers, "could not read rc-build.yml triggers");
  const topLevel = triggers[1].split("\n").filter((line) => /^ {2}\S/.test(line));
  assert.deepEqual(topLevel, ["  workflow_dispatch:"]);
});

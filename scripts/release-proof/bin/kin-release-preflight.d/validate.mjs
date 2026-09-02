#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// The "Validate installed capability proof" block of kin's install-proof.yml,
// ported assertion for assertion, plus the local-run substitutes for the
// publish-fetch bindings that block reads from files.
//
// Every assertion is recorded rather than thrown at first failure, so one run
// names every failing assertion instead of the first. Three outcomes:
//   PASS        the assertion held
//   FAIL        the assertion was evaluated and did not hold (the workflow
//               would have thrown exactly this message)
//   UNREADABLE  the assertion could not be evaluated: a capture is missing or
//               unparsable, or the expected value was never resolved locally.
//               Never reported as PASS.
//
// PORTED_FROM records the sha256 of the install-proof.yml this file was ported
// from. The driver compares it against the workflow at the ref under test and
// REFUSES to run when they differ, because a PASS produced by a stale port is a
// PASS against assertions the release gate no longer runs, and the report names
// the verdict without naming which contract produced it. Re-read the block by
// hand and update this constant; the driver prints the procedure when it
// refuses.
//
// Inputs (environment):
//   PF_CAPTURES         directory holding the captured proof files
//   PF_HOME             the isolated HOME the flow ran under
//   PF_INSTALLED_KIN    the launcher path recorded by the install step
//   PF_EXPECTED_COMMIT  40-hex commit the binaries must report, or empty
//   PF_EXPECTED_LOCK_SHA 64-hex sha256 of that commit's Cargo.lock, or empty
//   PF_RUNNER_OS        macOS | Linux
//   PF_LOCAL_BUILD      1 declares that the bytes under test carry no kin-vfs,
//                       the port of the workflow's `local_artifact` mode. The
//                       workflow sets that input when a pull request installs
//                       binaries it built itself, which exist for kin and
//                       kin-daemon only, and the capability contract then
//                       requires vfs_projection unsupported rather than
//                       healthy. No preflight leg sets it today: --archive and
//                       --rc-run judge whole release-layout archives, and
//                       --build overlays the built kin and kin-daemon onto a
//                       base release archive that supplies kin-vfs, the shim
//                       and KinNotifier.app. It is carried so the two
//                       contracts stay diffable, and so a future mode that
//                       does drop the VFS bytes has to say so rather than
//                       silently failing an assertion that was right
//   PF_EMULATED         1 waives assertions whose capture is missing: an
//                       emulated leg skips the daemon-runtime producer steps,
//                       so those captures are absent by design (present
//                       captures are still judged in full)
//   PF_ALLOW_DIRTY      1 waives the clean-source assertions (dirty, commit,
//                       lock provenance) and reports them as WAIVED
//   PF_HOST_APPS        comma list of clients this host detects through an
//                       application installed outside HOME (cursor, windsurf,
//                       antigravity). kin setup detects those by absolute
//                       /Applications paths, which no HOME isolation hides, so
//                       their appearance in the isolated fallback HOME is a fact
//                       about this host and not a leak; the exposure assertion
//                       is waived for exactly those ids and says so
//   PF_RESULT_JSON      where to write the assertion list
//   cwd                 the probe repository (kin-install-proof)

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Resynced 2026-08-22 (third time) against install-proof.yml carrying
// kin#1079, which makes every matrix row gate the release by dropping the
// Windows leg's continue-on-error waiver and its experimental flag, and stops
// the two `kin setup` steps piping through `tee`, because the long-lived child
// setup leaves behind inherits the write end of the pipe and holds it for the
// daemon's full idle window. Neither change is an assertion. The gating
// posture is job-level, and the setup capture is a producer step, ported into
// proof-flow.sh beside this file. The mirrored "Validate installed capability
// proof" step is byte for byte identical between the two pins, so this resync
// moves the pin with no assertion delta, as the kin#1069 (job timeout) and
// kin#1060 (Windows repo-free provenance step) resyncs before it did.
export const PORTED_FROM = {
  file: ".github/workflows/install-proof.yml",
  sha256: "0c469d2871a1a6b02944a2ddc5f12482a1556af4179f8f66bbfa018443ee2878",
};

class Unreadable extends Error {}

const captures = process.env.PF_CAPTURES || process.cwd();
const runnerOs = process.env.PF_RUNNER_OS || (process.platform === "darwin" ? "macOS" : "Linux");
const isWindows = runnerOs === "Windows";
// The workflow's `isPullRequestBuild`, which it derives from the LOCAL_ARTIFACT
// input. See PF_LOCAL_BUILD above for why no preflight leg sets this.
const isLocalBuild = process.env.PF_LOCAL_BUILD === "1";
const allowDirty = process.env.PF_ALLOW_DIRTY === "1";
const emulated = process.env.PF_EMULATED === "1";
const home = process.env.PF_HOME || os.homedir();
const hostApps = (process.env.PF_HOST_APPS || "").split(",").map((s) => s.trim()).filter(Boolean);

const results = [];
const record = (status, name, message) => {
  results.push({ status, name, message });
  const line = `ASSERT ${status.padEnd(10)} ${name}${message ? `: ${message}` : ""}`;
  console.log(line);
};

const check = (name, fn) => {
  try {
    const message = fn();
    record("PASS", name, typeof message === "string" ? message : "");
  } catch (error) {
    const missing =
      error instanceof Unreadable || (error && error.code === "ENOENT");
    if (missing && emulated) {
      // An emulated leg skips the daemon-runtime steps, so their captures are
      // absent by design rather than lost; a capture that IS present is still
      // judged in full above. Real-runner legs bind these assertions.
      record(
        "PASS",
        name,
        `WAIVED emulated leg: ${error.message}; its producer step is daemon-runtime and does not run under CPU emulation`,
      );
    } else if (error instanceof Unreadable) {
      record("UNREADABLE", name, error.message);
    } else if (error && error.code === "ENOENT") {
      record("UNREADABLE", name, `capture missing: ${error.path ?? error.message}`);
    } else {
      record("FAIL", name, error.message);
    }
  }
};

const readText = (file) => {
  const resolved = path.isAbsolute(file) ? file : path.join(captures, file);
  if (!fs.existsSync(resolved)) {
    throw new Unreadable(`capture missing: ${resolved}`);
  }
  return fs.readFileSync(resolved, "utf8");
};
const readJson = (file) => {
  const text = readText(file);
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Unreadable(`${file}: not JSON (${error.message}); first bytes: ${JSON.stringify(text.slice(0, 120))}`);
  }
};
const readJsonAt = (absolute) => {
  if (!fs.existsSync(absolute)) {
    throw new Unreadable(`file missing: ${absolute}`);
  }
  try {
    return JSON.parse(fs.readFileSync(absolute, "utf8"));
  } catch (error) {
    throw new Unreadable(`${absolute}: not JSON (${error.message})`);
  }
};

const expectedCommit = (process.env.PF_EXPECTED_COMMIT || "").trim();
const expectedLock = (process.env.PF_EXPECTED_LOCK_SHA || "").trim();
const installedKin = (process.env.PF_INSTALLED_KIN || "").trim();

// ---------------------------------------------------------------------------
// Verify binaries installed + runnable (the local half of that step)
// ---------------------------------------------------------------------------
check("installed launcher path", () => {
  const expectedInstalledKin = path.join(home, ".kin", "bin", isWindows ? "kin.exe" : "kin");
  if (installedKin !== expectedInstalledKin) {
    throw new Error(`installed Kin command proof ${installedKin || "missing"} does not equal ${expectedInstalledKin}`);
  }
  return installedKin;
});

// ---------------------------------------------------------------------------
// Validate installed capability proof
// ---------------------------------------------------------------------------
const fullSha = /^[0-9a-f]{40}$/;
const lockSha = /^[0-9a-f]{64}$/;

check("kin-build-meta.json schema", () => {
  const cliMeta = readJson("kin-build-meta.json");
  if (cliMeta.schema !== "kin.bench-meta.v2") {
    throw new Error(`kin-build-meta.json: unsupported schema ${cliMeta.schema ?? "missing"}`);
  }
});

const buildsOf = () => {
  const cliMeta = readJson("kin-build-meta.json");
  const daemonHealth = readJson("kin-daemon-health.json");
  return new Map([
    ["cli", {
      sha: cliMeta.kin_commit,
      dirty: cliMeta.kin_dirty,
      sourceKnown: cliMeta.kin_source_known,
      dependencyProvenance: cliMeta.dependency_provenance,
    }],
    ["daemon", {
      sha: daemonHealth.build?.sha,
      dirty: daemonHealth.build?.dirty,
      sourceKnown: daemonHealth.build?.source_known,
      dependencyProvenance: daemonHealth.build?.dependency_provenance,
    }],
  ]);
};

for (const side of ["cli", "daemon"]) {
  check(`${side} build SHA is a full commit`, () => {
    const build = buildsOf().get(side);
    if (!fullSha.test(build.sha ?? "")) {
      throw new Error(`${side} build SHA is not a full 40-hex commit: ${build.sha ?? "missing"}`);
    }
    return build.sha;
  });
  check(`${side} build SHA matches the expected commit`, () => {
    const build = buildsOf().get(side);
    if (!expectedCommit) {
      throw new Unreadable("no expected commit was resolved for this run");
    }
    if (build.sha !== expectedCommit) {
      if (allowDirty) return `WAIVED (--allow-dirty): ${side} build SHA ${build.sha} does not match ${expectedCommit}`;
      throw new Error(`${side} build SHA ${build.sha} does not match release tag ${expectedCommit}`);
    }
  });
  check(`${side} release binary is clean`, () => {
    const build = buildsOf().get(side);
    if (build.dirty !== false) {
      if (allowDirty) return `WAIVED (--allow-dirty): ${side} binary reports dirty=${build.dirty}`;
      throw new Error(`${side} release binary is dirty or did not report a clean build`);
    }
  });
  check(`${side} release binary proves source_known`, () => {
    const build = buildsOf().get(side);
    if (build.sourceKnown !== true) {
      throw new Error(`${side} release binary did not prove source_known=true`);
    }
  });
  check(`${side} Cargo.lock provenance is well formed`, () => {
    const build = buildsOf().get(side);
    if (!lockSha.test(build.dependencyProvenance ?? "")) {
      throw new Error(`${side} Cargo.lock provenance is missing or malformed`);
    }
  });
  check(`${side} Cargo.lock provenance matches the source`, () => {
    const build = buildsOf().get(side);
    if (!expectedLock) {
      throw new Unreadable("no expected Cargo.lock sha256 was resolved for this run");
    }
    if (build.dependencyProvenance !== expectedLock) {
      if (allowDirty) return `WAIVED (--allow-dirty): ${side} Cargo.lock provenance ${build.dependencyProvenance} does not match ${expectedLock}`;
      throw new Error(`${side} Cargo.lock provenance ${build.dependencyProvenance} does not match release source ${expectedLock}`);
    }
  });
}
check("CLI and daemon share Cargo.lock provenance", () => {
  const builds = buildsOf();
  if (builds.get("cli").dependencyProvenance !== builds.get("daemon").dependencyProvenance) {
    throw new Error("CLI and daemon were built from different Cargo.lock provenance");
  }
});

check("kin-status.json schema", () => {
  const status = readJson("kin-status.json");
  if (status.schema !== "kin.status.v3") {
    throw new Error(`kin-status.json: unsupported schema ${status.schema ?? "missing"}`);
  }
});

const validateEmbeddingCoverage = (coverage, label) => {
  if (!coverage || typeof coverage !== "object" || Array.isArray(coverage)) {
    throw new Error(`${label}: embedding_coverage is missing or malformed`);
  }
  if (coverage.state === "observed") {
    if (coverage.source !== "live_query_graph") {
      throw new Error(`${label}: observed coverage has source ${coverage.source ?? "missing"}`);
    }
    for (const field of ["indexed", "pending", "total"]) {
      if (!Number.isSafeInteger(coverage[field]) || coverage[field] < 0) {
        throw new Error(`${label}: embedding_coverage.${field} is not a non-negative integer`);
      }
    }
    if (coverage.reason !== undefined || coverage.indexed > coverage.total || coverage.pending < coverage.total - coverage.indexed) {
      throw new Error(`${label}: observed embedding coverage violates kin.status.v3 invariants`);
    }
  } else if (coverage.state === "unobserved") {
    if (typeof coverage.reason !== "string" || coverage.reason.length === 0) {
      throw new Error(`${label}: unobserved embedding coverage carries no reason`);
    }
    for (const field of ["source", "indexed", "pending", "total"]) {
      if (coverage[field] !== undefined) {
        throw new Error(`${label}: unobserved embedding coverage carries ${field}`);
      }
    }
  } else {
    throw new Error(`${label}: unknown embedding coverage state ${coverage.state ?? "missing"}`);
  }
};

check("bench metadata proves vector and embedding support", () => {
  const cliMeta = readJson("kin-build-meta.json");
  if (cliMeta.embeddings?.vector_enabled !== true || cliMeta.embeddings?.embeddings_enabled !== true) {
    throw new Error(`${runnerOs} bench metadata does not prove vector and embedding support`);
  }
});
if (!isWindows) {
  check("kin-status.json embedding coverage shape", () => {
    const status = readJson("kin-status.json");
    validateEmbeddingCoverage(status.embedding_coverage, "kin-status.json");
  });
}

// --- BEGIN HEALTH JOIN ---
// A check is out of scope only when the platform or the context puts it out of
// scope, which is exactly `unsupported`. Every other status is a component that
// is not answering at full strength, so a report claiming readiness over one
// claims more than its components support (FIR-2919).
const healthNeedsAttention = (check) =>
  check.status !== "healthy" && check.status !== "unsupported";
// Something wrong with the INSTALL, as against work in flight or ground the
// host never had. A different question from the one above, and conflating the
// two is what fenced v0.6.1.
const healthBlocksReadiness = (check) =>
  check.status === "missing" ||
  check.status === "misconfigured" ||
  (check.id === "semantic_query_readiness" && check.status === "stale");
const healthJoin = (checks) => {
  if (checks.some(healthBlocksReadiness)) return "failing";
  return checks.some(healthNeedsAttention) ? "needs_attention" : "ready";
};
// --- END HEALTH JOIN ---
const attentionRows = (report) => (report.checks ?? [])
  .filter(healthNeedsAttention)
  .map((check) => `${check.id}=${check.status}`)
  .join(", ") || "none";
const validateHealthReport = (report, reportPath) => {
  if (!Array.isArray(report.checks)) {
    throw new Error(`${reportPath}: checks is missing or malformed`);
  }
  const checks = new Map(report.checks.map((check) => [check.id, check]));
  if (checks.size !== report.checks.length) {
    throw new Error(`${reportPath}: duplicate health-check ids are not authoritative`);
  }
  // Required, not optional. A report with no `verdict` came from a build that
  // predates FIR-2919, whose aggregate gated on missing and misconfigured alone
  // and read `true` over a pending or degraded row. Grading it against either
  // rule would be a claim about bytes that cannot carry it.
  if (report.verdict === undefined) {
    throw new Error(
      `${reportPath}: the report carries no verdict field, so these bytes predate FIR-2919 and their aggregate cannot be graded against the health join`
    );
  }
  const verdict = healthJoin(report.checks);
  if (report.verdict !== verdict) {
    throw new Error(`${reportPath}: verdict=${report.verdict} disagrees with checks; expected ${verdict}`);
  }
  if (report.healthy !== (verdict === "ready")) {
    throw new Error(
      `${reportPath}: aggregate healthy=${report.healthy} disagrees with checks; expected ${verdict === "ready"}`
    );
  }
  return checks;
};

for (const fallbackReportPath of [
  "kin-claude-fallback-health.json",
  "kin-claude-fallback-doctor.json",
]) {
  check(`${fallbackReportPath} forced Claude fallback`, () => {
    const fallbackReport = readJson(fallbackReportPath);
    const fallbackChecks = validateHealthReport(fallbackReport, fallbackReportPath);
    if (fallbackChecks.get("mcp_client_claude")?.status !== "healthy") {
      throw new Error(`${fallbackReportPath}: forced Claude fallback config is not healthy`);
    }
    const waived = [];
    for (const absentId of [
      "mcp_client_cursor",
      "mcp_client_codex",
      "mcp_client_gemini",
      "mcp_client_windsurf",
      "mcp_client_antigravity",
    ]) {
      if (fallbackChecks.has(absentId)) {
        const client = absentId.replace(/^mcp_client_/, "");
        if (hostApps.includes(client)) {
          waived.push(absentId);
          continue;
        }
        throw new Error(`${fallbackReportPath}: isolated fallback HOME unexpectedly exposed ${absentId}`);
      }
    }
    if (waived.length > 0) {
      return `WAIVED host divergence: ${waived.join(", ")} detected through /Applications on this host (a hosted runner has no such app); PATH- and HOME-detected clients were still required absent`;
    }
  });
}

const required = new Map([
  ["kin_binary", "healthy"],
  ["kin_daemon_binary", "healthy"],
  ["daemon_running", "healthy"],
  ["repo_init", "healthy"],
  ["shell_path", "healthy"],
  ["setup_ledger", "healthy"],
  ["registry_authority", isWindows ? "unsupported" : "healthy"],
  ["vfs_projection", isWindows || isLocalBuild ? "unsupported" : "healthy"],
  ["mcp_client_claude", "healthy"],
  ["mcp_client_cursor", "healthy"],
  ["mcp_client_codex", "healthy"],
  ["mcp_client_gemini", "healthy"],
  ["mcp_client_windsurf", "healthy"],
  ["mcp_client_antigravity", "healthy"],
  ["mcp_client_antigravity_workspace", "healthy"],
]);

for (const reportPath of ["kin-health.json", "kin-doctor.json"]) {
  check(`${reportPath} aggregate health`, () => {
    const report = readJson(reportPath);
    const checks = validateHealthReport(report, reportPath);
    // Every row a correct fresh Unix install reports beyond healthy and
    // not-applicable, named with the statuses it may hold. This capture
    // runs before `kin embed`, so the daemon graph still has embeddings
    // pending and the model has never been fetched.
    //
    // This used to read `report.healthy !== true` with one tolerance for
    // a stale readiness. On the v0.6.1 release run's own
    // `install-proof-ubuntu-latest-33235776577` artifact,
    // `kin-health.json` carried FIVE rows needing attention under
    // `healthy: true`, so that assertion passed while naming none of
    // them. Listing them is what makes a sixth fail (FIR-2919).
    const firstRunAttention = new Map([
      ["projection_mode", ["stale"]],
      ["semantic_query_readiness", ["pending", "stale"]],
      ["reference_edge_coverage", ["pending"]],
      ["embedding_model", ["pending"]],
      ["memory_floor", ["degraded"]],
      // The first relation census is its own background pass, so a
      // capture that beats it reads `pending`, the same first-run
      // class as reference_edge_coverage above. The v0.6.2 preflight
      // measured exactly that on a native-arch containerized fresh
      // install (both health captures pending) while the workflow's
      // own v0.6.1 arm leg happened to win the race and read healthy,
      // so whether the row appears is host timing, not install state
      // (kin#1238).
      ["relation_census", ["pending"]],
    ]);
    const untolerated = report.checks.filter(
      (check) =>
        healthNeedsAttention(check) &&
        !(firstRunAttention.get(check.id) ?? []).includes(check.status)
    );
    if (untolerated.length > 0) {
      throw new Error(
        `${reportPath}: rows needing attention that a fresh install does not expect: ` +
        `${untolerated.map((check) => `${check.id}=${check.status}`).join(", ")}; ` +
        `verdict=${report.verdict}; every row needing attention: ${attentionRows(report)}`
      );
    }
    void checks;
  });
  check(`${reportPath} required check statuses`, () => {
    const report = readJson(reportPath);
    const checks = validateHealthReport(report, reportPath);
    for (const [id, expected] of required) {
      const actual = checks.get(id)?.status;
      if (actual !== expected) {
        throw new Error(`${reportPath}: ${id} is ${actual ?? "missing"}, expected ${expected}`);
      }
    }
  });
  check(`${reportPath} semantic_query_readiness`, () => {
    const report = readJson(reportPath);
    const checks = validateHealthReport(report, reportPath);
    const semanticReadiness = checks.get("semantic_query_readiness")?.status;
    const allowedSemanticReadiness = ["healthy", "pending", "stale"];
    if (!allowedSemanticReadiness.includes(semanticReadiness)) {
      throw new Error(
        `${reportPath}: semantic_query_readiness is ${semanticReadiness ?? "missing"}, expected ${allowedSemanticReadiness.join(" or ")}`
      );
    }
    return semanticReadiness;
  });
  check(`${reportPath} no hard failures`, () => {
    const report = readJson(reportPath);
    validateHealthReport(report, reportPath);
    const hardFailures = report.checks.filter((check) =>
      check.status === "missing" || check.status === "misconfigured"
    );
    if (hardFailures.length > 0) {
      throw new Error(`${reportPath}: hard failures: ${hardFailures.map((c) => c.id).join(", ")}`);
    }
  });
}

check("lexical kin search returns the seeded hello entity", () => {
  const search = readJson("kin-search.json");
  if (!Array.isArray(search) || !search.some((record) => record.name === "hello" && record.file === "probe.py")) {
    throw new Error("lexical kin search did not return the seeded hello entity");
  }
});
check("kin locate returns the seeded probe.py graph artifact", () => {
  const locate = readJson("kin-locate.json");
  if (!locate.files?.some((entry) => entry.path === "probe.py")) {
    throw new Error("kin locate did not return the seeded probe.py graph artifact");
  }
});

check("MCP client configs bind the installed launcher", () => {
  const repoRoot = fs.realpathSync(process.cwd());
  const ordinaryArgs = ["mcp", "start"];
  const repositoryArgs = ["mcp", "start", "--repo", repoRoot];
  const mcpConfigs = [
    { path: path.join(home, ".claude.json"), args: ordinaryArgs },
    { path: path.join(home, ".cursor", "mcp.json"), args: ordinaryArgs },
    { path: path.join(home, ".gemini", "settings.json"), args: ordinaryArgs },
    { path: path.join(home, ".codeium", "windsurf", "mcp_config.json"), args: ordinaryArgs },
    { path: path.join(captures, "kin-claude-fallback-config.json"), args: ordinaryArgs },
    { path: path.join(captures, "kin-codex-config.json"), args: repositoryArgs },
    { path: path.join(home, ".gemini", "config", "mcp_config.json"), args: repositoryArgs, cwd: repoRoot },
    { path: path.join(home, ".gemini", "antigravity-ide", "mcp_config.json"), args: repositoryArgs, cwd: repoRoot },
    { path: path.join(repoRoot, ".agents", "mcp_config.json"), args: repositoryArgs, cwd: repoRoot },
  ];
  const stripVerbatim = (p) => (typeof p === "string" && p.startsWith("\\\\?\\") ? p.slice(4) : p);
  for (const expected of mcpConfigs) {
    const entry = readJsonAt(expected.path)?.mcpServers?.kin;
    const entryArgs = Array.isArray(entry?.args) ? entry.args.map(stripVerbatim) : entry?.args;
    if (
      !entry ||
      entry.command !== installedKin ||
      JSON.stringify(entryArgs) !== JSON.stringify(expected.args) ||
      entry.env?.KIN_MCP_TOOL_PROFILE !== "agent-default" ||
      (expected.cwd !== undefined && stripVerbatim(entry.cwd) !== expected.cwd)
    ) {
      throw new Error(`${expected.path}: Kin MCP entry is missing or malformed`);
    }
  }
  return `${mcpConfigs.length} configs`;
});
check("Antigravity legacy repair preserved user policy", () => {
  const legacy = readJsonAt(path.join(home, ".gemini", "antigravity-ide", "mcp_config.json"));
  if (legacy.userPolicy !== "preserve" || legacy.mcpServers.kin.env.USER_POLICY !== "preserve") {
    throw new Error("Antigravity legacy repair did not preserve unrelated user policy");
  }
});

if (!isWindows) {
  check("bounded clean-install embedding reached full coverage", () => {
    const embed = readJson("kin-embed.json");
    if (embed.pending_entities !== 0 || embed.pending_artifacts !== 0 || embed.time_limited === true) {
      throw new Error(`bounded clean-install embedding did not reach full coverage: ${JSON.stringify(embed)}`);
    }
  });
  check("kin-embedded-status.json schema", () => {
    const embeddedStatus = readJson("kin-embedded-status.json");
    if (embeddedStatus.schema !== "kin.status.v3") {
      throw new Error(`kin-embedded-status.json: unsupported schema ${embeddedStatus.schema ?? "missing"}`);
    }
  });
  check("kin-embedded-status.json embedding coverage shape", () => {
    const embeddedStatus = readJson("kin-embedded-status.json");
    validateEmbeddingCoverage(embeddedStatus.embedding_coverage, "kin-embedded-status.json");
  });
  check("Unix status observed embedding coverage after settle", () => {
    const embeddedStatus = readJson("kin-embedded-status.json");
    const embeddedCoverage = embeddedStatus.embedding_coverage;
    const settleMode = fs.existsSync(path.join(captures, "kin-status-settle-mode.txt"))
      ? fs.readFileSync(path.join(captures, "kin-status-settle-mode.txt"), "utf8").trim()
      : "unrecorded";
    if (embeddedCoverage?.state !== "observed") {
      throw new Error(
        `Unix status could not observe embedding coverage after a ${settleMode} read: ` +
        `${JSON.stringify(embeddedCoverage)}`
      );
    }
    return settleMode;
  });
  check("Unix status proves complete observed embedding coverage", () => {
    const embeddedStatus = readJson("kin-embedded-status.json");
    const embeddedCoverage = embeddedStatus.embedding_coverage ?? {};
    if (
      embeddedCoverage.source !== "live_query_graph" ||
      embeddedCoverage.total === 0 ||
      embeddedCoverage.indexed !== embeddedCoverage.total ||
      embeddedCoverage.pending !== 0
    ) {
      throw new Error(`Unix status did not prove complete observed embedding coverage: ${JSON.stringify(embeddedCoverage)}`);
    }
    return `indexed ${embeddedCoverage.indexed}/${embeddedCoverage.total}`;
  });
  for (const reportPath of ["kin-embedded-health.json", "kin-embedded-doctor.json"]) {
    check(`${reportPath} healthy with semantic readiness`, () => {
      const report = readJson(reportPath);
      const checks = validateHealthReport(report, reportPath);
      const readiness = checks.get("semantic_query_readiness")?.status;
      if (readiness !== "healthy") {
        throw new Error(
          `${reportPath}: semantic_query_readiness=${readiness ?? "missing"} after a ` +
          `completed embed; verdict=${report.verdict}; every row needing attention: ` +
          `${attentionRows(report)}`
        );
      }
      // What a completed embed leaves behind on this runner, named. The
      // model is cached and the fill is done, so `embedding_model` and
      // `semantic_query_readiness` are gone from the list the pre-embed
      // capture carries; the three below are the runner, not the embed.
      // This used to read `report.healthy !== true`, which passed on the
      // v0.6.1 run's own `kin-embedded-health.json` while those three
      // rows sat inside it unnamed (FIR-2919). Naming them is what makes
      // a fourth fail.
      const postEmbedAttention = new Map([
        ["projection_mode", ["stale"]],
        ["reference_edge_coverage", ["pending"]],
        ["memory_floor", ["degraded"]],
        // The census pass is not tied to `kin embed`, so a capture can
        // still beat it after a completed embed; same measurement as
        // the pre-embed entry (kin#1238).
        ["relation_census", ["pending"]],
      ]);
      const stillWaiting = report.checks.filter(
        (check) =>
          healthNeedsAttention(check) &&
          !(postEmbedAttention.get(check.id) ?? []).includes(check.status)
      );
      if (stillWaiting.length > 0) {
        throw new Error(
          `${reportPath}: rows needing attention after a completed embed that this ` +
          `runner does not expect: ` +
          `${stillWaiting.map((check) => `${check.id}=${check.status}`).join(", ")}; ` +
          `verdict=${report.verdict}`
        );
      }
    });
  }
  check("semantic kin search returns the seeded hello entity", () => {
    const semanticSearch = readJson("kin-semantic-search.json");
    if (!Array.isArray(semanticSearch) || !semanticSearch.some((record) => record.name === "hello" && record.file === "probe.py")) {
      throw new Error("semantic kin search did not return the seeded hello entity");
    }
  });
  check("semantic kin locate proves complete coverage and returns probe.py", () => {
    const semanticLocate = readJson("kin-semantic-locate.json");
    if (semanticLocate.semantic_coverage?.supported !== true || semanticLocate.semantic_coverage?.complete !== true || !semanticLocate.files?.some((entry) => entry.path === "probe.py")) {
      throw new Error(
        "semantic kin locate did not prove complete coverage and return probe.py; " +
        `semantic_coverage=${JSON.stringify(semanticLocate.semantic_coverage ?? null)} ` +
        `files=${JSON.stringify((semanticLocate.files ?? []).map((entry) => entry.path))}`
      );
    }
    return `semantic_coverage=${JSON.stringify(semanticLocate.semantic_coverage)}`;
  });
}

const counts = { PASS: 0, FAIL: 0, UNREADABLE: 0 };
for (const result of results) counts[result.status] += 1;
console.log(`validate: ${counts.PASS} pass, ${counts.FAIL} fail, ${counts.UNREADABLE} unreadable`);
if (process.env.PF_RESULT_JSON) {
  fs.writeFileSync(
    process.env.PF_RESULT_JSON,
    `${JSON.stringify({ ported_from: PORTED_FROM, counts, assertions: results }, null, 2)}\n`,
  );
}
process.exit(counts.FAIL > 0 ? 1 : counts.UNREADABLE > 0 ? 2 : 0);

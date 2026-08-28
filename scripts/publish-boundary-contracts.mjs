#!/usr/bin/env node

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const DEFAULT_REGISTRY_URL = "https://kinlab.ai/registry/npm/";
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const DRY_RUN = process.argv.includes("--dry-run");

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");
const packageDir = path.join(repoRoot, "packages", "boundary-contracts");
const packageJsonPath = path.join(packageDir, "package.json");

const packageJson = JSON.parse(await readFile(packageJsonPath, "utf8"));
const packageName = packageJson.name;
const packageVersion = packageJson.version;
const distTag = normalizeDistTag(process.env.KINLAB_NPM_DIST_TAG?.trim() || "latest");

if (packageName !== "@kin/boundary-contracts") {
  throw new Error(`expected ${packageJsonPath} to define @kin/boundary-contracts, got ${packageName}`);
}

if (!SEMVER_RE.test(packageVersion)) {
  throw new Error(`package version is not valid semver: ${packageVersion}`);
}

const tagName = process.env.TAG_NAME?.trim();
if (tagName && tagName !== packageVersion && tagName !== `v${packageVersion}`) {
  throw new Error(
    `package version ${packageVersion} does not match tag ${tagName}; expected ${packageVersion} or v${packageVersion}`,
  );
}

if (DRY_RUN) {
  console.log(`Dry run: validating npm publish payload for ${packageName}@${packageVersion}`);
  runNpmPublish(["--dry-run"]);
  process.exit(0);
}

const token = process.env.KINLAB_NPM_TOKEN?.trim();
if (!token) {
  throw new Error("KINLAB_NPM_TOKEN is required for registry publish");
}

const registryUrl = normalizeRegistryUrl(process.env.KINLAB_NPM_REGISTRY_URL || DEFAULT_REGISTRY_URL);
const versionUrl = new URL(
  `${encodePackageForMetadataPath(packageName)}/${packageVersion}`,
  registryUrl,
);

const versionResponse = await fetch(versionUrl, {
  headers: {
    authorization: `Bearer ${token}`,
    accept: "application/json",
  },
});

if (versionResponse.status === 200) {
  console.log(`${packageName}@${packageVersion} is already present in ${registryUrl.href}; skipping publish`);
  process.exit(0);
}

if (versionResponse.status !== 404) {
  const body = await versionResponse.text();
  throw new Error(
    `registry preflight failed with ${versionResponse.status} ${versionResponse.statusText}: ${body.trim() || "<empty body>"}`,
  );
}

const tempDir = await mkdtemp(path.join(os.tmpdir(), "kinlab-npm-"));
const userConfigPath = path.join(tempDir, ".npmrc");

try {
  await writeFile(
    userConfigPath,
    [
      `@kin:registry=${registryUrl.href}`,
      `${registryAuthLine(registryUrl)}=${token}`,
      "always-auth=true",
      "",
    ].join("\n"),
    "utf8",
  );

  console.log(`Publishing ${packageName}@${packageVersion} to ${registryUrl.href}`);
  runNpmPublish([
    "--registry",
    registryUrl.href,
    "--userconfig",
    userConfigPath,
    "--access",
    "public",
    "--tag",
    distTag,
  ]);
} finally {
  await rm(tempDir, { recursive: true, force: true });
}

function normalizeRegistryUrl(value) {
  const registryUrl = new URL(value);
  if (!registryUrl.pathname.endsWith("/")) {
    registryUrl.pathname = `${registryUrl.pathname}/`;
  }
  return registryUrl;
}

function encodePackageForMetadataPath(name) {
  // replaceAll, not replace: a string pattern replaces the first match only,
  // so any name carrying a second slash would reach the registry path
  // half-encoded. The one call site passes a name already proven equal to
  // @kin/boundary-contracts above, so this is correctness rather than a fix
  // for a reachable input.
  return name.replaceAll("/", "%2F");
}

function registryAuthLine(registryUrl) {
  return `//${registryUrl.host}${registryUrl.pathname}:_authToken`;
}

function normalizeDistTag(value) {
  if (!value) {
    return "latest";
  }
  return value;
}

function runNpmPublish(extraArgs) {
  const result = spawnSync(
    "npm",
    ["publish", "./packages/boundary-contracts", ...extraArgs],
    {
      cwd: repoRoot,
      stdio: "inherit",
      env: {
        ...process.env,
        npm_config_loglevel: process.env.npm_config_loglevel || "warn",
      },
    },
  );

  if (result.status !== 0) {
    throw new Error(`npm publish exited with status ${result.status ?? "unknown"}`);
  }
}

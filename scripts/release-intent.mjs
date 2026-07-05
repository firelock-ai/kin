import fs from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

// release-intent.mjs — the kin release-intent gate.
//
// A single source of truth for "is this commit a coherent release?". It reads
// the workspace version and asserts every surface that a tag-driven release
// depends on is already in sync, BEFORE a tag is cut:
//
//   - every npm package version (packages/kin-mcp and the canonical
//     packages/kin) equals the workspace version — release.yml's npm publish
//     jobs hard-assert this, so a mismatch would otherwise only surface AFTER
//     the tag is already pushed;
//   - a CHANGELOG section exists for the version (required for a stable
//     release; a warning for a prerelease, which falls back to auto-notes);
//   - the version moves strictly forward of the newest existing vX.Y.Z tag.
//
// Decision:
//   tag v<version> already exists      -> should_tag=false, exit 0 (idempotent;
//                                         a normal push that did not bump).
//   invariants hold, tag absent        -> should_tag=true,  exit 0 (cut it).
//   invariants fail, tag absent        -> exit 1 (a new version is staged but a
//                                         release surface is out of sync — fail
//                                         loud rather than cut a half-bumped
//                                         release).
//
// In CI it appends `version`, `tag`, and `should_tag` to $GITHUB_OUTPUT so the
// workflow stays thin. Run it locally (no args) to preview the verdict.

function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith('--')) {
      throw new Error(`invalid argument: ${key}`);
    }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      args.set(key.slice(2), 'true');
    } else {
      args.set(key.slice(2), next);
      i += 1;
    }
  }
  return {
    manifest: args.get('manifest') ?? 'Cargo.toml',
    npm: (args.get('npm') ?? 'packages/kin-mcp/package.json,packages/kin/package.json')
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean),
    changelog: args.get('changelog') ?? 'CHANGELOG.md',
    json: args.get('json') === 'true',
  };
}

// Read version from a Cargo manifest, honouring [package] / [workspace.package].
function readManifestVersion(text) {
  let section = '';
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line.startsWith('[') && line.endsWith(']')) {
      section = line;
      continue;
    }
    const m = line.match(/^version\s*=\s*"([^"]+)"/);
    if (m && (section === '[package]' || section === '[workspace.package]')) {
      return m[1];
    }
  }
  throw new Error(`could not read [workspace.package]/[package] version from manifest`);
}

function changelogHasSection(changelog, version) {
  const normalized = changelog.replace(/\r\n/g, '\n');
  const heading = `## [${version}]`;
  const start = normalized.indexOf(heading);
  if (start === -1) return false;
  const rest = normalized.slice(start + heading.length);
  const nextHeading = rest.indexOf('\n## [');
  const body = (nextHeading === -1 ? rest : rest.slice(0, nextHeading)).trim();
  return body.length > 0;
}

// Minimal semver compare: numeric core first, then prerelease (a prerelease
// sorts BEFORE its release; identifiers compared per the semver spec). Returns
// negative if a < b, positive if a > b, 0 if equal.
function parseSemver(v) {
  const [core, pre = ''] = v.replace(/^v/, '').split('-', 2);
  const nums = core.split('.').map((p) => (/^\d+$/.test(p) ? Number(p) : 0));
  while (nums.length < 3) nums.push(0);
  return { nums: nums.slice(0, 3), pre };
}

function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  for (let i = 0; i < 3; i += 1) {
    if (pa.nums[i] !== pb.nums[i]) return pa.nums[i] - pb.nums[i];
  }
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === '') return 1; // release > prerelease
  if (pb.pre === '') return -1;
  const ai = pa.pre.split('.');
  const bi = pb.pre.split('.');
  for (let i = 0; i < Math.max(ai.length, bi.length); i += 1) {
    if (ai[i] === undefined) return -1;
    if (bi[i] === undefined) return 1;
    const an = /^\d+$/.test(ai[i]);
    const bn = /^\d+$/.test(bi[i]);
    if (an && bn) {
      const d = Number(ai[i]) - Number(bi[i]);
      if (d !== 0) return d;
    } else if (an !== bn) {
      return an ? -1 : 1; // numeric identifiers are lower than alphanumeric
    } else if (ai[i] !== bi[i]) {
      return ai[i] < bi[i] ? -1 : 1;
    }
  }
  return 0;
}

async function gitTags() {
  try {
    const { stdout } = await run('git', ['tag', '--list', 'v*.*.*']);
    return stdout.split('\n').map((t) => t.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

async function readFileOrNull(path) {
  try {
    return await fs.readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function emitOutputs(outputs) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return Promise.resolve();
  const body = Object.entries(outputs).map(([k, v]) => `${k}=${v}`).join('\n');
  return fs.appendFile(file, `${body}\n`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  const manifestText = await readFileOrNull(opts.manifest);
  if (manifestText === null) throw new Error(`manifest not found: ${opts.manifest}`);
  const version = readManifestVersion(manifestText);
  const tag = `v${version}`;
  const isPrerelease = version.includes('-');

  const failures = [];
  const warnings = [];

  // 1. Every npm package version must equal the workspace version.
  const npmVersions = [];
  for (const manifest of opts.npm) {
    const npmText = await readFileOrNull(manifest);
    if (npmText === null) {
      failures.push(`npm manifest not found: ${manifest}`);
      npmVersions.push({ manifest, version: null });
      continue;
    }
    const v = JSON.parse(npmText).version;
    npmVersions.push({ manifest, version: v });
    if (v !== version) {
      failures.push(`npm manifest ${manifest} is ${v}, workspace is ${version} — they must match (the npm publish jobs assert it)`);
    }
  }
  const npmVersion = npmVersions.map((n) => `${n.manifest.split('/').slice(-2, -1)[0] ?? n.manifest}@${n.version ?? '<missing>'}`).join(', ');

  // 2. CHANGELOG section: required for a stable release, advisory for prereleases.
  const changelogText = await readFileOrNull(opts.changelog);
  const hasChangelog = changelogText !== null && changelogHasSection(changelogText, version);
  if (!hasChangelog) {
    const msg = `no non-empty "## [${version}]" section in ${opts.changelog}`;
    if (isPrerelease) warnings.push(`${msg} (prerelease falls back to auto-generated notes)`);
    else failures.push(msg);
  }

  // 3. Monotonicity + idempotency against existing tags.
  const tags = await gitTags();
  const tagExists = tags.includes(tag);
  const newest = tags.length ? tags.reduce((a, b) => (compareSemver(a, b) >= 0 ? a : b)) : null;
  if (!tagExists && newest && compareSemver(version, newest) <= 0) {
    failures.push(`${tag} would not move forward of the newest tag ${newest}`);
  }

  let shouldTag;
  let exitCode;
  let summary;
  if (tagExists) {
    shouldTag = false;
    exitCode = 0;
    summary = `${tag} already exists — nothing to release.`;
  } else if (failures.length === 0) {
    shouldTag = true;
    exitCode = 0;
    summary = `${tag} is a coherent release — ready to tag.`;
  } else {
    shouldTag = false;
    exitCode = 1;
    summary = `${tag} is staged but release surfaces are out of sync — refusing to tag.`;
  }

  if (opts.json) {
    console.log(JSON.stringify({ version, tag, npmVersion, newest, tagExists, shouldTag, hasChangelog, failures, warnings }, null, 2));
  } else {
    console.log('Kin release-intent gate');
    console.log(`  workspace version : ${version}`);
    console.log(`  npm packages      : ${npmVersion || '<missing>'}`);
    console.log(`  changelog section : ${hasChangelog ? 'present' : 'absent'}`);
    console.log(`  newest tag        : ${newest ?? '<none>'}`);
    console.log(`  tag ${tag}${' '.repeat(Math.max(0, 13 - tag.length))}: ${tagExists ? 'exists' : 'absent'}`);
    for (const w of warnings) console.log(`  warn: ${w}`);
    for (const f of failures) console.log(`  FAIL: ${f}`);
    console.log(`  => should_tag=${shouldTag}`);
    console.log(summary);
  }

  await emitOutputs({ version, tag, should_tag: String(shouldTag) });
  process.exitCode = exitCode;
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});

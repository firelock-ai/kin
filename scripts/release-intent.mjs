import fs from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);

// release-intent.mjs — the kin release-intent gate.
//
// A single source of truth for "is this commit a coherent release?". It reads
// the workspace version and asserts every surface that a tag-driven release
// depends on is already in sync, BEFORE a tag is cut:
//
//   - every tag-bound npm package version (packages/kin-mcp, the canonical
//     packages/kin, and packages/boundary-contracts) equals the workspace
//     version — release.yml's registry staging/publish jobs hard-assert this,
//     so a mismatch would otherwise only surface AFTER the tag is pushed;
//   - a CHANGELOG section exists for the version (required for a stable
//     release; a warning for a prerelease, which falls back to auto-notes);
//   - the version moves strictly forward of the newest existing vX.Y.Z tag.
//
// Decision:
//   tag exists, tree matches it        -> should_tag=false, exit 0 (idempotent;
//                                         a normal push that did not bump).
//   tag exists, release-affecting work
//   still sits after it                -> exit 1 (the bump is missing; see
//                                         the paragraph below).
//   invariants hold, tag absent        -> should_tag=true,  exit 0 (cut it).
//   invariants fail, tag absent        -> exit 1 (a new version is staged but a
//                                         release surface is out of sync, so
//                                         it fails loud rather than cut a
//                                         half-bumped release).
//
// The second row is the silent one. A version bump that never landed leaves
// the workspace version equal to the last released version, whose tag
// exists, so the idempotent branch used to swallow it: the mint reported a
// green notice and exited 0 on a fifteen-minute cron while the release never
// moved, and nothing else announced it, because the held-rail alarm only
// fires on a `held` marker and a dropped bump writes `clear`. The two facts
// that separate that row from a genuine no-op are whether the tag exists and
// whether this tree still carries release-affecting content the tag does
// not, so the gate reads exactly those two and refuses on both.
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
    npm: (args.get('npm') ?? 'packages/kin-mcp/package.json,packages/kin/package.json,packages/boundary-contracts/package.json')
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

// Is a changed path something a release actually ships?
//
// This mirrors `classifyPath` in scripts/check-release-version.mjs and is a
// deliberate copy rather than an import. release-tag.yml copies THIS FILE
// ALONE out of reviewed main into $RUNNER_TEMP, under a different basename,
// and runs it there against a detached checkout, so any relative import here
// resolves to a path that does not exist and the mint dies on a module
// resolution error instead of judging the release. The two copies are held
// together by a parity test over a shared corpus in release-intent.test.mjs,
// and a structural test in the same file refuses any relative import added to
// this one.
export function classifyPath(path) {
  const normalized = path.replaceAll('\\', '/').replace(/^\.\/+/, '');
  const lower = normalized.toLowerCase();
  const segments = lower.split('/');
  const basename = segments.at(-1) ?? '';

  if (
    lower.startsWith('.github/') ||
    lower.startsWith('docs/') ||
    lower === 'agents.md' ||
    lower === 'claude.md' ||
    lower === 'license' ||
    /\.(md|mdx|markdown|rst|adoc|txt)$/.test(lower)
  ) {
    return 'non-release';
  }

  if (
    segments.some((segment) =>
      ['test', 'tests', 'benches', 'bench', 'examples', 'example', 'fuzz', 'fixtures', 'snapshots']
        .includes(segment)) ||
    /(^test[-_].*|.*[-_.]test\.[^.]+|.*_test\.[^.]+)$/.test(basename)
  ) {
    return 'non-release';
  }

  return 'release';
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

// Release-affecting content this tree carries that the named tag does not.
//
// Two dots on purpose: this compares the two TREES, so a release-affecting
// change that a later commit reverted correctly reports nothing stranded, and
// no merge-listing quirk can undercount it the way a per-commit walk would.
// The commit count is reported beside it and is descriptive only; the decision
// is the path set.
async function releaseDriftSinceTag(tag) {
  const { stdout: names } = await run(
    'git',
    ['diff', '--name-only', '-z', `${tag}..HEAD`],
    { maxBuffer: 16 * 1024 * 1024 },
  );
  const strandedPaths = names
    .split('\0')
    .filter(Boolean)
    .filter((path) => classifyPath(path) === 'release');
  let commitsSinceTag = 0;
  try {
    const { stdout: count } = await run('git', ['rev-list', '--count', `${tag}..HEAD`]);
    commitsSinceTag = Number.parseInt(count.trim(), 10) || 0;
  } catch {
    commitsSinceTag = 0;
  }
  return { strandedPaths, commitsSinceTag };
}

// The whole verdict, as a pure function, so every row of the decision table is
// reachable from a test without a repository, a tag, or a git process.
export function decideReleaseIntent({
  tag,
  tagExists,
  failures = [],
  strandedPaths = [],
  commitsSinceTag = 0,
}) {
  if (tagExists && strandedPaths.length > 0) {
    return {
      shouldTag: false,
      exitCode: 1,
      stranded: true,
      summary:
        `${tag} already exists, but this tree still carries ` +
        `${strandedPaths.length} release-affecting path(s) it does not, across ` +
        `${commitsSinceTag} commit(s). The version bump is missing, so this ` +
        `release would be a silent no-op.`,
    };
  }
  if (tagExists) {
    return {
      shouldTag: false,
      exitCode: 0,
      stranded: false,
      summary: `${tag} already exists, so there is nothing to release.`,
    };
  }
  if (failures.length === 0) {
    return {
      shouldTag: true,
      exitCode: 0,
      stranded: false,
      summary: `${tag} is a coherent release. Ready to tag.`,
    };
  }
  return {
    shouldTag: false,
    exitCode: 1,
    stranded: false,
    summary: `${tag} is staged but release surfaces are out of sync. Refusing to tag.`,
  };
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
      failures.push(`npm manifest ${manifest} is ${v}, workspace is ${version} — they must match (the npm staging jobs assert it)`);
    }
  }
  const npmVersion = npmVersions.map((n) => `${n.manifest.split('/').slice(-2, -1)[0] ?? n.manifest}@${n.version ?? '<missing>'}`).join(', ');

  // 1b. Cargo's explicit internal path-version pin and every local Kin
  // workspace entry in Cargo.lock must move with the workspace version. A
  // global text replacement is forbidden: third-party packages such as
  // async-stream can legitimately have the same numeric version.
  const cliManifestPath = 'crates/kin-cli/Cargo.toml';
  const cliManifest = await readFileOrNull(cliManifestPath);
  const spinePin = cliManifest?.match(
    /^kin-spine\s*=\s*\{[^\n]*version\s*=\s*"([^"]+)"[^\n]*\}$/m,
  )?.[1] ?? null;
  if (spinePin !== version) {
    failures.push(
      `${cliManifestPath} kin-spine path-version pin is ${spinePin ?? '<missing>'}, workspace is ${version}`,
    );
  }

  const cargoLockPath = 'Cargo.lock';
  const cargoLock = await readFileOrNull(cargoLockPath);
  const localLockVersions = [];
  if (cargoLock === null) {
    failures.push(`${cargoLockPath} not found`);
  } else {
    for (const block of cargoLock.split('[[package]]').slice(1)) {
      if (/^source\s*=/m.test(block)) continue;
      const name = block.match(/^name = "([^"]+)"/m)?.[1] ?? null;
      const locked = block.match(/^version = "([^"]+)"/m)?.[1] ?? null;
      if (!name?.startsWith('kin-')) continue;
      localLockVersions.push({ name, version: locked });
      if (locked !== version) {
        failures.push(
          `${cargoLockPath} local package ${name} is ${locked ?? '<missing>'}, workspace is ${version}`,
        );
      }
    }
    if (localLockVersions.length === 0) {
      failures.push(`${cargoLockPath} has no local Kin workspace packages`);
    }
  }

  // 1c. The fuzz workspace resolves kin-parser by path, so its lockfile carries
  // the workspace version as well. A stale entry only surfaces in the fuzz job's
  // --locked resolution, which runs after the release commit already exists.
  const fuzzLockPath = 'fuzz/Cargo.lock';
  const fuzzLock = await readFileOrNull(fuzzLockPath);
  if (fuzzLock === null) {
    failures.push(`${fuzzLockPath} not found`);
  } else {
    let fuzzLocal = 0;
    for (const block of fuzzLock.split('[[package]]').slice(1)) {
      if (/^source\s*=/m.test(block)) continue;
      const name = block.match(/^name = "([^"]+)"/m)?.[1] ?? null;
      const locked = block.match(/^version = "([^"]+)"/m)?.[1] ?? null;
      if (name !== 'kin-parser') continue;
      fuzzLocal += 1;
      if (locked !== version) {
        failures.push(
          `${fuzzLockPath} local package ${name} is ${locked ?? '<missing>'}, workspace is ${version}`,
        );
      }
    }
    if (fuzzLocal === 0) {
      failures.push(`${fuzzLockPath} has no path-resolved kin-parser entry`);
    }
  }

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

  // Only ask git about drift when the tag exists, which is the one branch
  // where the answer changes the verdict. A failure here is loud on purpose:
  // `tagExists` already proves `git tag --list` worked and the tag is present,
  // so a diff that cannot run is anomalous, and a swallowed error would put the
  // gate straight back to reporting the silent no-op it exists to catch.
  const drift = tagExists
    ? await releaseDriftSinceTag(tag)
    : { strandedPaths: [], commitsSinceTag: 0 };
  const { shouldTag, exitCode, stranded, summary } = decideReleaseIntent({
    tag,
    tagExists,
    failures,
    strandedPaths: drift.strandedPaths,
    commitsSinceTag: drift.commitsSinceTag,
  });

  if (opts.json) {
    console.log(JSON.stringify({ version, tag, npmVersion, newest, tagExists, stranded, strandedPaths: drift.strandedPaths, commitsSinceTag: drift.commitsSinceTag, shouldTag, hasChangelog, failures, warnings }, null, 2));
  } else {
    console.log('Kin release-intent gate');
    console.log(`  workspace version : ${version}`);
    console.log(`  npm packages      : ${npmVersion || '<missing>'}`);
    console.log(`  kin-spine pin     : ${spinePin ?? '<missing>'}`);
    console.log(`  local lock entries: ${localLockVersions.length}`);
    console.log(`  changelog section : ${hasChangelog ? 'present' : 'absent'}`);
    console.log(`  newest tag        : ${newest ?? '<none>'}`);
    console.log(`  tag ${tag}${' '.repeat(Math.max(0, 13 - tag.length))}: ${tagExists ? 'exists' : 'absent'}`);
    console.log(`  stranded paths    : ${drift.strandedPaths.length}`);
    for (const path of drift.strandedPaths.slice(0, 30)) console.log(`    - ${path}`);
    if (drift.strandedPaths.length > 30) {
      console.log(`    ... ${drift.strandedPaths.length - 30} more`);
    }
    for (const w of warnings) console.log(`  warn: ${w}`);
    for (const f of failures) console.log(`  FAIL: ${f}`);
    console.log(`  => should_tag=${shouldTag}`);
    console.log(summary);
  }

  // An annotation, not a runner-state write: release-tag.yml hands this process
  // inert GITHUB_ENV/PATH/STATE files and fails the job if any of them grows, so
  // the only way for a stranded release to say so where an operator will see it
  // is a workflow command on stdout.
  if (stranded) console.log(`::error::${summary}`);

  await emitOutputs({ version, tag, should_tag: String(shouldTag) });
  process.exitCode = exitCode;
}

// Run only when this file IS the entry point, so a test can import the pure
// functions above without `main()` reading the test runner's own working tree.
//
// Compare REAL paths. The usual idiom compares `import.meta.url` against
// `pathToFileURL(process.argv[1])`, and that is wrong here: Node resolves
// symlinks for `import.meta.url` and does not for `argv[1]`, so invoking a copy
// of this file through a symlinked directory makes the two disagree and the
// gate exits 0 having judged nothing. release-tag.yml runs exactly that way, on
// a copy under a different basename inside $RUNNER_TEMP, and the mint's next
// step reads the outputs this file never wrote. Verified against a
// `/tmp -> /private/tmp` copy, where the naive form did not run at all.
//
// Unresolvable paths fall to running, not skipping. A gate that silently
// declines to judge is the failure this file exists to end; a test that runs
// `main()` by mistake fails loudly on the spot.
function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return false;
  const self = fileURLToPath(import.meta.url);
  if (entry === self) return true;
  try {
    return realpathSync(entry) === realpathSync(self);
  } catch {
    return true;
  }
}

if (isDirectRun()) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

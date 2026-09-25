#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Install this run's archive with the real installer, then bind both installed
// components to the checked-out source and the build's inventory. No release API.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readUpdateBuildIdentity } from './read-update-build-identity.cjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const PLATFORMS = {
  'linux:x64': ['kin-linux-x86_64', 'x86_64-unknown-linux-musl'],
  'linux:arm64': ['kin-linux-aarch64', 'aarch64-unknown-linux-musl'],
  'darwin:x64': ['kin-macos-x86_64', 'x86_64-apple-darwin'],
  'darwin:arm64': ['kin-macos-aarch64', 'aarch64-apple-darwin'],
  'win32:x64': ['kin-windows-x86_64', 'x86_64-pc-windows-msvc'],
};
export const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const readRegular = (name) => {
  const stat = fs.lstatSync(name);
  assert.ok(stat.isFile(), `not a regular file: ${name}`);
  assert.ok(stat.size <= 512 * 1024 * 1024, `candidate file exceeds 512 MiB: ${name}`);
  return fs.readFileSync(name);
};

export function installerHostScope(platform, env) {
  if (platform === 'win32') {
    // install.ps1 changes HKCU User PATH and uses the runner's temporary area.
    // HOME/USERPROFILE do not isolate that Windows account. Do not offer this
    // proof as a safe installer experiment on a persistent Windows account.
    assert.equal(env.GITHUB_ACTIONS, 'true', 'Windows installer proof requires disposable GitHub-hosted Actions');
    assert.equal(env.RUNNER_ENVIRONMENT, 'github-hosted', 'Windows installer proof refuses persistent/self-hosted runners');
    return { kin_home: 'fresh isolated directory', host: 'disposable GitHub-hosted runner',
      user_path_restored: false, installer_temporary_state: 'runner temporary area',
      host_cleanup_owner: 'GitHub-hosted runner teardown, not this proof driver' };
  }
  return { kin_home: 'fresh isolated directory', host_cleanup_owner: 'runner teardown',
    user_path_restored: null };
}

export function validateManifest(m, expected) {
  const { platform, arch, artifact, commit, lock, version, repository, runId, attempt } = expected;
  assert.deepEqual(PLATFORMS[`${platform}:${arch}`], [artifact, m.target], 'native platform mismatch');
  assert.equal(m.schema_version, 2);
  assert.equal(m.release_tag, undefined, 'published release is not a candidate');
  assert.deepEqual(m.release_candidate, { ref: commit, version });
  assert.equal(m.artifact, artifact);
  assert.deepEqual(m.kin, { commit, cargo_lock_sha256: lock, embedded_dependency_provenance: lock });
  assert.deepEqual(m.workflow, { repository, run_id: runId, run_attempt: attempt });
  const suffix = platform === 'win32' ? '.exe' : '';
  const names = [`kin${suffix}`, `kin-daemon${suffix}`];
  assert.ok(Array.isArray(m.archive_contents));
  assert.equal(new Set(m.archive_contents.map((r) => r.name)).size, m.archive_contents.length, 'duplicate component');
  const components = names.map((name) => {
    const row = m.archive_contents.find((r) => r.name === name);
    assert.ok(row && /^[a-f0-9]{64}$/.test(row.sha256), `missing component ${name}`);
    assert.ok(Number.isSafeInteger(row.size_bytes) && row.size_bytes > 0);
    const identity = row.build_identity;
    assert.equal(identity?.schema, 'kin.update-build.v1');
    assert.equal(identity.version, version);
    assert.equal(identity.commit, commit);
    assert.equal(identity.clean, true);
    assert.equal(identity.source_known, true);
    assert.equal(identity.dependency_provenance, lock);
    assert.ok(Number.isSafeInteger(identity.graph_snapshot_version) && identity.graph_snapshot_version > 0);
    return row;
  });
  assert.equal(components[0].build_identity.graph_snapshot_version, components[1].build_identity.graph_snapshot_version);
  const archive = `${artifact}.${platform === 'win32' ? 'zip' : 'tar.gz'}`;
  assert.equal(m.archive?.name, archive);
  assert.match(m.archive.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(m.archive.size_bytes) && m.archive.size_bytes > 0);
  return { archive, components };
}

export function verifyInstalledComponent(name, component) {
  const bytes = readRegular(name);
  assert.equal(bytes.length, component.size_bytes, 'installed component size changed');
  assert.equal(digest(bytes), component.sha256, 'installed component bytes changed');
  assert.deepEqual(readUpdateBuildIdentity(name), component.build_identity, 'installed static identity changed');
}

export function validateArchive(bytes, checksum, record) {
  assert.equal(bytes.length, record.size_bytes, 'archive size mismatch');
  assert.equal(digest(bytes), record.sha256, 'archive digest mismatch');
  const rows = checksum.trim().split(/\r?\n/);
  assert.equal(rows.length, 1, 'ambiguous archive checksum');
  assert.equal(rows[0].replace(/  \*/, '  '), `${record.sha256}  ${record.name}`, 'archive checksum identity mismatch');
}

// A loopback mirror exercises both real download paths, including PowerShell's
// checksum request, without assuming its Invoke-WebRequest accepts file://.
export async function serveArchive(version, name, archive, checksum) {
  const routes = new Map([
    [`/download/v${version}/${name}`, archive],
    [`/download/v${version}/${name}.sha256`, checksum],
  ]);
  const requests = [];
  const server = http.createServer((req, res) => {
    const body = req.method === 'GET' && routes.get(req.url);
    requests.push({ method: req.method, path: req.url, status: body ? 200 : 404 });
    res.writeHead(body ? 200 : 404, { 'Content-Length': body ? body.length : 0 });
    res.end(body || undefined);
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { url: `http://127.0.0.1:${server.address().port}`, requests, close: async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  } };
}

export async function runCommand(executable, args, { cwd, env, prefix, deadline }) {
  const remaining = deadline - Date.now();
  assert.ok(remaining > 0, 'candidate install deadline elapsed');
  const out = fs.openSync(`${prefix}.stdout`, 'wx');
  const err = fs.openSync(`${prefix}.stderr`, 'wx');
  const child = spawn(executable, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
  let issue = null, bytes = 0;
  const chunks = [];
  const stop = (why) => {
    if (issue) return;
    issue = why;
    if (child.pid) {
      if (process.platform === 'win32') {
        const killer = spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', timeout: 10_000 });
        killer.on('error', () => child.kill());
        killer.on('close', (code) => { if (code !== 0) child.kill(); });
      } else {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
      }
    }
  };
  const timer = setTimeout(() => stop('candidate command timed out'), remaining);
  for (const [stream, fd, capture] of [[child.stdout, out, true], [child.stderr, err, false]]) {
    stream.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > 8 * 1024 * 1024) return stop('candidate command output exceeded 8 MiB');
      fs.writeSync(fd, chunk);
      if (capture) chunks.push(chunk);
    });
  }
  let error;
  child.on('error', (value) => { error = value; });
  const result = await new Promise((resolve) => child.on('close', (code, signal) => resolve({ code, signal })));
  clearTimeout(timer); fs.closeSync(out); fs.closeSync(err);
  fs.writeFileSync(`${prefix}.exit.json`, JSON.stringify({ ...result, issue, error: error?.message }) + '\n', { flag: 'wx' });
  assert.ok(!error && !issue && result.code === 0 && result.signal === null,
    `${path.basename(prefix)} failed: ${error?.message || issue || JSON.stringify(result)}`);
  return Buffer.concat(chunks).toString('utf8');
}

export async function main() {
  assert.ok(process.env.RUNNER_TEMP && process.env.ARTIFACT, 'requires candidate workflow environment');
  const output = path.join(process.env.RUNNER_TEMP, 'kin-candidate-install');
  fs.mkdirSync(output); // Refuse reuse of any earlier proof or install.
  const result = { schema: 'kin.candidate-install.v1', passed: false, platform: process.platform, arch: process.arch };
  let mirror;
  try {
    result.host_scope = installerHostScope(process.platform, process.env);
    const deadline = Date.now() + 300_000;
    const git = (...args) => execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', timeout: 10_000 }).trim();
    const commit = git('rev-parse', 'HEAD');
    assert.equal(commit, process.env.GITHUB_SHA, 'checkout differs from dispatched source');
    assert.equal(git('status', '--porcelain', '--untracked-files=all'), '', 'candidate checkout is dirty');
    const lock = digest(readRegular(path.join(ROOT, 'Cargo.lock')));
    const cargo = readRegular(path.join(ROOT, 'Cargo.toml')).toString();
    const version = /^\[workspace\.package\]\s*\n(?:(?!^\[).)*?^version\s*=\s*"([^"]+)"/ms.exec(cargo)?.[1];
    assert.ok(version, 'workspace version missing');
    const expected = { platform: process.platform, arch: process.arch, artifact: process.env.ARTIFACT,
      commit, lock, version, repository: process.env.GITHUB_REPOSITORY,
      runId: process.env.GITHUB_RUN_ID, attempt: process.env.GITHUB_RUN_ATTEMPT };
    assert.ok(expected.repository && expected.runId && expected.attempt, 'workflow run identity missing');
    const staged = path.join(process.env.RUNNER_TEMP, 'kin-candidate');
    const manifestBytes = readRegular(path.join(staged, `${expected.artifact}.provenance.json`));
    const manifest = JSON.parse(manifestBytes);
    const { archive, components } = validateManifest(manifest, expected);
    const archiveBytes = readRegular(path.join(staged, archive));
    const checksum = readRegular(path.join(staged, `${archive}.sha256`));
    validateArchive(archiveBytes, checksum.toString(), manifest.archive);
    Object.assign(result, { expected, manifest_sha256: digest(manifestBytes), archive: manifest.archive, components });
    fs.writeFileSync(path.join(output, 'provenance.json'), manifestBytes);
    const home = path.join(output, 'home'), kinHome = path.join(home, '.kin');
    fs.mkdirSync(home, { mode: 0o700 });
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) =>
      !/^(?:_?KIN_|GIT_|DYLD_|LD_|HOME$|USERPROFILE$|APPDATA$|LOCALAPPDATA$|XDG_)/i.test(k)));
    Object.assign(env, { HOME: home, USERPROFILE: home, KIN_HOME: kinHome, KIN_DIR: kinHome,
      KIN_NO_SETUP: '1', KIN_VERSION: version, KIN_REGISTRY_PATH: path.join(home, 'registry.toml'),
      APPDATA: path.join(home, 'appdata'), LOCALAPPDATA: path.join(home, 'local-appdata'),
      XDG_CONFIG_HOME: path.join(home, 'config'), XDG_CACHE_HOME: path.join(home, 'cache') });
    mirror = await serveArchive(version, archive, archiveBytes, checksum);
    env.KIN_BASE_URL = mirror.url;
    const windows = process.platform === 'win32';
    const installer = path.join(ROOT, 'scripts', windows ? 'install.ps1' : 'install.sh');
    result.installer_sha256 = digest(readRegular(installer));
    const run = (exe, args, label) => runCommand(exe, args, { cwd: home, env,
      prefix: path.join(output, label), deadline });
    await run(windows ? 'pwsh' : 'sh', windows ? ['-NoProfile', '-NonInteractive', '-File', installer] : [installer], 'installer');
    result.downloads = mirror.requests;
    for (const suffix of ['', '.sha256']) {
      assert.ok(mirror.requests.some((r) => r.status === 200 && r.path === `/download/v${version}/${archive}${suffix}`), 'installer did not fetch exact archive and checksum');
    }
    const bin = path.join(kinHome, 'bin');
    for (const component of components) {
      const name = path.join(bin, component.name);
      verifyInstalledComponent(name, component);
      const line = await run(name, ['--version'], component.name);
      assert.ok(line.startsWith(`${component.name.replace(/\.exe$/, '')} ${version} (${commit} `), 'executed version/source mismatch');
    }
    const meta = JSON.parse(await run(path.join(bin, windows ? 'kin.exe' : 'kin'), ['bench-meta', '--json'], 'bench-meta'));
    assert.equal(meta.kin_commit, commit); assert.equal(meta.kin_version, version);
    assert.equal(meta.kin_dirty, false); assert.equal(meta.kin_source_known, true);
    assert.equal(meta.dependency_provenance, lock);
    result.scope = 'native archive installation and exact CLI/daemon identity; no signing, public delivery, upgrade or full first-contact claim';
    if (process.env.GITHUB_PATH) fs.appendFileSync(process.env.GITHUB_PATH, `${bin}\n`);
    if (process.env.GITHUB_ENV) for (const key of ['HOME', 'KIN_HOME', 'KIN_DIR', 'KIN_REGISTRY_PATH']) {
      assert.ok(!/[\r\n]/.test(env[key])); fs.appendFileSync(process.env.GITHUB_ENV, `${key}=${env[key]}\n`);
    }
    result.passed = true;
  } catch (error) {
    result.error = error.stack; throw error;
  } finally {
    if (mirror) {
      result.downloads = mirror.requests;
      try { await mirror.close(); result.mirror_closed = true; }
      catch (error) { result.passed = false; result.cleanup_error = error.stack; process.exitCode = 1; }
    }
    fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify(result, null, 2) + '\n');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error); process.exitCode = 1; });
}

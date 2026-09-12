// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import cp from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const sourceRoot = path.resolve(here, '../..');
const version = '7.8.9';

const controlledNpx = [
  '#!/usr/bin/env node',
  "const fs = require('node:fs');",
  "const path = require('node:path');",
  '',
  'const args = process.argv.slice(2);',
  'const record = process.env.MCPB_TEST_NPX_RECORD;',
  'if (!record) throw new Error("MCPB_TEST_NPX_RECORD is required");',
  "fs.appendFileSync(record, JSON.stringify({ args, cwd: process.cwd() }) + '\\n');",
  '',
  'if (',
  '  args.length === 5 &&',
  "  args[0] === '-y' &&",
  "  args[1] === '@anthropic-ai/mcpb' &&",
  "  args[2] === 'pack'",
  ') {',
  '  const stage = args[3];',
  '  const output = args[4];',
  '  const capture = process.env.MCPB_TEST_NPX_CAPTURE;',
  '  if (!capture) throw new Error("MCPB_TEST_NPX_CAPTURE is required for pack");',
  '  fs.cpSync(stage, capture, { recursive: true });',
  "  const manifest = JSON.parse(fs.readFileSync(path.join(stage, 'manifest.json'), 'utf8'));",
  "  const releaseIdentity = JSON.parse(fs.readFileSync(path.join(stage, 'release-identity.json'), 'utf8'));",
  "  fs.writeFileSync(output, JSON.stringify({ manifest, releaseIdentity }) + '\\n');",
  '  process.exit(0);',
  '}',
  '',
  'if (',
  '  args.length === 2 &&',
  "  args[0] === '-y' &&",
  "  /^@kinlab\\/kin-mcp@\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?$/.test(args[1])",
  ') {',
  '  process.exit(0);',
  '}',
  '',
  "process.stderr.write('unexpected controlled npx invocation: ' + JSON.stringify(args) + '\\n');",
  'process.exit(64);',
  ''
].join('\n');

function commandResult(command, args, options) {
  return cp.spawnSync(command, args, {
    encoding: 'utf8',
    ...options
  });
}

async function createFixture({ mcpVersion = version, kinVersion = version } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcpb-build-test-'));
  const mcpb = path.join(root, 'scripts', 'mcpb');
  const fakeBin = path.join(root, 'fake-bin');
  const capture = path.join(root, 'captured-pack');
  const npxRecord = path.join(root, 'npx-record.jsonl');
  const output = path.join(root, 'out', 'kin.mcpb');
  const workspace = path.join(root, 'workspace');

  await fs.mkdir(path.join(root, 'assets', 'mcp'), { recursive: true });
  await fs.mkdir(path.join(root, 'packages', 'kin-mcp'), { recursive: true });
  await fs.mkdir(path.join(root, 'packages', 'kin'), { recursive: true });
  await fs.mkdir(path.join(mcpb, 'server'), { recursive: true });
  await fs.mkdir(fakeBin, { recursive: true });
  await fs.mkdir(path.dirname(output), { recursive: true });
  await fs.mkdir(workspace, { recursive: true });

  await Promise.all([
    fs.writeFile(path.join(root, 'assets', 'mcp', 'icon-512.png'), 'fixture icon'),
    fs.writeFile(
      path.join(root, 'packages', 'kin-mcp', 'package.json'),
      JSON.stringify({ name: '@kinlab/kin-mcp', version: mcpVersion }) + '\n'
    ),
    fs.writeFile(
      path.join(root, 'packages', 'kin', 'package.json'),
      JSON.stringify({ name: '@kinlab/kin', version: kinVersion }) + '\n'
    ),
    fs.copyFile(path.join(sourceRoot, 'scripts', 'mcpb', 'build.sh'), path.join(mcpb, 'build.sh')),
    fs.copyFile(
      path.join(sourceRoot, 'scripts', 'mcpb', 'manifest.json'),
      path.join(mcpb, 'manifest.json')
    ),
    fs.copyFile(
      path.join(sourceRoot, 'scripts', 'mcpb', 'server', 'index.js'),
      path.join(mcpb, 'server', 'index.js')
    ),
    fs.writeFile(path.join(fakeBin, 'npx'), controlledNpx, { mode: 0o755 })
  ]);

  const env = {
    ...process.env,
    PATH: [fakeBin, process.env.PATH || ''].filter(Boolean).join(path.delimiter),
    KIN_MCPB_OUTPUT: output,
    MCPB_TEST_NPX_CAPTURE: capture,
    MCPB_TEST_NPX_RECORD: npxRecord
  };
  return { root, mcpb, capture, npxRecord, output, workspace, env };
}

async function readNpxCalls(record) {
  const lines = (await fs.readFile(record, 'utf8'))
    .trim()
    .split('\n')
    .filter(Boolean);
  return lines.map(line => JSON.parse(line));
}

test(
  'the MCPB builder packs a version-pinned manifest and launcher',
  { skip: process.platform === 'win32' },
  async () => {
    const fixture = await createFixture();
    try {
      const build = commandResult('bash', [path.join(fixture.mcpb, 'build.sh')], {
        cwd: fixture.root,
        env: fixture.env
      });
      assert.equal(build.status, 0, build.stdout + '\n' + build.stderr);

      const packed = JSON.parse(await fs.readFile(fixture.output, 'utf8'));
      assert.equal(packed.manifest.version, version);
      assert.equal(packed.releaseIdentity.launcher, '@kinlab/kin-mcp@' + version);
      assert.equal(packed.releaseIdentity.native_release_tag, 'v' + version);

      const stagedLauncher = path.join(fixture.capture, 'server', 'index.js');
      const launch = commandResult(process.execPath, [stagedLauncher], {
        cwd: fixture.workspace,
        env: {
          ...fixture.env,
          KIN_MCP_REPO: fixture.workspace
        }
      });
      assert.equal(launch.status, 0, launch.stdout + '\n' + launch.stderr);

      const calls = await readNpxCalls(fixture.npxRecord);
      assert.equal(calls.length, 2);
      assert.deepEqual(calls[0].args.slice(0, 3), ['-y', '@anthropic-ai/mcpb', 'pack']);
      assert.deepEqual(calls[1], {
        args: ['-y', '@kinlab/kin-mcp@' + version],
        cwd: await fs.realpath(fixture.workspace)
      });
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  }
);

test(
  'the MCPB builder rejects package-version drift before packing',
  { skip: process.platform === 'win32' },
  async () => {
    const fixture = await createFixture({ kinVersion: '7.8.10' });
    try {
      const build = commandResult('bash', [path.join(fixture.mcpb, 'build.sh')], {
        cwd: fixture.root,
        env: fixture.env
      });
      assert.notEqual(build.status, 0);
      assert.match(build.stderr, /does not match/);
      await assert.rejects(fs.access(fixture.npxRecord));
      await assert.rejects(fs.access(fixture.output));
    } finally {
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  }
);

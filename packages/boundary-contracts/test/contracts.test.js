// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import test from 'node:test';
import assert from 'node:assert/strict';
import cp from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { assertContract, loadAllSchemas, validateContract } from '../src/index.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const gitHubRoot = path.resolve(root, '..', '..', '..');
const fsAdapterPath = path.join(gitHubRoot, 'kin', 'packages', 'fs-adapter', 'bin', 'kin-fs-adapter.js');
const scmAdapterPath = path.join(gitHubRoot, 'kin', 'packages', 'scm-adapter', 'bin', 'kin-scm-adapter.js');
const graphServicePath = path.join(gitHubRoot, 'kin', 'packages', 'graph-service', 'bin', 'kin-graph-service.js');
const kinBinaryPath = resolveKinBinaryPath();

test('all schemas load', async () => {
  const schemas = await loadAllSchemas();
  assert.ok(schemas.workspaceContext);
  assert.ok(schemas.kinCommandResult);
  assert.ok(schemas.scmSnapshot);
  assert.ok(schemas.scmResourceGroups);
  assert.ok(schemas.shadowGateReport);
});

test('shadow gate report contract accepts the kin review shadow payload shape', async () => {
  // Canonical shape emitted by `kin review shadow --json` (kin-review::shadow).
  // The live payload is asserted against the same required fields by the
  // review_shadow_json integration test in the kin workspace.
  const report = {
    schema_version: 1,
    mode: 'shadow',
    input: {
      base_ref: 'main',
      head_ref: 'feature/change',
      resolved_base: 'a'.repeat(64),
      resolved_head: 'b'.repeat(64),
      title: 'Example PR'
    },
    changed_entities: [
      {
        entity_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        name: 'compute_total',
        kind: 'Function',
        change: 'modified',
        file: 'src/billing.rs',
        start_line: 10,
        end_line: 12,
        signature_changed: true,
        visibility_changed: false
      }
    ],
    blast_radius: {
      callers: [],
      dependents: [
        {
          entity_id: '3fa85f64-5717-4562-b3fc-2c963f66afa7',
          name: 'render_invoice',
          kind: 'Function',
          file: 'src/invoice.rs',
          via: 'depends_on'
        }
      ],
      contract_consumers: [],
      tests: [
        {
          entity_id: '3fa85f64-5717-4562-b3fc-2c963f66afa8',
          name: 'test_compute_total',
          kind: 'Function',
          file: 'tests/billing.rs',
          via: 'tests'
        }
      ],
      open_work_items: [],
      total_affected: 2,
      cross_repo: {
        status: 'not_evaluated',
        detail: 'cross-repo federation is not evaluated by shadow report v1',
        nodes: []
      }
    },
    policy: {
      enforcement: 'report_only',
      verdict: 'would_block',
      risk_level: 'medium',
      blocking_count: 1,
      attention_count: 1,
      summary: '1 blocking finding(s), 1 attention signal(s); would block in enforcing mode',
      findings: [
        {
          kind: 'downstream_risk',
          severity: 'error',
          blocking: true,
          message: 'Contract surface of `compute_total` changed with 1 graph-known downstream entity(ies)',
          file: 'src/billing.rs',
          line: 10
        }
      ]
    },
    repair_context: [
      {
        finding: 'Contract surface of `compute_total` changed with 1 graph-known downstream entity(ies)',
        kind: 'downstream_risk',
        file: 'src/billing.rs',
        line: 10,
        covering_tests: ['test_compute_total (tests/billing.rs)'],
        affected_consumers: [],
        guidance: 'Verify each listed dependent and consumer, then run the covering tests.'
      }
    ],
    evidence_gaps: [
      {
        kind: 'cross_repo_not_evaluated',
        subject: 'blast_radius.cross_repo',
        detail: 'cross-repo federation is not evaluated by shadow report v1'
      }
    ],
    audit: {
      generated_at: '2026-07-01T00:00:00Z',
      actor: 'ci-runner',
      actor_kind: 'service',
      tool: 'kin-review',
      tool_version: '0.0.0',
      base_change: 'a'.repeat(64),
      head_change: 'b'.repeat(64),
      changes_in_range: 1,
      entity_attribution: [],
      head_approvals: []
    }
  };

  await assertContract('shadowGateReport', report);

  // The contract must reject payloads that claim enforcement.
  const enforcing = structuredClone(report);
  enforcing.policy.enforcement = 'blocking';
  const rejected = await validateContract('shadowGateReport', enforcing);
  assert.equal(rejected.ok, false);
});

test('graph service and fs adapter outputs conform to shared workspace contracts', async () => {
  const repoRoot = await makeFixtureRepo();

  const graphContext = runJson(graphServicePath, ['context', '--repo', repoRoot]);
  await assertContract('workspaceContext', graphContext);

  const graphEntries = runJson(graphServicePath, ['read-dir', '--repo', repoRoot, '--path', '/src']);
  await assertContract('directoryList', graphEntries);

  const graphContent = runJson(graphServicePath, ['read-file', '--repo', repoRoot, '--path', '/src/app.ts']);
  await assertContract('fileContent', graphContent);

  const fsContext = runJson(fsAdapterPath, ['context', '--repo', repoRoot, '--backendMode', 'graphNative', '--graphServicePath', graphServicePath]);
  await assertContract('workspaceContext', fsContext);

  const fsStat = runJson(fsAdapterPath, ['stat', '--repo', repoRoot, '--backendMode', 'graphNative', '--graphServicePath', graphServicePath, '--path', '/src/app.ts']);
  await assertContract('fileStat', fsStat);
});

test('scm adapter outputs conform to shared scm contracts', async () => {
  const repoRoot = await makeInitializedFixtureRepo();

  const context = runJson(scmAdapterPath, ['context', '--repo', repoRoot, '--kin', kinBinaryPath]);
  await assertContract('scmContext', context);

  const snapshot = runJson(scmAdapterPath, ['snapshot', '--repo', repoRoot, '--kin', kinBinaryPath]);
  await assertContract('scmSnapshot', snapshot);

  const groups = runJson(scmAdapterPath, ['resource-groups', '--repo', repoRoot, '--kin', kinBinaryPath]);
  await assertContract('scmResourceGroups', groups);

  const trace = runJson(scmAdapterPath, ['trace', '--repo', repoRoot, '--kin', kinBinaryPath, '--entity', 'KinLayout']);
  await assertContract('kinCommandResult', trace);

  const history = runJson(scmAdapterPath, ['history', '--repo', repoRoot, '--kin', kinBinaryPath, '--entity', 'KinLayout']);
  await assertContract('kinCommandResult', history);

  const review = runJson(scmAdapterPath, ['review', '--repo', repoRoot, '--kin', kinBinaryPath]);
  await assertContract('kinCommandResult', review);
});

function runJson(commandPath, args) {
  const result = cp.spawnSync(process.execPath, [commandPath, ...args], {
    cwd: root,
    encoding: 'utf8'
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`Command failed: ${commandPath} ${args.join(' ')}\n${result.stderr || result.stdout}`);
  }

  const payloadText = (result.stdout || '').trim();
  if (!payloadText) {
    throw new Error(`No JSON output from ${commandPath} ${args.join(' ')}`);
  }
  return JSON.parse(payloadText);
}

async function makeFixtureRepo() {
  const repoRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-boundary-contracts-'));
  await fs.mkdir(path.join(repoRoot, '.kin', 'source-root', 'src'), { recursive: true });
  await fs.writeFile(path.join(repoRoot, '.kin', 'mode'), 'native\n');
  await fs.writeFile(path.join(repoRoot, '.kin', 'source-root', 'src', 'app.ts'), 'export const app = true;\n');
  await fs.mkdir(path.join(repoRoot, '.git'), { recursive: true });
  return repoRoot;
}

async function makeInitializedFixtureRepo() {
  const repoRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-boundary-contracts-runtime-'));
  await fs.mkdir(path.join(repoRoot, '.git'), { recursive: true });

  const result = cp.spawnSync(kinBinaryPath, ['init', repoRoot], {
    cwd: gitHubRoot,
    encoding: 'utf8'
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`Command failed: ${kinBinaryPath} init ${repoRoot}\n${result.stderr || result.stdout}`);
  }

  return repoRoot;
}

function resolveKinBinaryPath() {
  const configured = process.env.KIN_BINARY_PATH?.trim();
  if (configured) {
    return configured;
  }

  const candidates = [
    path.join(gitHubRoot, 'kin', 'target', 'debug', 'kin'),
    path.join(gitHubRoot, 'kin', 'target', 'release', 'kin')
  ];

  for (const candidate of candidates) {
    try {
      if (cp.spawnSync(candidate, ['--help'], { encoding: 'utf8' }).status === 0) {
        return candidate;
      }
    } catch {
      // Try next candidate.
    }
  }

  return 'kin';
}

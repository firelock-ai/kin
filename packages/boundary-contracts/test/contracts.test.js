// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { assertContract, loadAllSchemas, validateContract } from '../src/index.js';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = path.resolve(packageRoot, '../..');

test('all schemas load', async () => {
  const schemas = await loadAllSchemas();
  assert.ok(schemas.workspaceContext);
  assert.ok(schemas.kinCommandResult);
  assert.ok(schemas.scmSnapshot);
  assert.ok(schemas.scmResourceGroups);
  assert.ok(schemas.mcpArtifactReadInput);
  assert.ok(schemas.shadowGateReport);
});

test('repository transfer declarations match the Rust schema authority', async () => {
  const [declarations, transferSource] = await Promise.all([
    fs.readFile(path.join(packageRoot, 'src/index.d.ts'), 'utf8'),
    fs.readFile(
      path.join(repositoryRoot, 'crates/kin-remote/src/repository_transfer.rs'),
      'utf8'
    )
  ]);
  const versionMatch = transferSource.match(
    /pub const REPOSITORY_TRANSFER_SCHEMA_VERSION: u32 = (\d+);/
  );

  assert.ok(versionMatch, 'Rust transfer schema authority must remain readable');
  const schemaVersion = Number(versionMatch[1]);
  assert.equal(schemaVersion, 4, 'update the shared declarations for each schema revision');

  for (const contract of [
    'RepositoryTransferStatus',
    'RepositoryTransferPack',
    'RepositoryTransferReceipt'
  ]) {
    assert.ok(
      declarations.includes(
        `export interface ${contract} {\n  schema_version: ${schemaVersion};`
      ),
      `${contract} must declare repository transfer schema ${schemaVersion}`
    );
  }
});

test('exact MCP artifact reads accept lossless paths and reject lossy selectors', async () => {
  const sourceChangeId = 'a'.repeat(64);
  const artifactId = '3fa85f64-5717-4562-b3fc-2c963f66afa6';
  const nonUtf8Path = { bytes_hex: '6173736574732fff7061796c6f61642e62696e' };

  assert.equal(
    (await validateContract('mcpArtifactReadInput', {
      artifact_id: artifactId,
      source_change_id: sourceChangeId
    })).ok,
    true
  );
  assert.equal(
    (await validateContract('mcpArtifactReadInput', {
      path: nonUtf8Path,
      source_change_id: sourceChangeId
    })).ok,
    true
  );
  assert.equal(
    (await validateContract('mcpArtifactReadInput', {
      artifact_id: artifactId,
      path: nonUtf8Path,
      source_change_id: sourceChangeId
    })).ok,
    true,
    'callers may bind both identity and location for an exact coherence check'
  );

  assert.equal(
    (await validateContract('mcpArtifactReadInput', {
      path: { display: 'assets/�payload.bin' }
    })).ok,
    false
  );
  assert.equal(
    (await validateContract('mcpArtifactReadInput', {
      path: { bytes_hex: 'FF' }
    })).ok,
    false
  );
  assert.equal(
    (await validateContract('mcpArtifactReadInput', {
      source_change_id: sourceChangeId
    })).ok,
    false
  );
  assert.equal(
    (await validateContract('mcpArtifactReadInput', {
      artifact_id: artifactId,
      fallback_path: 'assets/payload.bin'
    })).ok,
    false
  );
});

test('shadow gate report contract accepts the kin review shadow payload shape', async () => {
  // Canonical shape emitted by `kin review shadow --json` (kin-review::shadow).
  // The live payload is asserted against the same required fields by the
  // review_shadow_json integration test in the kin workspace.
  const oldHash = Array(32).fill(17);
  const newHash = Array(32).fill(34);
  const report = {
    schema_version: 2,
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
    changed_artifacts: [
      {
        artifact_id: '3fa85f64-5717-4562-b3fc-2c963f66afa9',
        operation: 'updated',
        old: {
          path: { bytes_hex: '636f6e6669672f706f6c6963792e79616d6c' },
          entry: { type: 'blob', hash: oldHash, executable: false }
        },
        new: {
          path: { bytes_hex: '6465706c6f792f706f6c6963792e79616d6c' },
          entry: { type: 'blob', hash: newHash, executable: false }
        },
        aspects: ['renamed', 'blob_content_changed']
      }
    ],
    artifact_activity: [
      {
        change_id: 'b'.repeat(64),
        transition: {
          artifact_id: '3fa85f64-5717-4562-b3fc-2c963f66afa9',
          operation: 'updated',
          old: {
            path: { bytes_hex: '636f6e6669672f706f6c6963792e79616d6c' },
            entry: { type: 'blob', hash: oldHash, executable: false }
          },
          new: {
            path: { bytes_hex: '6465706c6f792f706f6c6963792e79616d6c' },
            entry: { type: 'blob', hash: newHash, executable: false }
          },
          aspects: ['renamed', 'blob_content_changed']
        }
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
        detail: 'cross-repo federation is not evaluated by shadow report v2',
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
        detail: 'cross-repo federation is not evaluated by shadow report v2'
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

  // Exact repository paths are canonical lowercase hex, never lossy strings.
  const lossyPath = structuredClone(report);
  lossyPath.changed_artifacts[0].new.path = { display: 'deploy/policy.yaml' };
  assert.equal((await validateContract('shadowGateReport', lossyPath)).ok, false);

  const nonCanonicalPath = structuredClone(report);
  nonCanonicalPath.changed_artifacts[0].new.path.bytes_hex = 'FF';
  assert.equal((await validateContract('shadowGateReport', nonCanonicalPath)).ok, false);

  // Entry variants and fixed-width object identities must be exact.
  const malformedHash = structuredClone(report);
  malformedHash.changed_artifacts[0].new.entry.hash.pop();
  assert.equal((await validateContract('shadowGateReport', malformedHash)).ok, false);
});

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
  assert.ok(schemas.repoScopedSemanticToolCall);
  assert.ok(schemas.repoScopedSemanticToolResponse);
  assert.ok(schemas.repoScopedSemanticToolError);
  assert.ok(schemas.shadowGateReport);
});

test('repo-scoped semantic contracts bind the path authority and fail closed', async () => {
  const call = {
    schema_version: 1,
    name: 'semantic_locate',
    arguments: { query: 'route_request', limit: 10 }
  };
  assert.equal((await validateContract('repoScopedSemanticToolCall', call)).ok, true);

  for (const selector of [
    'repo_id',
    'repository',
    'repo_path',
    'cwd',
    'workspace',
    'session_id'
  ]) {
    const conflicting = structuredClone(call);
    conflicting.arguments[selector] = 'repo-b';
    assert.equal(
      (await validateContract('repoScopedSemanticToolCall', conflicting)).ok,
      false,
      `${selector} must not override the repository selected by the route path`
    );
  }

  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', { ...call, repo_id: 'repo-b' })).ok,
    false,
    'the strict outer envelope must reject an added repository selector'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', { ...call, name: 'semantic_review' })).ok,
    false,
    'the hosted route has a closed semantic tool allowlist'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      ...call,
      arguments: { query: 'route_request', page_size: 201 }
    })).ok,
    false,
    'hosted locate paging is bounded before retrieval'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      ...call,
      arguments: { query: 'route_request', unexpected: true }
    })).ok,
    false,
    'tool-specific arguments stay closed to undeclared runtime keys'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      ...call,
      arguments: { query: 'x'.repeat(4097) }
    })).ok,
    false,
    'the shared contract enforces the runtime query-size bound'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      ...call,
      arguments: { query: 'route_request', pipeline: 'FUSED' }
    })).ok,
    false,
    'the hosted pipeline name is canonical and case-sensitive'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      ...call,
      arguments: {
        query: 'route_request',
        max_chars: 20_000,
        max_response_chars: 30_000
      }
    })).ok,
    false,
    'one hosted call cannot ask for two conflicting response ceilings'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      schema_version: 1,
      name: 'semantic_locate',
      arguments: { cursor: 'v1.repo-bound-cursor', page_size: 1 }
    })).ok,
    true,
    'a hosted cursor page does not need to repeat the query'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      schema_version: 1,
      name: 'get_context_pack',
      arguments: { entity_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6', include_traffic: false }
    })).ok,
    true
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      schema_version: 1,
      name: 'get_context_pack',
      arguments: { entity_id: 'not-a-canonical-uuid', include_traffic: false }
    })).ok,
    false,
    'the shared contract rejects entity identifiers the daemon cannot parse'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      schema_version: 1,
      name: 'get_context_pack',
      arguments: { entity_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6', include_traffic: true }
    })).ok,
    false,
    'the shared contract must not advertise daemon-wide traffic on a repo-scoped call'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      schema_version: 1,
      name: 'trace_data_flow',
      arguments: { focal: 'route_request', depth: 8, limit_per_step: 25 }
    })).ok,
    true
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      schema_version: 1,
      name: 'trace_data_flow',
      arguments: { focal: 'route_request', depth: 9 }
    })).ok,
    false,
    'hosted trace expansion is bounded by the shared contract'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolCall', {
      schema_version: 1,
      name: 'trace_data_flow',
      arguments: { focal: 'x'.repeat(4097) }
    })).ok,
    false,
    'hosted trace selectors are bounded before graph resolution'
  );

  const response = {
    schema_version: 1,
    capability: 'repo_scoped_semantic_tools_v1',
    repository: {
      repo_id: 'repo-a',
      snapshot_identity: 'c'.repeat(64),
      graph_root: 'a'.repeat(64),
      selected_change_id: 'b'.repeat(64)
    },
    name: 'semantic_locate',
    result: {
      content: [{ type: 'text', text: '{"entities":[]}' }]
    }
  };
  assert.equal((await validateContract('repoScopedSemanticToolResponse', response)).ok, true);
  assert.equal(
    (await validateContract('repoScopedSemanticToolResponse', {
      ...response,
      capability: 'unscoped_semantic_tools'
    })).ok,
    false
  );
  // The authority a hosted response reports is an identity, never an order. A
  // backend generation on the wire lets a caller count and watch a repository's
  // publications, so the contract refuses the old field outright rather than
  // tolerating it alongside the new one.
  const orderedAuthority = {
    ...response,
    repository: {
      repo_id: 'repo-a',
      snapshot_cursor: 41,
      graph_root: 'a'.repeat(64),
      selected_change_id: 'b'.repeat(64)
    }
  };
  assert.equal(
    (await validateContract('repoScopedSemanticToolResponse', orderedAuthority)).ok,
    false,
    'an ordered snapshot cursor is not a hosted authority identity'
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolResponse', {
      ...response,
      repository: { ...response.repository, snapshot_identity: 'not-hex' }
    })).ok,
    false,
    'a hosted authority identity is a 64-character hex digest'
  );

  const error = {
    schema_version: 1,
    capability: 'repo_scoped_semantic_tools_v1',
    error: {
      code: 'cursor_repository_mismatch',
      message: 'semantic cursor belongs to repository repo-a, not repo-b',
      repo_id: 'repo-b',
      retryable: false
    }
  };
  assert.equal((await validateContract('repoScopedSemanticToolError', error)).ok, true);
  assert.equal(
    (await validateContract('repoScopedSemanticToolError', {
      schema_version: 1,
      capability: 'repo_scoped_semantic_tools_v1',
      error: {
        code: 'authentication_required',
        message: 'Authentication required',
        repo_id: 'repo-a',
        retryable: false
      }
    })).ok,
    true
  );
  assert.equal(
    (await validateContract('repoScopedSemanticToolError', {
      ...error,
      error: { ...error.error, code: 'silently_fell_back' }
    })).ok,
    false
  );
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

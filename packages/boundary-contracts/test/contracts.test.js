// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  assertContract,
  hostedRepositoryTransferLeaf,
  hostedRepositoryTransferPath,
  hostedRepositoryTransferSeam,
  loadAllSchemas,
  loadSchema,
  validateContract
} from '../src/index.js';

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

/**
 * Read the top-level field names of one `pub struct` out of the Rust source.
 *
 * The names are the wire names only while nothing renames them, so the caller
 * checks that separately; this returns the declaration as written.
 */
function rustStructFields(source, name) {
  const opening = `pub struct ${name} {`;
  const start = source.indexOf(opening);
  if (start < 0) {
    return null;
  }
  const end = source.indexOf('\n}', start);
  if (end < 0) {
    return null;
  }
  const body = source.slice(start + opening.length, end);
  return {
    body,
    fields: [...body.matchAll(/^ {4}pub ([a-z0-9_]+):/gm)].map(match => match[1])
  };
}

/** The same for one `export interface` in the TypeScript declarations. */
function declaredInterfaceFields(declarations, name) {
  const opening = `export interface ${name} {`;
  const start = declarations.indexOf(opening);
  if (start < 0) {
    return null;
  }
  const end = declarations.indexOf('\n}', start);
  if (end < 0) {
    return null;
  }
  const body = declarations.slice(start + opening.length, end);
  return [...body.matchAll(/^ {2}([a-z0-9_]+)\??:/gm)].map(match => match[1]);
}

test('the hosted transfer seam is one contract three implementations read', async () => {
  const seam = await hostedRepositoryTransferSeam();
  const [declarations, transferSource] = await Promise.all([
    fs.readFile(path.join(packageRoot, 'src/index.d.ts'), 'utf8'),
    fs.readFile(
      path.join(repositoryRoot, 'crates/kin-remote/src/repository_transfer.rs'),
      'utf8'
    )
  ]);

  // The extractors must be shown to work before an empty result is read as
  // agreement. A struct that does not exist returns null rather than [], and a
  // struct that does returns a field this test names.
  assert.equal(
    rustStructFields(transferSource, 'RepositoryTransferNotAStruct'),
    null,
    'the Rust extractor must miss a struct that does not exist'
  );
  assert.ok(
    rustStructFields(transferSource, 'RepositoryTransferStatus').fields.includes(
      'push_apply_ready'
    ),
    'the Rust extractor must find a field the struct is known to declare'
  );
  assert.equal(
    declaredInterfaceFields(declarations, 'RepositoryTransferNotAnInterface'),
    null,
    'the TypeScript extractor must miss an interface that does not exist'
  );

  // Each leaf's response envelope, against the Rust struct that produces it and
  // the TypeScript interface that describes it. The three key sets are compared
  // to the contract rather than to each other, so no two of them can agree on a
  // name the contract never had.
  const responseTypes = {
    advertise: 'RepositoryRefAdvertisement',
    status: 'RepositoryTransferStatus',
    export: 'RepositoryTransferPack',
    receive: 'RepositoryTransferReceipt'
  };
  const declaredHere = new Set([
    'RepositoryTransferStatus',
    'RepositoryTransferPack',
    'RepositoryTransferReceipt'
  ]);

  assert.deepEqual(
    seam.leaves.map(leaf => leaf.leaf).sort(),
    Object.keys(responseTypes).sort(),
    'every contract leaf needs a response type, and every response type a leaf'
  );

  for (const leaf of seam.leaves) {
    const typeName = responseTypes[leaf.leaf];
    const rust = rustStructFields(transferSource, typeName);
    assert.ok(rust, `${typeName} must remain readable in the Rust authority`);
    assert.equal(
      rust.body.includes('rename'),
      false,
      `${typeName} renames a field, so its declared names are no longer its wire names`
    );
    assert.deepEqual(
      rust.fields,
      leaf.responseKeys,
      `${typeName} and the ${leaf.leaf} response envelope must carry the same keys in the same order`
    );

    if (declaredHere.has(typeName)) {
      assert.deepEqual(
        declaredInterfaceFields(declarations, typeName),
        leaf.responseKeys,
        `the ${typeName} declaration and the ${leaf.leaf} response envelope must carry the same keys`
      );
    }
  }

  // The two request members that carry a shape of their own.
  const expectation = rustStructFields(transferSource, 'RepositoryTransferExpectation');
  assert.deepEqual(expectation.fields, seam.expectationKeys);
  const limits = rustStructFields(transferSource, 'RepositoryTransferLimits');
  assert.deepEqual(limits.fields, seam.limitsKeys);
  assert.deepEqual(
    declaredInterfaceFields(declarations, 'RepositoryTransferLimits'),
    seam.limitsKeys
  );

  // The constants both sides stamp on every envelope.
  const protocol = transferSource.match(
    /pub const REPOSITORY_TRANSFER_PROTOCOL: &str = "([^"]+)";/
  );
  assert.ok(protocol, 'the Rust protocol constant must remain readable');
  assert.equal(protocol[1], seam.protocol);
  const version = transferSource.match(
    /pub const REPOSITORY_TRANSFER_SCHEMA_VERSION: u32 = (\d+);/
  );
  assert.ok(version, 'the Rust schema version constant must remain readable');
  assert.equal(Number(version[1]), seam.schemaVersion);
});

test('the hosted transfer route is built from the contract, and refuses what it cannot address', async () => {
  const seam = await hostedRepositoryTransferSeam();
  assert.equal(seam.orgScoped, true);
  assert.equal(seam.authorizationScheme, 'Bearer');
  assert.equal(
    seam.routeTemplate,
    '/api/v1/orgs/{orgId}/repos/{repoId}/transfer/{leaf}',
    'the org-scoped route is the seam; a bare repository id names no organization'
  );

  assert.equal(
    await hostedRepositoryTransferPath('kin-open-core', 'kin', 'receive'),
    '/api/v1/orgs/kin-open-core/repos/kin/transfer/receive'
  );
  // A repository id admits a slash. An unencoded one would address a route the
  // caller never asked for, which is a silent cross-repository write.
  assert.equal(
    await hostedRepositoryTransferPath('acme', 'group/repo name', 'status'),
    '/api/v1/orgs/acme/repos/group%2Frepo%20name/transfer/status'
  );

  await assert.rejects(
    () => hostedRepositoryTransferPath('acme', 'kin', 'zzznotaleaf'),
    /serves no leaf zzznotaleaf/,
    'a leaf the contract does not declare must refuse rather than build a URL'
  );
  await assert.rejects(
    () => hostedRepositoryTransferPath('', 'kin', 'status'),
    /non-empty orgId/,
    'an empty organization must refuse rather than address /orgs//repos/'
  );
  await assert.rejects(
    () => hostedRepositoryTransferLeaf('advertize'),
    /serves no leaf advertize/
  );

  // Every method and request envelope the seam declares, so a leaf cannot
  // quietly change verb or lose a body key.
  assert.deepEqual(
    seam.leaves.map(leaf => [leaf.leaf, leaf.method, leaf.requestKeys.join(',')]),
    [
      ['advertise', 'GET', ''],
      ['status', 'POST', 'destination_ref'],
      ['export', 'POST', 'source_ref,expectation'],
      ['receive', 'POST', 'destination_ref,pack']
    ]
  );

  // The refusal statuses the seam promises, each with a sentence. The client
  // renders `error` verbatim, so a refusal with no body is a refusal a user
  // cannot act on.
  assert.deepEqual(
    seam.refusals.map(refusal => refusal.status),
    [401, 403, 404, 409, 413, 422, 424]
  );
  for (const refusal of seam.refusals) {
    assert.ok(refusal.reason.length > 0, `refusal ${refusal.status} needs a reason`);
  }
  // The refusal body itself. The client prints `error` verbatim, so a schema
  // that stopped requiring it would let a server refuse with no sentence.
  const schema = await loadSchema('hostedRepositoryTransfer');
  assert.deepEqual(schema.definitions.refusal.required, ['error']);
  assert.equal(schema.definitions.refusal.properties.error.minLength, 1);
});

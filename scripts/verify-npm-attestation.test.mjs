// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import test from 'node:test';

import { verifyNpmAttestation } from './verify-npm-attestation.mjs';

const integrity = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;
const expected = {
  packageName: '@kinlab/kin',
  version: '1.2.3',
  integrity,
  repository: 'https://github.com/firelock-ai/kin',
  workflowPath: '.github/workflows/release.yml',
  ref: 'refs/tags/v1.2.3',
  commit: 'a'.repeat(40),
};

function fixture() {
  const statement = {
    predicateType: 'https://slsa.dev/provenance/v1',
    subject: [{
      name: 'pkg:npm/%40kinlab/kin@1.2.3',
      digest: { sha512: Buffer.alloc(64, 7).toString('hex') },
    }],
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: {
            repository: expected.repository,
            path: expected.workflowPath,
            ref: expected.ref,
          },
        },
        resolvedDependencies: [{
          uri: `git+${expected.repository}@${expected.ref}`,
          digest: { gitCommit: expected.commit },
        }],
      },
      runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } },
    },
  };
  return {
    invalid: [],
    missing: [],
    verified: [{
      name: expected.packageName,
      version: expected.version,
      attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
      attestationBundles: [{
        predicateType: 'https://slsa.dev/provenance/v1',
        bundle: { dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString('base64') } },
      }],
    }],
  };
}

test('binds verified npm provenance to bytes, workflow, tag, and commit', () => {
  assert.doesNotThrow(() => verifyNpmAttestation(fixture(), expected));
});

test('rejects a provenance commit mismatch', () => {
  assert.throws(
    () => verifyNpmAttestation(fixture(), { ...expected, commit: 'b'.repeat(40) }),
    /expected Git commit/,
  );
});

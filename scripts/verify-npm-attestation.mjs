#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

function integrityHex(integrity) {
  const match = /^sha512-([A-Za-z0-9+/]+={0,2})$/.exec(integrity);
  if (!match) throw new Error(`expected sha512 npm integrity, got ${integrity}`);
  return Buffer.from(match[1], 'base64').toString('hex');
}

function statementFromBundle(bundle) {
  const payload = bundle?.bundle?.dsseEnvelope?.payload;
  if (!payload) throw new Error('SLSA attestation bundle has no DSSE payload');
  return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
}

export function verifyNpmAttestation(audit, expected) {
  if ((audit.invalid ?? []).length > 0 || (audit.missing ?? []).length > 0) {
    throw new Error(`npm signature audit reported invalid or missing entries: ${JSON.stringify({ invalid: audit.invalid, missing: audit.missing })}`);
  }
  const entry = (audit.verified ?? []).find(
    (candidate) => candidate.name === expected.packageName && candidate.version === expected.version,
  );
  if (!entry) throw new Error(`npm audit did not verify ${expected.packageName}@${expected.version}`);
  if (entry.attestations?.provenance?.predicateType !== 'https://slsa.dev/provenance/v1') {
    throw new Error('verified npm entry has no SLSA v1 provenance attestation');
  }
  const bundle = (entry.attestationBundles ?? []).find(
    (candidate) => candidate.predicateType === 'https://slsa.dev/provenance/v1',
  );
  if (!bundle) throw new Error('npm audit omitted the verified SLSA attestation bundle');
  const statement = statementFromBundle(bundle);
  if (statement.predicateType !== 'https://slsa.dev/provenance/v1') {
    throw new Error(`unexpected provenance predicate ${statement.predicateType}`);
  }
  const expectedDigest = integrityHex(expected.integrity);
  const subjectName = `pkg:npm/${expected.packageName.replace(/^@/, '%40')}@${expected.version}`;
  const subject = (statement.subject ?? []).find((candidate) => candidate.name === subjectName);
  if (!subject || subject.digest?.sha512 !== expectedDigest) {
    throw new Error('npm provenance subject does not match the exact packed artifact integrity');
  }
  const definition = statement.predicate?.buildDefinition;
  const workflow = definition?.externalParameters?.workflow;
  if (
    workflow?.repository !== expected.repository
    || workflow?.path !== expected.workflowPath
    || workflow?.ref !== expected.ref
  ) {
    throw new Error(`npm provenance workflow identity mismatch: ${JSON.stringify(workflow ?? null)}`);
  }
  const dependency = (definition?.resolvedDependencies ?? []).find(
    (candidate) => candidate.digest?.gitCommit === expected.commit,
  );
  if (!dependency || dependency.uri !== `git+${expected.repository}@${expected.ref}`) {
    throw new Error('npm provenance does not bind the release tag to the expected Git commit');
  }
  if (statement.predicate?.runDetails?.builder?.id !== 'https://github.com/actions/runner/github-hosted') {
    throw new Error('npm provenance was not produced by a GitHub-hosted runner');
  }
}

async function main(argv) {
  if (argv.length !== 8) {
    throw new Error('usage: verify-npm-attestation.mjs <audit.json> <package> <version> <integrity> <repository-url> <workflow-path> <ref> <commit>');
  }
  const [file, packageName, version, integrity, repository, workflowPath, ref, commit] = argv;
  const audit = JSON.parse(fs.readFileSync(file, 'utf8'));
  verifyNpmAttestation(audit, { packageName, version, integrity, repository, workflowPath, ref, commit });
  console.log(`Verified npm provenance for ${packageName}@${version} at ${ref} (${commit})`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

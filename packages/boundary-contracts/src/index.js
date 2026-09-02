// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const schemaDir = path.join(root, 'schemas');
let schemaCachePromise;

const schemaFiles = {
  workspaceContext: 'workspace-context.schema.json',
  scmContext: 'scm-context.schema.json',
  fileStat: 'file-stat.schema.json',
  directoryEntry: 'directory-entry.schema.json',
  directoryList: 'directory-list.schema.json',
  fileContent: 'file-content.schema.json',
  commandAck: 'command-ack.schema.json',
  daemonError: 'daemon-error.schema.json',
  kinCommandResult: 'kin-command-result.schema.json',
  scmSnapshot: 'scm-snapshot.schema.json',
  scmResourceGroups: 'scm-resource-groups.schema.json',
  intent: 'intent.schema.json',
  intentConflict: 'intent-conflict.schema.json',
  trafficReport: 'traffic-report.schema.json',
  mcpArtifactReadInput: 'mcp-artifact-read-input.schema.json',
  repoScopedSemanticToolCall: 'repo-scoped-semantic-tool-call.schema.json',
  repoScopedSemanticToolResponse: 'repo-scoped-semantic-tool-response.schema.json',
  repoScopedSemanticToolError: 'repo-scoped-semantic-tool-error.schema.json',
  shadowGateReport: 'shadow-gate-report.schema.json',
  hostedRepositoryTransfer: 'hosted-repository-transfer.schema.json',
  graphExport: 'graph-export.schema.json',
  graphEvent: 'graph-event.schema.json'
};

const schemaIdMap = {
  'kin://contracts/directory-entry': 'directoryEntry'
};

export async function loadSchema(name) {
  const filename = schemaFiles[name];
  if (!filename) {
    throw new Error(`Unknown schema: ${name}`);
  }
  const content = await fs.readFile(path.join(schemaDir, filename), 'utf8');
  return JSON.parse(content);
}

export async function loadAllSchemas() {
  if (!schemaCachePromise) {
    schemaCachePromise = Promise.all(
      Object.keys(schemaFiles).map(async name => [name, await loadSchema(name)])
    ).then(entries => Object.fromEntries(entries));
  }
  return schemaCachePromise;
}

export async function validateContract(name, payload) {
  const schemas = await loadAllSchemas();
  const schema = schemas[name];
  const errors = [];

  if (!schema) {
    throw new Error(`Unknown schema: ${name}`);
  }

  validateAgainstSchema(schema, payload, schemas, '$', errors, schema);
  return {
    ok: errors.length === 0,
    errors
  };
}

/**
 * The hosted repository-v6 transfer seam, as one literal.
 *
 * A caller that needs the route, the four leaves or the envelope keys reads
 * them from here rather than spelling them again. Both replicas of this seam,
 * the Kin client and the KinLab control plane, resolve it through this one
 * function, so a rename in the contract moves both and a rename in either
 * implementation fails its own test rather than a stranger's push.
 */
export async function hostedRepositoryTransferSeam() {
  const schema = await loadSchema('hostedRepositoryTransfer');
  const seam = schema?.definitions?.seam?.const;
  if (!seam) {
    throw new Error(
      'hosted-repository-transfer.schema.json carries no definitions.seam.const'
    );
  }
  return seam;
}

/**
 * One leaf of that seam by name, refusing rather than returning undefined.
 *
 * A missing leaf is a contract that moved under a caller, which is exactly the
 * case a silent `undefined` would carry into a request URL.
 */
export async function hostedRepositoryTransferLeaf(leaf) {
  const seam = await hostedRepositoryTransferSeam();
  const found = seam.leaves.find(candidate => candidate.leaf === leaf);
  if (!found) {
    throw new Error(
      `hosted repository transfer seam serves no leaf ${leaf}; it serves ` +
        seam.leaves.map(candidate => candidate.leaf).join(', ')
    );
  }
  return found;
}

/**
 * The org-scoped path for one leaf, with the template's own placeholders
 * substituted and each segment encoded.
 *
 * Encoding is not cosmetic here: a repository id admits a slash, and an
 * unencoded one would silently address a different route.
 */
export async function hostedRepositoryTransferPath(orgId, repoId, leaf) {
  const seam = await hostedRepositoryTransferSeam();
  await hostedRepositoryTransferLeaf(leaf);
  for (const [name, value] of [['orgId', orgId], ['repoId', repoId]]) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`hosted repository transfer path needs a non-empty ${name}`);
    }
  }
  return seam.routeTemplate
    .replace('{orgId}', encodeURIComponent(orgId))
    .replace('{repoId}', encodeURIComponent(repoId))
    .replace('{leaf}', leaf);
}

export async function assertContract(name, payload) {
  const result = await validateContract(name, payload);
  if (!result.ok) {
    throw new Error(`${name} validation failed:\n${result.errors.join('\n')}`);
  }
}

function validateAgainstSchema(schema, value, schemas, pointer, errors, rootSchema) {
  if (schema === false) {
    errors.push(`${pointer}: value is forbidden`);
    return;
  }
  if (schema === true) {
    return;
  }

  if (schema.$ref) {
    if (schema.$ref.startsWith('#/')) {
      const resolved = resolveLocalRef(rootSchema, schema.$ref);
      if (!resolved) {
        errors.push(`${pointer}: unresolved schema ref ${schema.$ref}`);
        return;
      }
      validateAgainstSchema(resolved, value, schemas, pointer, errors, rootSchema);
      return;
    }
    const schemaName = schemaIdMap[schema.$ref];
    if (!schemaName || !schemas[schemaName]) {
      errors.push(`${pointer}: unresolved schema ref ${schema.$ref}`);
      return;
    }
    validateAgainstSchema(
      schemas[schemaName],
      value,
      schemas,
      pointer,
      errors,
      schemas[schemaName]
    );
    return;
  }

  if (schema.not) {
    const candidateErrors = [];
    validateAgainstSchema(
      schema.not,
      value,
      schemas,
      pointer,
      candidateErrors,
      rootSchema
    );
    if (candidateErrors.length === 0) {
      errors.push(`${pointer}: matched a forbidden schema`);
    }
  }

  if (schema.oneOf) {
    const candidates = schema.oneOf.filter(candidate => {
      const candidateErrors = [];
      validateAgainstSchema(
        candidate,
        value,
        schemas,
        pointer,
        candidateErrors,
        rootSchema
      );
      return candidateErrors.length === 0;
    });
    if (candidates.length !== 1) {
      errors.push(`${pointer}: expected exactly one matching schema`);
    }
    return;
  }

  if (schema.anyOf) {
    const matched = schema.anyOf.some(candidate => {
      const candidateErrors = [];
      validateAgainstSchema(
        candidate,
        value,
        schemas,
        pointer,
        candidateErrors,
        rootSchema
      );
      return candidateErrors.length === 0;
    });
    if (!matched) {
      errors.push(`${pointer}: expected at least one matching schema`);
      return;
    }
  }

  if (schema.type !== undefined && !matchesType(schema.type, value)) {
    errors.push(`${pointer}: expected ${formatType(schema.type)}`);
    return;
  }

  if ('const' in schema && value !== schema.const) {
    errors.push(`${pointer}: expected constant ${JSON.stringify(schema.const)}`);
  }

  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${pointer}: expected one of ${schema.enum.join(', ')}`);
  }

  if (schema.pattern && typeof value === 'string' && !new RegExp(schema.pattern).test(value)) {
    errors.push(`${pointer}: did not match ${schema.pattern}`);
  }

  if (typeof value === 'string') {
    const length = Array.from(value).length;
    if (schema.minLength !== undefined && length < schema.minLength) {
      errors.push(`${pointer}: expected at least ${schema.minLength} character(s)`);
    }
    if (schema.maxLength !== undefined && length > schema.maxLength) {
      errors.push(`${pointer}: expected at most ${schema.maxLength} character(s)`);
    }
  }

  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push(`${pointer}: expected value >= ${schema.minimum}`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push(`${pointer}: expected value <= ${schema.maximum}`);
    }
  }

  if (schema.required && isPlainObject(value)) {
    for (const key of schema.required) {
      if (!(key in value)) {
        errors.push(`${pointer}: missing required property ${key}`);
      }
    }
  }

  if (schema.type === 'object' && isPlainObject(value) && schema.properties) {
    for (const [key, propertySchema] of Object.entries(schema.properties)) {
      if (key in value) {
        validateAgainstSchema(
          propertySchema,
          value[key],
          schemas,
          `${pointer}.${key}`,
          errors,
          rootSchema
        );
      }
    }

    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(schema.properties, key)) {
          errors.push(`${pointer}: unexpected property ${key}`);
        }
      }
    }
  }

  if (schema.type === 'array' && Array.isArray(value) && schema.items) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push(`${pointer}: expected at least ${schema.minItems} item(s)`);
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      errors.push(`${pointer}: expected at most ${schema.maxItems} item(s)`);
    }
    if (schema.uniqueItems) {
      const encoded = value.map(item => JSON.stringify(item));
      if (new Set(encoded).size !== encoded.length) {
        errors.push(`${pointer}: expected unique items`);
      }
    }
    value.forEach((item, index) => {
      validateAgainstSchema(
        schema.items,
        item,
        schemas,
        `${pointer}[${index}]`,
        errors,
        rootSchema
      );
    });
  }
}

function resolveLocalRef(rootSchema, ref) {
  return ref
    .slice(2)
    .split('/')
    .map(segment => segment.replaceAll('~1', '/').replaceAll('~0', '~'))
    .reduce((current, segment) => current?.[segment], rootSchema);
}

function matchesType(expected, value) {
  if (Array.isArray(expected)) {
    return expected.some(type => matchesType(type, value));
  }

  switch (expected) {
    case 'object':
      return isPlainObject(value);
    case 'array':
      return Array.isArray(value);
    case 'string':
      return typeof value === 'string';
    case 'number':
      return typeof value === 'number';
    case 'integer':
      return Number.isInteger(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'null':
      return value === null;
    default:
      return true;
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function formatType(type) {
  return Array.isArray(type) ? type.join(' | ') : type;
}

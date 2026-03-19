// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

import cp from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { assertKinContract } from './contracts.js';

const DEFAULT_DAEMON_URL = 'http://127.0.0.1:4219';

export async function resolveContext(options = {}) {
  const { repoPath, kinPath } = options;
  if (!repoPath) {
    throw new Error('repoPath is required');
  }

  const repoRoot = await findKinRoot(repoPath);
  if (!repoRoot) {
    throw new Error(`Kin repository not found for ${repoPath}`);
  }

  return assertKinContract('scmContext', {
    repoRoot,
    repoName: path.basename(repoRoot),
    mode: await readRepoMode(repoRoot),
    kinPath: await resolveKinCliPath(repoRoot, kinPath) ?? null
  });
}

export async function buildSnapshot(options = {}) {
  const { daemonUrl = DEFAULT_DAEMON_URL } = options;
  const context = await resolveContext(options);
  const status = await runKinStatus(context.repoRoot, context.kinPath);
  const summary = parseStatusOutput(status.stdout);

  const [health, changes, sessions, intents] = await Promise.all([
    fetchJson(`${daemonUrl}/health`, 'health'),
    fetchJson(`${daemonUrl}/status`, 'status'),
    fetchJson(`${daemonUrl}/session`, 'session'),
    fetchJson(`${daemonUrl}/intent`, 'intent')
  ]);
  const partialFailures = [changes, sessions, intents]
    .filter(result => !result.ok)
    .map(result => ({
      endpoint: result.endpoint,
      status: result.status,
      error: result.error
    }));

  return assertKinContract('scmSnapshot', {
    ok: status.ok,
    ...context,
    daemonUrl,
    daemon: {
      connected: health.ok,
      health: health.data,
      changes: isObject(changes.data) ? changes.data : null,
      sessions: Array.isArray(sessions.data) ? sessions.data : [],
      intents: Array.isArray(intents.data) ? intents.data : [],
      partialFailures
    },
    summary,
    stdout: status.stdout,
    stderr: status.stderr
  });
}

export async function runCommand(options = {}, args = []) {
  if (!Array.isArray(args) || args.length === 0) {
    throw new Error('args are required');
  }

  const context = await resolveContext(options);
  if (!context.kinPath) {
    return assertKinContract('kinCommandResult', {
      ok: false,
      command: null,
      args,
      stdout: '',
      stderr: 'Kin CLI not found. Set a path explicitly or build the sibling kin repo.'
    });
  }

  const result = cp.spawnSync(context.kinPath, args, {
    cwd: context.repoRoot,
    encoding: 'utf8'
  });

  return assertKinContract('kinCommandResult', {
    ok: result.status === 0,
    command: context.kinPath,
    args,
    stdout: result.stdout || '',
    stderr: result.stderr || ''
  });
}

export function buildResourceGroups(snapshot) {
  const groups = [];
  const partialFailures = Array.isArray(snapshot.daemon.partialFailures) ? snapshot.daemon.partialFailures : [];
  const sessionsUnavailable = partialFailures.some(item => item.endpoint === 'session');
  const intentsUnavailable = partialFailures.some(item => item.endpoint === 'intent');

  groups.push({
    id: 'summary',
    label: 'Kin Summary',
    items: [
      resourceItem('mode', 'Mode', snapshot.mode),
      resourceItem('branch', 'Branch', snapshot.summary.branch || 'unknown'),
      resourceItem('head', 'Head', snapshot.summary.head || 'unknown'),
      resourceItem('entities', 'Entities', formatNumber(snapshot.summary.entityCount))
    ]
  });

  if (snapshot.daemon.changes) {
    const changes = snapshot.daemon.changes;
    groups.push({
      id: 'changes',
      label: 'Semantic Changes',
      items: [
        resourceItem('base-change', 'Base Change', changes.base_change || 'unknown'),
        resourceItem('entity-adds', 'Entity Adds', formatNumber(changes.entity_adds)),
        resourceItem('entity-mods', 'Entity Mods', formatNumber(changes.entity_mods)),
        resourceItem('entity-removes', 'Entity Removes', formatNumber(changes.entity_removes)),
        resourceItem('relation-adds', 'Relation Adds', formatNumber(changes.relation_adds)),
        resourceItem('relation-removes', 'Relation Removes', formatNumber(changes.relation_removes))
      ]
    });
  } else {
    groups.push({
      id: 'changes',
      label: 'Semantic Changes',
      items: [
        resourceItem(
          'daemon-offline',
          'Daemon',
          'Not connected',
          'Start the Kin daemon to populate semantic change counts and live activity.'
        )
      ]
    });
  }

  groups.push({
    id: 'sessions',
    label: 'Active Sessions',
    items: sessionsUnavailable
      ? [resourceItem('sessions-unavailable', 'Sessions', 'Unavailable', 'Daemon session endpoint did not return a valid response.')]
      : snapshot.daemon.sessions.length > 0
      ? snapshot.daemon.sessions.map((session, index) => resourceItem(
        `session-${session.session_id || session.id || index}`,
        session.vendor || session.session_id || 'session',
        [session.transport, session.pid ? `pid ${session.pid}` : null].filter(Boolean).join(' · ') || 'active session',
        session.last_heartbeat || ''
      ))
      : [resourceItem('sessions-none', 'Sessions', 'None')]
  });

  groups.push({
    id: 'intents',
    label: 'Active Intents',
    items: intentsUnavailable
      ? [resourceItem('intents-unavailable', 'Intents', 'Unavailable', 'Daemon intent endpoint did not return a valid response.')]
      : snapshot.daemon.intents.length > 0
      ? snapshot.daemon.intents.map((intent, index) => resourceItem(
        `intent-${intent.intent_id || index}`,
        intent.task_description || intent.intent_id || 'intent',
        [intent.lock_type, intent.session_id].filter(Boolean).join(' · ') || 'active intent',
        Array.isArray(intent.scopes) ? intent.scopes.join('\n') : ''
      ))
      : [resourceItem('intents-none', 'Intents', 'None')]
  });

  if (partialFailures.length > 0) {
    groups.push({
      id: 'daemon-diagnostics',
      label: 'Daemon Diagnostics',
      items: partialFailures.map((failure, index) => resourceItem(
        `daemon-failure-${failure.endpoint || index}`,
        failure.endpoint || 'daemon',
        failure.status ? `HTTP ${failure.status}` : 'Request failed',
        failure.error || 'No response body returned.'
      ))
    });
  }

  if (!snapshot.ok || snapshot.stderr) {
    groups.push({
      id: 'diagnostics',
      label: 'Diagnostics',
      items: [
        resourceItem(
          'status-output',
          'Kin Status',
          snapshot.ok ? 'Warnings present' : 'Status failed',
          (snapshot.stderr || snapshot.stdout || '').trim()
        )
      ]
    });
  }

  return groups;
}

export function parseStatusOutput(stdout = '') {
  const branch = capture(stdout, /^On branch:\s+(.+)$/m);
  const head = capture(stdout, /^Head:\s+(.+)$/m);
  const entityCount = Number.parseInt(capture(stdout, /^Entities:\s+(\d+)$/m) || '0', 10);

  return {
    branch: branch || null,
    head: head || null,
    entityCount: Number.isNaN(entityCount) ? 0 : entityCount
  };
}

export async function findKinRoot(startPath) {
  let current = path.resolve(startPath);

  try {
    const stat = await fsp.stat(current);
    if (stat.isFile()) {
      current = path.dirname(current);
    }
  } catch {
    current = path.dirname(current);
  }

  while (true) {
    if (await pathExists(path.join(current, '.kin'))) {
      return current;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

export async function readRepoMode(repoRoot) {
  const modePath = path.join(repoRoot, '.kin', 'mode');
  try {
    const mode = (await fsp.readFile(modePath, 'utf8')).trim();
    return mode === 'native' ? 'native' : 'compat';
  } catch {
    return 'compat';
  }
}

export async function resolveKinCliPath(repoRoot, configuredPath) {
  const requestedPath = configuredPath || process.env.KIN_BINARY_PATH || '';
  if (requestedPath && await pathExists(requestedPath)) {
    return requestedPath;
  }

  const siblingDebug = path.resolve(repoRoot, '..', 'kin', 'target', 'debug', 'kin');
  if (await pathExists(siblingDebug)) {
    return siblingDebug;
  }

  const siblingRelease = path.resolve(repoRoot, '..', 'kin', 'target', 'release', 'kin');
  if (await pathExists(siblingRelease)) {
    return siblingRelease;
  }

  const which = process.platform === 'win32' ? 'where' : 'which';
  const result = cp.spawnSync(which, ['kin'], { encoding: 'utf8' });
  if (result.status === 0) {
    const candidate = (result.stdout || '').split(/\r?\n/).find(Boolean);
    if (candidate) {
      return candidate.trim();
    }
  }

  return undefined;
}

async function runKinStatus(repoRoot, kinPath) {
  if (!kinPath) {
    return {
      ok: false,
      stdout: '',
      stderr: 'Kin CLI not found. Set a path explicitly or build the sibling kin repo.'
    };
  }

  const result = cp.spawnSync(kinPath, ['status'], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  return {
    ok: result.status === 0,
    stdout: result.stdout || '',
    stderr: result.stderr || ''
  };
}

async function fetchJson(url, endpoint) {
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(1500)
    });
    if (!response.ok) {
      return {
        ok: false,
        endpoint,
        status: response.status,
        data: null,
        error: `${response.status} ${response.statusText}`
      };
    }
    return {
      ok: true,
      endpoint,
      status: response.status,
      data: await response.json(),
      error: null
    };
  } catch {
    return {
      ok: false,
      endpoint,
      status: null,
      data: null,
      error: 'Connection failed'
    };
  }
}

function capture(text, pattern) {
  const match = text.match(pattern);
  return match ? match[1].trim() : null;
}

function resourceItem(id, label, description, tooltip = '') {
  return { id, label, description, tooltip };
}

function formatNumber(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return '0';
  }
  return value.toString();
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

async function pathExists(targetPath) {
  try {
    await fsp.access(targetPath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

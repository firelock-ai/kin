#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import process from 'node:process';
import { assertKinContract } from '../src/contracts.js';
import { buildResourceGroups, buildSnapshot, resolveContext, runCommand } from '../src/index.js';

function parseArgs(argv) {
  const args = { _: [] };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith('--')) {
        args[key] = true;
      } else {
        args[key] = next;
        i += 1;
      }
    } else {
      args._.push(token);
    }
  }

  return args;
}

function usage() {
  console.error(`Usage:
  kin-scm-adapter context --repo <path> [--kin <path>]
  kin-scm-adapter snapshot --repo <path> [--kin <path>] [--daemon <url>]
  kin-scm-adapter resource-groups --repo <path> [--kin <path>] [--daemon <url>]
  kin-scm-adapter trace --repo <path> --entity <name> [--kin <path>]
  kin-scm-adapter history --repo <path> --entity <name> [--kin <path>]
  kin-scm-adapter review --repo <path> [--kin <path>]
`);
}

function printJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  if (!command) {
    usage();
    process.exitCode = 1;
    return;
  }

  try {
    if (!args.repo) {
      throw new Error('--repo is required');
    }

    if (command === 'context') {
      printJson(await resolveContext({
        repoPath: args.repo,
        kinPath: args.kin
      }));
      return;
    }

    if (command === 'snapshot') {
      printJson(await buildSnapshot({
        repoPath: args.repo,
        kinPath: args.kin,
        daemonUrl: args.daemon
      }));
      return;
    }

    if (command === 'resource-groups') {
      const snapshot = await buildSnapshot({
        repoPath: args.repo,
        kinPath: args.kin,
        daemonUrl: args.daemon
      });
      printJson(await assertKinContract('scmResourceGroups', {
        ok: snapshot.ok,
        groups: buildResourceGroups(snapshot)
      }));
      return;
    }

    if (command === 'trace' || command === 'history') {
      if (!args.entity) {
        throw new Error(`--entity is required for ${command}`);
      }
      printJson(await runCommand({
        repoPath: args.repo,
        kinPath: args.kin
      }, [command, args.entity]));
      return;
    }

    if (command === 'review') {
      printJson(await runCommand({
        repoPath: args.repo,
        kinPath: args.kin
      }, ['review']));
      return;
    }

    usage();
    process.exitCode = 1;
  } catch (error) {
    printJson({
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    });
    process.exitCode = 1;
  }
}

await main();

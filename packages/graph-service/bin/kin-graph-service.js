#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import process from 'node:process';
import { assertKinContract } from '../src/contracts.js';
import {
  createDirectory,
  createServer,
  deletePath,
  readDirectory,
  readFile,
  renamePath,
  resolveContext,
  statPath,
  writeFile
} from '../src/index.js';

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
  kin-graph-service context --repo <path>
  kin-graph-service stat --repo <path> --path <virtual-path>
  kin-graph-service read-dir --repo <path> --path <virtual-path>
  kin-graph-service read-file --repo <path> --path <virtual-path>
  kin-graph-service write-file --repo <path> --path <virtual-path> [--create] [--overwrite]
  kin-graph-service mkdir --repo <path> --path <virtual-path>
  kin-graph-service delete --repo <path> --path <virtual-path> [--recursive]
  kin-graph-service rename --repo <path> --from <virtual-path> --to <virtual-path> [--overwrite]
  kin-graph-service serve --repo <path> [--host 127.0.0.1] [--port 4311] [--json-ready]
`);
}

function printJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
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

    const options = {
      repoPath: args.repo,
      host: args.host,
      port: args.port
    };

    if (command === 'context') {
      printJson(await resolveContext(options));
      return;
    }

    if (command === 'serve') {
      const handle = await createServer(options);
      if (args['json-ready']) {
        const context = await assertKinContract('workspaceContext', handle.context);
        process.stdout.write(`${JSON.stringify({
          ok: true,
          url: handle.url,
          ...context
        })}\n`);
      } else {
        process.stdout.write(`kin-graph-service listening on ${handle.url}\n`);
      }
      const stop = async () => {
        await handle.close();
        process.exit(0);
      };
      process.on('SIGINT', stop);
      process.on('SIGTERM', stop);
      return;
    }

    if (command === 'rename') {
      if (!args.from || !args.to) {
        throw new Error('--from and --to are required for rename');
      }
      await renamePath(options, args.from, args.to, { overwrite: Boolean(args.overwrite) });
      printJson(await assertKinContract('commandAck', { ok: true }));
      return;
    }

    if (!args.path) {
      throw new Error('--path is required');
    }

    switch (command) {
      case 'stat':
        printJson(await statPath(options, args.path));
        return;
      case 'read-dir':
        printJson(await readDirectory(options, args.path));
        return;
      case 'read-file': {
        const content = await readFile(options, args.path);
        printJson(await assertKinContract('fileContent', {
          encoding: 'base64',
          content: Buffer.from(content).toString('base64')
        }));
        return;
      }
      case 'write-file': {
        const content = await readStdin();
        await writeFile(options, args.path, content, {
          create: Boolean(args.create),
          overwrite: Boolean(args.overwrite)
        });
        printJson(await assertKinContract('commandAck', { ok: true }));
        return;
      }
      case 'mkdir':
        await createDirectory(options, args.path);
        printJson(await assertKinContract('commandAck', { ok: true }));
        return;
      case 'delete':
        await deletePath(options, args.path, { recursive: Boolean(args.recursive) });
        printJson(await assertKinContract('commandAck', { ok: true }));
        return;
      default:
        usage();
        process.exitCode = 1;
    }
  } catch (error) {
    printJson({
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    });
    process.exitCode = 1;
  }
}

await main();

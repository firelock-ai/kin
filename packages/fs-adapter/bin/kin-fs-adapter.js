#!/usr/bin/env node

import process from 'node:process';
import { assertKinContract } from '../src/contracts.js';
import {
  createDirectory,
  deletePath,
  readDirectory,
  readFile,
  renamePath,
  resolveContext,
  runKinStatus,
  statPath,
  writeFile
} from '../src/index.js';

function parseArgs(argv) {
  const args = {
    _: []
  };

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
  kin-fs-adapter context --repo <path> [--backendMode sourceRootBridge|graphNative] [--graphServiceUrl <url>] [--graphServicePath <path>]
  kin-fs-adapter stat --repo <path> --path <virtual-path> [--backendMode ...] [--graphServiceUrl <url>] [--graphServicePath <path>]
  kin-fs-adapter read-dir --repo <path> --path <virtual-path> [--backendMode ...] [--graphServiceUrl <url>] [--graphServicePath <path>]
  kin-fs-adapter read-file --repo <path> --path <virtual-path> [--backendMode ...] [--graphServiceUrl <url>] [--graphServicePath <path>]
  kin-fs-adapter write-file --repo <path> --path <virtual-path> [--backendMode ...] [--graphServiceUrl <url>] [--graphServicePath <path>] [--create] [--overwrite]
  kin-fs-adapter mkdir --repo <path> --path <virtual-path> [--backendMode ...] [--graphServiceUrl <url>] [--graphServicePath <path>]
  kin-fs-adapter delete --repo <path> --path <virtual-path> [--backendMode ...] [--graphServiceUrl <url>] [--graphServicePath <path>] [--recursive]
  kin-fs-adapter rename --repo <path> --from <virtual-path> --to <virtual-path> [--backendMode ...] [--graphServiceUrl <url>] [--graphServicePath <path>] [--overwrite]
  kin-fs-adapter status --repo <path> [--backendMode ...] [--kin <path>]
`);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
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
    if (command === 'context') {
      const context = await resolveContext({
        repoPath: args.repo,
        backendMode: args.backendMode,
        graphServiceUrl: args.graphServiceUrl,
        graphServicePath: args.graphServicePath
      });
      printJson(context);
      return;
    }

    if (!args.repo) {
      throw new Error('--repo is required');
    }

    if (command === 'status') {
      const result = await runKinStatus({
        repoPath: args.repo,
        backendMode: args.backendMode,
        kinPath: args.kin
      });
      printJson(result);
      return;
    }

    if (command === 'rename') {
      if (!args.from || !args.to) {
        throw new Error('--from and --to are required for rename');
      }
      await renamePath(
        {
          repoPath: args.repo,
          backendMode: args.backendMode,
          graphServiceUrl: args.graphServiceUrl,
          graphServicePath: args.graphServicePath
        },
        args.from,
        args.to,
        { overwrite: Boolean(args.overwrite) }
      );
      printJson(await assertKinContract('commandAck', { ok: true }));
      return;
    }

    if (!args.path) {
      throw new Error('--path is required');
    }

    switch (command) {
      case 'stat': {
        const result = await statPath(
          {
            repoPath: args.repo,
            backendMode: args.backendMode,
            graphServiceUrl: args.graphServiceUrl,
            graphServicePath: args.graphServicePath
          },
          args.path
        );
        printJson(result);
        return;
      }
      case 'read-dir': {
        const result = await readDirectory(
          {
            repoPath: args.repo,
            backendMode: args.backendMode,
            graphServiceUrl: args.graphServiceUrl,
            graphServicePath: args.graphServicePath
          },
          args.path
        );
        printJson(result);
        return;
      }
      case 'read-file': {
        const result = await readFile(
          {
            repoPath: args.repo,
            backendMode: args.backendMode,
            graphServiceUrl: args.graphServiceUrl,
            graphServicePath: args.graphServicePath
          },
          args.path
        );
        printJson(await assertKinContract('fileContent', {
          encoding: 'base64',
          content: Buffer.from(result).toString('base64')
        }));
        return;
      }
      case 'write-file': {
        const content = await readStdin();
        await writeFile(
          {
            repoPath: args.repo,
            backendMode: args.backendMode,
            graphServiceUrl: args.graphServiceUrl,
            graphServicePath: args.graphServicePath
          },
          args.path,
          content,
          {
            create: Boolean(args.create),
            overwrite: Boolean(args.overwrite)
          }
        );
        printJson(await assertKinContract('commandAck', { ok: true }));
        return;
      }
      case 'mkdir': {
        await createDirectory(
          {
            repoPath: args.repo,
            backendMode: args.backendMode,
            graphServiceUrl: args.graphServiceUrl,
            graphServicePath: args.graphServicePath
          },
          args.path
        );
        printJson(await assertKinContract('commandAck', { ok: true }));
        return;
      }
      case 'delete': {
        await deletePath(
          {
            repoPath: args.repo,
            backendMode: args.backendMode,
            graphServiceUrl: args.graphServiceUrl,
            graphServicePath: args.graphServicePath
          },
          args.path,
          { recursive: Boolean(args.recursive) }
        );
        printJson(await assertKinContract('commandAck', { ok: true }));
        return;
      }
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

#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const SEMVER = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const TRANSIENT_HTTP_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function fetchJson(url, {
  label,
  headers = {},
  allow404 = false,
  fetchImpl = globalThis.fetch,
  sleepImpl = sleep,
  retries = 5,
} = {}) {
  let lastError;
  for (let attempt = 1; attempt <= retries; attempt += 1) {
    try {
      const response = await fetchImpl(url, {
        headers,
        signal: AbortSignal.timeout(20_000),
      });
      if (response.status === 404 && allow404) return null;

      const body = await response.text();
      if (!response.ok) {
        const rateLimited = response.status === 403
          && (response.headers.get('retry-after') !== null
            || response.headers.get('x-ratelimit-remaining') === '0');
        const message = `${label} returned HTTP ${response.status}: ${body.slice(0, 300)}`;
        if (!TRANSIENT_HTTP_STATUSES.has(response.status) && !rateLimited) {
          throw Object.assign(new Error(message), { permanent: true });
        }
        lastError = new Error(message);
      } else {
        try {
          return JSON.parse(body);
        } catch (error) {
          lastError = new Error(`${label} returned invalid JSON: ${error.message}`);
        }
      }
    } catch (error) {
      if (error.permanent) throw error;
      lastError = error;
    }

    if (attempt < retries) await sleepImpl(1_000 * (2 ** (attempt - 1)));
  }
  throw new Error(`${label} failed after ${retries} attempts: ${lastError?.message ?? 'unknown error'}`);
}

export function parseSemver(value) {
  const match = SEMVER.exec(value);
  if (!match) throw new Error(`invalid semantic version: ${value}`);
  const prerelease = match[4]?.split('.') ?? [];
  for (const identifier of prerelease) {
    if (/^\d+$/.test(identifier) && identifier.length > 1 && identifier.startsWith('0')) {
      throw new Error(`numeric prerelease identifiers may not have leading zeroes: ${value}`);
    }
  }
  return {
    core: [BigInt(match[1]), BigInt(match[2]), BigInt(match[3])],
    prerelease,
  };
}

export function compareSemver(left, right) {
  const a = parseSemver(left);
  const b = parseSemver(right);
  for (let index = 0; index < 3; index += 1) {
    if (a.core[index] !== b.core[index]) return a.core[index] < b.core[index] ? -1 : 1;
  }
  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0;
  if (a.prerelease.length === 0) return 1;
  if (b.prerelease.length === 0) return -1;
  const length = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = a.prerelease[index];
    const rightPart = b.prerelease[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;
    const leftNumeric = /^\d+$/.test(leftPart);
    const rightNumeric = /^\d+$/.test(rightPart);
    if (leftNumeric && rightNumeric) return BigInt(leftPart) < BigInt(rightPart) ? -1 : 1;
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftPart < rightPart ? -1 : 1;
  }
  return 0;
}

export function releaseChannel(version) {
  const parsed = parseSemver(version);
  if (parsed.prerelease.length === 0) return 'latest';
  const channel = parsed.prerelease[0];
  if (!['alpha', 'beta', 'rc'].includes(channel)) {
    throw new Error(`unsupported prerelease channel in ${version}; expected alpha, beta, or rc`);
  }
  return channel;
}

export function assertNotRollback(candidate, current, label = 'release channel') {
  if (!current || current === '<none>' || current === 'null') return;
  if (compareSemver(candidate, current) < 0) {
    throw new Error(`${label} is already ${current}; refusing to roll it back to ${candidate}`);
  }
}

export async function resolveNpmChannel(packageName, channel, options = {}) {
  const metadata = await fetchJson(
    `https://registry.npmjs.org/${encodeURIComponent(packageName)}`,
    {
      label: `npm metadata for ${packageName}`,
      headers: {
        Accept: 'application/vnd.npm.install-v1+json',
        'User-Agent': 'kin-release-policy',
      },
      ...options,
    },
  );
  const distTags = metadata?.['dist-tags'];
  if (distTags === null || typeof distTags !== 'object' || Array.isArray(distTags)) {
    throw new Error(`npm metadata for ${packageName} has no valid dist-tags authority`);
  }
  const current = distTags[channel];
  if (current === undefined) return '<none>';
  parseSemver(current);
  return current;
}

export async function resolveGitHubLatest(repository, token, options = {}) {
  if (!token) throw new Error('GH_TOKEN is required to read GitHub Latest fail-closed');
  const release = await fetchJson(
    `https://api.github.com/repos/${repository}/releases/latest`,
    {
      label: `GitHub Latest for ${repository}`,
      allow404: true,
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'User-Agent': 'kin-release-policy',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      ...options,
    },
  );
  if (release === null) return '<none>';
  if (typeof release?.tag_name !== 'string') {
    throw new Error('GitHub Latest response has no tag_name');
  }
  parseSemver(release.tag_name);
  return release.tag_name;
}

async function main(argv) {
  const [command, ...args] = argv;
  if (command === 'channel' && args.length === 1) {
    console.log(releaseChannel(args[0]));
    return;
  }
  if (command === 'compare' && args.length === 2) {
    console.log(compareSemver(args[0], args[1]));
    return;
  }
  if (command === 'assert-not-rollback' && args.length >= 2 && args.length <= 3) {
    assertNotRollback(args[0], args[1], args[2]);
    console.log(`${args[2] ?? 'release channel'} may advance from ${args[1] || '<none>'} to ${args[0]}`);
    return;
  }
  if (command === 'npm-channel' && args.length === 2) {
    console.log(await resolveNpmChannel(args[0], args[1]));
    return;
  }
  if (command === 'github-latest' && args.length === 1) {
    console.log(await resolveGitHubLatest(args[0], process.env.GH_TOKEN));
    return;
  }
  throw new Error('usage: release-order.mjs channel <version> | compare <a> <b> | assert-not-rollback <candidate> <current-or-empty> [label] | npm-channel <package> <channel> | github-latest <owner/repo>');
}

if (process.argv[1]
  && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

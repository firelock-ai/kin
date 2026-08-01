import fs from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const RELEASE_TAG = /^v\d+\.\d+\.\d+$/;

const DEFAULT_ABANDONED = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'abandoned-release-tags.json',
);

function parseArgs(argv) {
  const args = new Map();

  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const value = argv[i + 1];

    if (!key.startsWith('--') || value === undefined) {
      throw new Error(`invalid arguments: ${argv.join(' ')}`);
    }

    args.set(key.slice(2), value);
    i += 1;
  }

  return {
    input: args.get('input'),
    output: args.get('output'),
    version: args.get('version'),
    abandoned: args.get('abandoned'),
  };
}

export function extractSection(changelog, version) {
  const normalized = changelog.replace(/\r\n/g, '\n');
  const heading = `## [${version}]`;
  const start = normalized.indexOf(heading);

  if (start === -1) {
    return null;
  }

  const rest = normalized.slice(start);
  const nextHeading = rest.indexOf('\n## [', heading.length);
  const section = nextHeading === -1 ? rest : rest.slice(0, nextHeading);

  return `${section.trim()}\n`;
}

/// Read the abandoned release-tag record into a tag-to-successor map.
///
/// Validation is strict for the same reason the tag selector's is: a record
/// that cannot be trusted must stop the run rather than resolve to an empty
/// chain, because an empty chain is indistinguishable from "nothing was
/// abandoned" and would publish notes that silently omit the superseded work.
export function loadAbandonments(raw) {
  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch (error) {
    throw new Error(`abandoned release-tag record is not valid JSON: ${error.message}`);
  }

  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('abandoned release-tag record must be a JSON object');
  }
  if (manifest.schema_version !== 1) {
    throw new Error(
      `abandoned release-tag record must declare schema_version 1, found ${JSON.stringify(manifest.schema_version)}`,
    );
  }
  if (!Array.isArray(manifest.abandoned)) {
    throw new Error("abandoned release-tag record must carry an 'abandoned' array");
  }

  const abandonments = new Map();
  for (const record of manifest.abandoned) {
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error('every abandoned release-tag entry must be a JSON object');
    }
    const { tag, superseded_by: supersededBy } = record;
    if (typeof tag !== 'string' || !RELEASE_TAG.test(tag)) {
      throw new Error(`abandoned tag ${JSON.stringify(tag)} is not a vX.Y.Z release tag`);
    }
    if (typeof supersededBy !== 'string' || !RELEASE_TAG.test(supersededBy)) {
      throw new Error(`abandoned tag ${tag} names a successor that is not a vX.Y.Z release tag`);
    }
    if (supersededBy === tag) {
      throw new Error(`abandoned tag ${tag} cannot supersede itself`);
    }
    if (abandonments.has(tag)) {
      throw new Error(`release tag ${tag} is recorded as abandoned more than once`);
    }
    abandonments.set(tag, supersededBy);
  }

  return abandonments;
}

function parseSemver(tag) {
  return tag.replace(/^v/, '').split('.').map(Number);
}

function descendingByVersion(left, right) {
  const a = parseSemver(left);
  const b = parseSemver(right);
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) {
      return b[i] - a[i];
    }
  }
  return 0;
}

/// Every abandoned tag this version stands in for, newest first.
///
/// Walks the `superseded_by` edges backwards from the version being published,
/// transitively: v0.4.5 collects v0.4.4, and v0.4.4's own predecessor v0.4.3
/// with it. Traversal is breadth-first over a visited set, so a record that
/// points in a circle terminates instead of hanging, and a successor named by
/// more than one abandoned tag contributes all of them rather than whichever
/// sorted first.
export function abandonedAncestors(abandonments, version) {
  const target = `v${version.replace(/^v/, '')}`;
  const ancestors = [];
  // Seeded with the version being published so it can never be collected as
  // its own predecessor: a record that names it abandoned is contradictory,
  // and following that edge would emit its section twice.
  const seen = new Set([target]);
  const queue = [target];

  while (queue.length > 0) {
    const current = queue.shift();
    for (const [tag, supersededBy] of abandonments) {
      if (supersededBy !== current || seen.has(tag)) {
        continue;
      }
      seen.add(tag);
      ancestors.push(tag);
      queue.push(tag);
    }
  }

  return ancestors.sort(descendingByVersion);
}

/// The release notes for a version, carrying forward the sections of every tag
/// it supersedes.
///
/// With no abandoned predecessors this is byte-identical to the single section
/// the extractor has always emitted. A predecessor that has no changelog
/// section of its own contributes nothing and is reported, because the record
/// tracks abandoned tags and the changelog tracks released content: the two do
/// not have to line up, and v0.4.3 is a real example of one that does not.
export function composeNotes(changelog, version, abandonments) {
  const rolledUp = abandonedAncestors(abandonments, version);

  const own = extractSection(changelog, version);
  const missing = own === null ? [version] : [];

  const carried = [];
  for (const tag of rolledUp) {
    const candidate = tag.replace(/^v/, '');
    const section = extractSection(changelog, candidate);
    if (section === null) {
      missing.push(candidate);
    } else {
      carried.push({ tag, section });
    }
  }

  const parts = [];
  if (own !== null) {
    parts.push(own);
  }
  if (carried.length > 0) {
    // Say why a superseded version's heading is in these notes. Without this a
    // reader sees a bare `## [0.4.4]` under the 0.4.5 release and reasonably
    // concludes 0.4.4 shipped, when the whole reason its content is here is
    // that it never did. The workflow-log warning is not a substitute: nobody
    // reading a release ever sees it.
    parts.push(carriedForwardNotice(carried.map((entry) => entry.tag)));
    parts.push(...carried.map((entry) => entry.section));
  }

  return {
    notes: parts.length > 0 ? parts.join('\n') : null,
    rolledUp,
    carried: carried.map((entry) => entry.tag),
    missing,
  };
}

function carriedForwardNotice(tags) {
  const named = tags.join(', ');
  const plural = tags.length > 1 ? 'releases were tagged but never published' : 'release was tagged but never published';
  return `## Carried forward from ${named}\n\nThe following ${plural}, so the notes below ship here for the first time.\n`;
}

async function readChangelog(input) {
  try {
    return await fs.readFile(input, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function readAbandonments(abandonedPath, explicit) {
  let raw;
  try {
    raw = await fs.readFile(abandonedPath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT' && !explicit) {
      // The default record is absent. Say so rather than rolling up nothing in
      // silence: a missing record and an empty one produce the same notes, and
      // only one of them is correct.
      console.warn(`no abandoned release-tag record at ${abandonedPath}; no superseded sections will be rolled up`);
      return new Map();
    }
    throw error;
  }

  return loadAbandonments(raw);
}

async function main() {
  const { input, output, version, abandoned } = parseArgs(process.argv.slice(2));

  if (!input || !output || !version) {
    throw new Error('usage: node scripts/extract-release-notes.mjs --version <version> --input <path> --output <path> [--abandoned <path>]');
  }

  const changelog = await readChangelog(input);

  let notes;
  if (changelog === null) {
    console.warn(`changelog not found at ${input}; falling back to auto-generated release notes`);
    notes = '';
  } else {
    const abandonments = await readAbandonments(abandoned ?? DEFAULT_ABANDONED, abandoned !== undefined);
    const composed = composeNotes(changelog, version, abandonments);

    for (const absent of composed.missing) {
      if (absent !== version) {
        console.warn(`superseded version ${absent} has no changelog section to roll up`);
      }
    }
    if (composed.notes === null) {
      console.warn(`no changelog section for version ${version}; falling back to auto-generated release notes`);
    } else if (composed.missing.includes(version)) {
      console.warn(`no changelog section for version ${version}; publishing only the superseded sections it carries forward`);
    }
    if (composed.rolledUp.length > 0) {
      console.warn(`rolling up sections for abandoned ${composed.rolledUp.join(', ')} into ${version}`);
    }

    notes = composed.notes ?? '';
  }

  await fs.writeFile(output, notes);
}

// `import.meta.url` is already a realpath, so the entry point must be resolved
// the same way or invocation through a symlink compares false, main() never
// runs, and the process exits 0 having written no notes at all.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

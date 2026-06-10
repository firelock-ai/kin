import fs from 'node:fs/promises';

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
  };
}

function extractSection(changelog, version) {
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

async function main() {
  const { input, output, version } = parseArgs(process.argv.slice(2));

  if (!input || !output || !version) {
    throw new Error('usage: node scripts/extract-release-notes.mjs --version <version> --input <path> --output <path>');
  }

  const changelog = await readChangelog(input);

  let notes;
  if (changelog === null) {
    console.warn(`changelog not found at ${input}; falling back to auto-generated release notes`);
    notes = '';
  } else {
    notes = extractSection(changelog, version);
    if (notes === null) {
      console.warn(`no changelog section for version ${version}; falling back to auto-generated release notes`);
      notes = '';
    }
  }

  await fs.writeFile(output, notes);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});

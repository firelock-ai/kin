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
    throw new Error(`release notes not found for version ${version}`);
  }

  const rest = normalized.slice(start);
  const nextHeading = rest.indexOf('\n## [', heading.length);
  const section = nextHeading === -1 ? rest : rest.slice(0, nextHeading);

  return `${section.trim()}\n`;
}

async function main() {
  const { input, output, version } = parseArgs(process.argv.slice(2));

  if (!input || !output || !version) {
    throw new Error('usage: node scripts/extract-release-notes.mjs --version <version> --input <path> --output <path>');
  }

  const changelog = await fs.readFile(input, 'utf8');
  const notes = extractSection(changelog, version);
  await fs.writeFile(output, notes);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});

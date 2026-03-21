#!/usr/bin/env node

import { runKinMcp } from '../src/index.js';

const exitCode = await runKinMcp(process.argv.slice(2));
process.exit(exitCode);

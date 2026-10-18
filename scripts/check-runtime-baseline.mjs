#!/usr/bin/env node
// Runtime baseline sentinel.
//
// xtrape-docs reference/10-runtime-baseline.md §4 requires the Node major to be
// declared identically in package.json `engines.node`, the CI job container
// image, and the deployment image. Three hand-maintained copies of one decision
// drift silently — a pin does not fail loudly when it goes stale (that is how
// Node 20 survived its own EOL here). This turns the agreement into a check.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const BASELINE_MAJOR = 24;
const root = new URL('../', import.meta.url);
const read = (p) => readFileSync(fileURLToPath(new URL(p, root)), 'utf8');

const problems = [];

const engines = JSON.parse(read('package.json')).engines?.node;
if (engines !== `>=${BASELINE_MAJOR}`) {
  problems.push(`package.json engines.node is ${JSON.stringify(engines)}, expected ">=${BASELINE_MAJOR}"`);
}

const ci = read('.forgejo/workflows/ci.yml');
const ciImages = [...ci.matchAll(/^\s*image:\s*(\S+)\s*$/gm)].map((m) => m[1]);
if (ciImages.length === 0) problems.push('.forgejo/workflows/ci.yml declares no job container image');
for (const image of ciImages) {
  if (!image.startsWith(`node:${BASELINE_MAJOR}-`) && image !== `node:${BASELINE_MAJOR}`) {
    problems.push(`.forgejo/workflows/ci.yml container image "${image}" is not on the Node ${BASELINE_MAJOR} baseline`);
  }
}

const dockerfile = read('Dockerfile');
const froms = [...dockerfile.matchAll(/^FROM\s+(\S+)/gm)].map((m) => m[1]);
if (froms.length === 0) problems.push('Dockerfile declares no FROM stage');
for (const image of froms) {
  if (!image.startsWith(`node:${BASELINE_MAJOR}-`) && image !== `node:${BASELINE_MAJOR}`) {
    problems.push(`Dockerfile stage "${image}" is not on the Node ${BASELINE_MAJOR} baseline`);
  }
}

if (problems.length) {
  console.error(`Node ${BASELINE_MAJOR} runtime baseline violated:`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}

console.log(
  `Node ${BASELINE_MAJOR} baseline OK — engines.node="${engines}", CI images [${ciImages.join(', ')}], Dockerfile [${froms.join(', ')}]`,
);

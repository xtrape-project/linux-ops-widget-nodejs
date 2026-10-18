import { defineConfig } from 'vitest/config';

// The shared Forgejo runner is one machine running every Xtrape job; CI runs
// there are starved in two distinct places, each with its own remedy:
//
// - per-test time (#88): the default 5s testTimeout is too tight for a few
//   filesystem-heavy tests (mkdtemp + Checkpoint publication atomicity, the
//   parameter-ROWS round-trip) that pass comfortably on a developer machine
//   but exceed 5s on the loaded runner. Raised to 30s below; no test's
//   behavior changes.
// - the worker -> main RPC (#90): vitest spawns one worker per available CPU
//   by default, and on the loaded runner those workers starve the main
//   process until its internal `onTaskUpdate` call times out — the run is
//   reported failed although every test file passed. `testTimeout` does not
//   govern that channel; the fix is to bound the worker pool in CI so the
//   main process keeps getting scheduled. Local runs stay unconstrained.
const ci = process.env.CI === 'true' || process.env.CI === '1';

export default defineConfig({
  test: {
    testTimeout: 30_000,
    hookTimeout: 30_000,
    ...(ci ? { maxWorkers: 2, minWorkers: 1 } : {}),
  },
});

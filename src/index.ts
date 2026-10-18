#!/usr/bin/env node
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { serveCeService, type ServeCeServiceHandle } from '@xtrape/connector';
import { ActionRegistry } from './registry.js';
import { TaskDb } from './task-db.js';
import { OpsService } from './service.js';
import { buildCeActions } from './ce-actions.js';
import { ALL_ARTIFACTS, STATIC_EXTRACTOR_MEDIA_TYPE, buildCheckpointSet, checkpointRefFor, definitionFingerprint, isCheckpointExposed, parseBoundedCheckpoints } from './checkpoints.js';
import { registrationInputSchemaFor } from './schema-titles.js';
import type { ActionDefinition } from './types.js';
import { buildConfirmationChannel } from './confirmation-ask.js';
import { ServerStore } from './servers.js';
import { loadOrCreateInstanceId } from './instance.js';
import { SshExecutor, fetchHostKeyFingerprint } from './executors/ssh.js';
import { FileAuditLogger } from './audit.js';
import { buildManifest } from './manifest.js';
import { RedlineSet, sweepEnabled } from './redlines.js';
import { syncEffective } from './content-sync.js';
import { syncGovernedContentOnce } from './content-poll.js';
import { contentSourceFromEnv } from './content-config.js';
import { ParamGuardSet } from './param-guards.js';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

/**
 * Widget entrypoint. Starting this Widget produces a Service: it registers with
 * the Xtrape Platform through the Connector SDK (`@xtrape/connector`), which
 * owns registration, the Service Token, heartbeat, and the prepare/execute
 * command lifecycle. This process is a Worker of that Service.
 *
 * There is no MCP transport here by design. MCP is a protocol projection under
 * Xtrape Exposure and its authority is `xtrape/xtrape-exposure` — a Widget that
 * spoke MCP directly would be a second, ungoverned entry point into the same
 * capabilities.
 */
async function main(): Promise<void> {
  const confDir = process.env.LINUX_OPS_WIDGET_CONF_DIR ?? './conf';
  const logDir = process.env.LINUX_OPS_WIDGET_LOG_DIR ?? './logs';
  const dataDir = process.env.LINUX_OPS_WIDGET_DATA_DIR ?? './data';
  const recordedOutputRaw = process.env.LINUX_OPS_WIDGET_MAX_RECORDED_OUTPUT_BYTES;
  let recordedOutputBytes: number | undefined;
  if (recordedOutputRaw !== undefined && recordedOutputRaw.trim() !== '') {
    recordedOutputBytes = Number(recordedOutputRaw);
    if (!Number.isInteger(recordedOutputBytes) || recordedOutputBytes < 1) {
      throw new Error(`LINUX_OPS_WIDGET_MAX_RECORDED_OUTPUT_BYTES must be a positive integer (got "${recordedOutputRaw}")`);
    }
  }

  const platformUrl = process.env.LINUX_OPS_WIDGET_PLATFORM_URL;
  if (!platformUrl) {
    // Fail closed rather than idling: without the Platform there is no command
    // authority, no authorization, and no central audit — nothing here is
    // allowed to execute on its own.
    throw new Error('LINUX_OPS_WIDGET_PLATFORM_URL is required; this Widget only executes under Platform command authority');
  }

  const callbackToken = process.env.LINUX_OPS_WIDGET_CALLBACK_TOKEN?.trim();
  const host = process.env.LINUX_OPS_WIDGET_CALLBACK_HOST ?? '0.0.0.0';
  // The callback listener serves the command surface (execute/prepare/messages).
  // With no callback token the SDK accepts UNAUTHENTICATED requests, letting
  // anyone who can reach the listener invoke ops actions and bypass Platform
  // command creation / authorization / audit. Require a token.
  if (!callbackToken) {
    if (process.env.LINUX_OPS_WIDGET_ALLOW_INSECURE_CALLBACK === 'true') {
      if (!LOOPBACK_HOSTS.has(host)) {
        throw new Error(
          `LINUX_OPS_WIDGET_ALLOW_INSECURE_CALLBACK requires a loopback LINUX_OPS_WIDGET_CALLBACK_HOST (got "${host}")`,
        );
      }
      process.stderr.write(
        'linux-ops-widget: WARNING — insecure callback (no token); loopback-only local dev. Set LINUX_OPS_WIDGET_CALLBACK_TOKEN for any real deployment.\n',
      );
    } else {
      throw new Error(
        'LINUX_OPS_WIDGET_CALLBACK_TOKEN is required (unauthenticated callbacks let the Platform command authority be bypassed)',
      );
    }
  }

  // Config is fully validated above, before any filesystem or network work: a
  // deployment that is missing its callback token should fail on that, not on
  // whatever unrelated thing the process happens to touch first.
  const tasksDir = join(confDir, 'tasks');
  // The task library lives in the DB (#58); provisioned `conf/tasks/` files
  // are a one-time-per-id bootstrap import — once a task is managed online,
  // the DB is the truth and host files stop being an edit channel.
  const taskStore = new TaskDb(join(dataDir, 'tasks.db'));
  // A GOVERNED library (xtrape-docs#255) takes its content from the review
  // side, so the provisioned-files bootstrap is skipped: importing host files
  // there would inject tasks nobody reviewed, beside ones that were.
  const content = contentSourceFromEnv(process.env);
  const contentPollSeconds = Number(process.env.LINUX_OPS_WIDGET_CONTENT_POLL_SECONDS ?? '60');
  if (content && (!Number.isFinite(contentPollSeconds) || contentPollSeconds < 0)) {
    throw new Error('LINUX_OPS_WIDGET_CONTENT_POLL_SECONDS must be a non-negative number of seconds (0 disables polling)');
  }
  if (content === undefined) {
    const { imported, skipped } = taskStore.importDir(tasksDir);
    if (imported > 0 || skipped > 0) {
      process.stderr.write(`linux-ops-widget: task library — imported ${imported} provisioned task(s) from ${tasksDir}, ${skipped} already managed in the DB\n`);
    }
  }
  // Redlines are screened at REVIEW time, and again whenever the rule set
  // changes (#65) — which is what this sweep is: a task approved before a
  // rule existed is re-judged under it, suspended if the rule is hard, and
  // escalated per run if it is soft.
  const redlines = RedlineSet.load(join(confDir, 'redlines.json'));
  // Parameter risk control (#66): judged per invocation, because a
  // parameter's value does not exist until somebody calls.
  const paramGuards = ParamGuardSet.load(join(confDir, 'param-guards.json'));
  if (content) {
    // Startup pulls the current effective version. A failure here is NOT
    // fatal: the last effective version is already local, and refusing to
    // start would make the review side an availability dependency of running
    // operations — precisely what this design says it must not be.
    try {
      // No live catalog here on purpose: the registry does not exist yet and
      // is built fresh from the post-sync DB a few lines below — startup has
      // no old/new window to keep consistent. And no pre-publication either
      // (unlike the poll's syncGovernedContentOnce): the instance credential
      // does not exist yet — the checkpoints FACTORY publishes the whole
      // enabled set atomically with registration right after, and a failure
      // there fails startup with nothing exposed.
      const outcome = await syncEffective(taskStore, content.source, redlines);
      process.stderr.write(
        `linux-ops-widget: governed task library at ${content.describe} — effective ${outcome.versionId.slice(0, 12)}` +
          `${outcome.unchanged ? ' (unchanged)' : `, ${outcome.applied.length} applied, ${outcome.withdrawn.length} withdrawn, ${outcome.refused.length} refused`}\n`,
      );
    } catch (error) {
      process.stderr.write(
        `linux-ops-widget: WARNING — could not reach the governed content source (${error instanceof Error ? error.message : String(error)}); ` +
          `continuing with the last effective version already applied here\n`,
      );
    }
  }
  const swept = sweepEnabled(taskStore, redlines);
  if (swept.screened > 0) {
    process.stderr.write(`linux-ops-widget: screened ${swept.screened} enabled task(s) against ${redlines.rules.length} redline(s)\n`);
  }
  // Set once buildCeActions hands it over; the governed poll uses it to
  // republish the catalog after applying a new effective version.
  let refreshOpsCatalog: (() => void) | undefined;
  const registry = new ActionRegistry();
  for (const def of taskStore.enabledDefinitions()) registry.register(def);
  if (registry.list().length === 0) {
    process.stderr.write(`linux-ops-widget: WARNING — no enabled tasks in the library (and nothing to import from ${tasksDir}); no ops task Actions will be published\n`);
  }
  const store = new ServerStore(join(confDir, 'servers.json'));
  // The executor pins a first-use host key straight into the fleet store
  // (#44, accept-new); a pin that cannot persist refuses the connection.
  const executor = new SshExecutor({ pin: (server, fingerprint) => void store.pinHostKey(server, fingerprint), ensureDurable: () => store.ensureDurable() });
  const audit = new FileAuditLogger(logDir);
  const opsService = new OpsService({
    registry,
    servers: store,
    executors: [executor],
    audit,
    // How much output this deployment records (#61 B): the task generates
    // what its business needs, the deployment decides what it can afford to
    // keep. Beyond it output is read and dropped — the task still finishes
    // and reports its own exit status.
    ...(recordedOutputBytes !== undefined ? { maxRecordedOutputBytes: recordedOutputBytes } : {}),
    // Read per execution so a sweep's verdict applies without a restart.
    paramGuards,
    screening: (actionId) => {
      const verdict = taskStore.screening(actionId)?.verdict;
      return verdict === 'soft' || verdict === 'hard' ? verdict : undefined;
    },
  });

  const httpPort = Number(process.env.LINUX_OPS_WIDGET_CALLBACK_PORT ?? '0');

  // ---- the governance flip (#79): every action is a governed Checkpoint ----
  // Input schemas come from the SAME entries the live catalog serves; ops
  // schemas are the base form (the live eligible-server enum is a prepare-time
  // projection, not part of the immutable definition).
  // One source for both rows: the catalog entry is already described
  // (schema-titles.ts), and an ops entry's catalog schema IS the base form.
  const inputSchemaFor = (name: string): Record<string, unknown> | undefined => registrationInputSchemaFor(ceActionsFull, name);
  // Set once the checkpoints factory ran; growth republishes through the
  // handle with the SAME profile digest the registration snapshot cited.
  let factoryProfileDigest: string | undefined;
  // The local "already published" cache keys on the FULL Checkpoint definition,
  // NOT on `id@version` (linux-ops#81 review 2692 P1). An `id@version` cache
  // suppressed the publish attempt whenever a revision reused the same
  // id@version with different bytes (or different risk / schema), so the drift
  // never reached the Platform and its immutable-conflict authority
  // (409 CHECKPOINT_IMMUTABLE_CONFLICT) never fired — a swapped script could ride
  // the old READ_ONLY Checkpoint. Keyed on the definition fingerprint, a drift
  // changes the fingerprint, so it is NOT suppressed: it is republished, and the
  // Platform rejects a same id@version carrying a different definition. Only a
  // byte-for-byte identical definition is skipped (a true no-op).
  const publishedDefFingerprints = new Set<string>();
  // #77 bounded reference profile: expose only the named Checkpoint subset.
  const boundedCheckpoints = parseBoundedCheckpoints(process.env.LINUX_OPS_BOUNDED_CHECKPOINTS);
  const ensureTaskCheckpoints = async (tasks: ReadonlyArray<ActionDefinition>): Promise<void> => {
    if (!factoryProfileDigest) throw new Error('checkpoint growth before the service registered');
    // Grow only tasks the bounded profile exposes: an unexposed task never
    // publishes a Checkpoint, so its ops entry (filtered elsewhere) binds nothing.
    const exposed = tasks.filter((t) => isCheckpointExposed(checkpointRefFor(t.id, t.version).checkpointId, boundedCheckpoints));
    if (exposed.length === 0) return;
    // Build the definitions for EVERY exposed incoming task (no id@version
    // pre-filter), then publish only those whose full definition has not already
    // been published. A drifted definition at a known id@version is therefore
    // published and lands on the Platform's immutable-conflict check.
    const grown = buildCheckpointSet({
      profileDigest: factoryProfileDigest,
      inputSchemaFor,
      tasks: exposed,
      staticRows: false,
      bounded: boundedCheckpoints,
    });
    const freshDefs = grown.definitions.filter((d) => !publishedDefFingerprints.has(definitionFingerprint(d)));
    if (freshDefs.length === 0) return;
    await handle.publishCheckpoints(freshDefs, grown.schemaRecords);
    for (const d of freshDefs) publishedDefFingerprints.add(definitionFingerprint(d));
  };

  const ceActionsFull = buildCeActions({
      ensureTaskCheckpoints: (tasks) => ensureTaskCheckpoints(tasks),
      isCheckpointExposed: (id) => isCheckpointExposed(id, boundedCheckpoints),
      registry,
      taskStore,
      audit,
      store,
      opsService,
      // The REAL rule set reaches the review paths (review 2403): built
      // without it, Enable screened against an empty set and a hard-redline
      // draft could be approved, staying live until the next startup sweep.
      redlines,
      // …and so do the parameter guards (review 2404): without them the run
      // panel never told a caller which guards would ask.
      paramGuards,
      ...(content ? { content: { source: content.source, path: content.path } } : {}),
      onRebuildAvailable: (rebuild) => {
        refreshOpsCatalog = rebuild;
      },
      probe: (server) =>
        // `true` prints nothing, so anything at all is already wrong. The
        // executor is bounded by default now; this says what THIS call expects.
        executor.run(server, { command: 'true', maxOutputBytes: 4096 }),
      probeHostKey: (host, port) => fetchHostKeyFingerprint(host, port),
      // What the target can RUN (#69): one round trip that prints the
      // interpreter names `command -v` resolves, in a fixed candidate order.
      // POSIX sh only — this is exactly the host we do not yet know the
      // shells of. Bounded output; the parse keeps only clean single words.
      probeShells: async (server) => {
        const candidates = ['sh', 'bash', 'dash', 'ash', 'zsh', 'ksh', 'fish', 'python3', 'python', 'perl', 'node', 'ruby'];
        // `; true` — the loop's own exit status is its LAST iteration's, and
        // the last candidate being absent is 127, which is not a probe failure.
        const command = `for c in ${candidates.join(' ')}; do command -v "$c" >/dev/null 2>&1 && printf '%s\\n' "$c"; done; true`;
        const out = await executor.run(server, { command, maxOutputBytes: 4096 });
        if (out.terminatedBy !== undefined || out.exitCode !== 0) throw new Error(`interpreter probe exited ${out.exitCode}${out.terminatedBy ? ` (${out.terminatedBy})` : ''}`);
        return out.stdout.split('\n').map((l) => l.trim()).filter((l) => candidates.includes(l));
      },
  });

  // The startup schema-record set is digest-only (independent of the profile
  // digest the factory discovers), so it can ride the serve OPTIONS while the
  // definitions ride the factory.
  const startupSchemaRecords = buildCheckpointSet({
    profileDigest: `sha256:${'0'.repeat(64)}`,
    inputSchemaFor,
    tasks: registry.list(),
    bounded: boundedCheckpoints,
  }).schemaRecords;

  const handle: ServeCeServiceHandle = await serveCeService({
    serverUrl: platformUrl,
    manifest: buildManifest(),
    // #253 ruling round-1: the Widget self-reports its build identity — the
    // SDK computes `manifest.build.artifactDigest` over the built module
    // tree this process actually runs (this file's own directory), and the
    // Platform's TargetAdmission requires it for GOVERNED registrations.
    buildRoot: dirname(fileURLToPath(import.meta.url)),
    handler: async () => ({ content: 'linux-ops-widget healthy', messageType: 'SUMMARY' }),
    // #77: bounded narrowing is applied INSIDE buildCeActions (the live rebuild
    // path), so this is the live array the Connector holds by reference —
    // enable/disable/remove stay reflected, never a startup snapshot.
    actions: ceActionsFull,
    schemaRecords: startupSchemaRecords,
    // The governance flip (#79): definitions are built AFTER registration —
    // the admitted execution-profile digest is discoverable only with the
    // instance credential (connector#100 bounded facade) — and still ride the
    // registration descriptor atomically, so the Service is GOVERNED from its
    // first admitted snapshot.
    checkpoints: async (ctx) => {
      const listing = await ctx.listExecutionProfiles();
      const pick = process.env.LINUX_OPS_EXECUTION_PROFILE_DIGEST;
      const profiles = pick ? listing.profiles.filter((p) => p.digest === pick) : listing.profiles;
      if (profiles.length !== 1) {
        throw new Error(
          `expected exactly one admitted execution profile, found ${profiles.length}${pick ? ` matching ${pick}` : ''} — set LINUX_OPS_EXECUTION_PROFILE_DIGEST to choose`,
        );
      }
      const profileDigest = profiles[0]!.digest;
      for (const artifact of ALL_ARTIFACTS) {
        await ctx.publishResourceExtractorArtifact({ bytesJson: artifact.bytesJson, mediaType: STATIC_EXTRACTOR_MEDIA_TYPE, digest: artifact.digest });
      }
      const tasks = registry.list();
      const set = buildCheckpointSet({ profileDigest, inputSchemaFor, tasks, bounded: boundedCheckpoints });
      factoryProfileDigest = profileDigest;
      // Seed the published-fingerprint cache from the definitions the Platform
      // registered at bootstrap, so an identical later republish is a no-op but a
      // DRIFTED definition at the same id@version is not suppressed (review 2692).
      for (const d of set.definitions) publishedDefFingerprints.add(definitionFingerprint(d));
      return set.definitions;
    },
    instanceId: loadOrCreateInstanceId(confDir),
    ...(process.env.LINUX_OPS_WIDGET_REGISTRATION_TOKEN
      ? { registrationToken: process.env.LINUX_OPS_WIDGET_REGISTRATION_TOKEN }
      : {}),
    ...(callbackToken ? { callbackToken } : {}),
    ...(Number.isInteger(httpPort) && httpPort > 0 ? { port: httpPort } : {}),
    host,
    ...(process.env.LINUX_OPS_WIDGET_CALLBACK_ADDRESS ? { address: process.env.LINUX_OPS_WIDGET_CALLBACK_ADDRESS } : {}),
  });

  // The way to reach a person, when the running SDK carries the interaction
  // primitive (xtrape-docs#241). Attached after registration because the
  // channel rides the Connector. On an SDK without ask() this stays undefined and
  // the fail-closed path holds: a task needing a human stops, nobody is asked.
  // `connector`, not `agent` — the repository froze that naming, and since
  // SDK 0.8.1 the handle exposes the canonical `connector` property. The
  // deprecated alias stays as a harmless fallback for an older handle shape;
  // both are the same instance.
  const runtimeHandle = handle as unknown as Record<string, unknown>;
  opsService.attachConfirmation(buildConfirmationChannel(runtimeHandle['connector'] ?? runtimeHandle['agent']));

  // A governed library learns that a review was approved by ASKING. There is
  // no webhook and deliberately so: an inbound callback would be another
  // thing to expose, authenticate and debug, while a poll is one timer whose
  // failure mode is "a change lands a minute later" (xtrape-docs#255, CE).
  let pollTimer: NodeJS.Timeout | undefined;
  if (content && contentPollSeconds > 0) {
    let running = false;
    pollTimer = setInterval(() => {
      // Overlap guard: a slow forge must not stack syncs on top of each other,
      // where two passes would fight over the same enable pointers.
      if (running) return;
      running = true;
      void syncGovernedContentOnce({ source: content.source, taskStore, redlines, registry, ensureTaskCheckpoints })
        .then((outcome) => {
          if (outcome.unchanged || (outcome.applied.length === 0 && outcome.withdrawn.length === 0)) return;
          // GROW BEFORE EXPOSE is atomic against the durable state (review
          // 2674 P1-1): the pass above published the incoming version's
          // Checkpoints BEFORE any pointer moved — a publish failure lands in
          // the catch below with NOTHING committed, and the next tick retries.
          // The registry was swapped per-task inside the sync's synchronous
          // loop; what remains is republishing the ops catalog entries.
          refreshOpsCatalog?.();
          process.stderr.write(
            `linux-ops-widget: applied effective version ${outcome.versionId.slice(0, 12)} — ${outcome.applied.length} task(s) live, ${outcome.withdrawn.length} withdrawn\n`,
          );
        })
        .catch((error) => {
          process.stderr.write(`linux-ops-widget: content poll failed (${error instanceof Error ? error.message : String(error)}); keeping the last effective version\n`);
        })
        .finally(() => {
          running = false;
        });
    }, contentPollSeconds * 1000);
    // The poll must not be the reason this process stays alive.
    pollTimer.unref?.();
  }

  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => {
      if (pollTimer) clearInterval(pollTimer);
      void handle.close().finally(() => process.exit(0));
    });
  }
  process.stderr.write(`linux-ops-widget: registered with Platform ${platformUrl} (callback ${handle.address})\n`);
}

main().catch((err) => {
  // A registration/connection/config failure exits cleanly so a supervisor
  // restarts, instead of an unhandled rejection with a half-started process.
  process.stderr.write(`linux-ops-widget: fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});

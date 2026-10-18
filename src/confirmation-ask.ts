import type { ConfirmationChannel, ConfirmationOutcome, ConfirmationRequest } from './confirmation.js';
import { describeRequest } from './confirmation.js';

/**
 * The slice of the Connector SDK this adapter needs: the interaction
 * primitive (`ask`, xtrape-docs#241). Typed structurally so this Widget builds
 * against today's published SDK; `buildConfirmationChannel` probes for the
 * method at runtime.
 *
 * **The probe succeeds in every build from this lockfile**: `pnpm-lock.yaml`
 * pins `@xtrape/connector` 0.8.1, whose `CeServiceConnector` carries `ask()`
 * (xtrape-connector-nodejs#87) — the deliberate dependency bump review 2182
 * reserved this flip for. A build on an SDK without the method still takes
 * the fail-closed path, and the installed-package test pins which of the two
 * this repository ships.
 *
 * The bump is necessary rather than sufficient (review 2172). Two
 * Platform-side pieces remain: permission for this Service to create the
 * `apr_*` conversation (the persist-only message route is grant-gated,
 * server-ce#94 — an operational grant, not code), and routing the question to
 * the person behind the command (xtrape-docs#241, unbuilt). Until both land
 * the probe succeeds while the question may go nowhere useful, which is why
 * an unanswered wait ends only on cancel.
 */
export interface Asker {
  ask(opts: {
    conversationId: string;
    content: string;
    payload?: unknown;
    signal?: AbortSignal;
  }): Promise<{ senderId: string; payload?: unknown }>;
}

/**
 * Bridge the Widget's confirmation seam onto the interaction primitive.
 *
 * The division of labour is the settled one: this Widget decides WHEN to ask
 * (its policy did, before this runs) and what the answer means (here); the
 * Platform relays. Nothing here picks a recipient — and deriving who to ask
 * from the identity credential the execution request carried is the Platform's
 * to do, still unbuilt (xtrape-docs#241).
 */
export function askConfirmationChannel(asker: Asker): ConfirmationChannel {
  return {
    async ask(request: ConfirmationRequest, signal?: AbortSignal): Promise<ConfirmationOutcome> {
      const answer = await asker.ask({
        // One conversation per EXECUTION, keyed by interactionId (the commandId
        // when there is one). The executionHash still travels in the payload as
        // WHAT is approved — but it is content, shared by any run of the same
        // task+args, so it cannot be the conversation or two runs collide in
        // one thread (review 2172).
        conversationId: `apr_${request.interactionId}`,
        // Everything a person needs in order to own their answer. Disclosure
        // is the obligation; being understood is not.
        content: `${request.question}\n${describeRequest(request)}`,
        payload: {
          commandId: request.commandId,
          executionHash: request.executionHash,
          serverId: request.serverId,
          taskId: request.taskId,
          taskVersion: request.taskVersion,
          scriptDigest: request.scriptDigest,
          riskLevel: request.riskLevel,
          rule: request.rule,
          reason: request.reason,
        },
        ...(signal !== undefined ? { signal } : {}),
      });
      return parseAnswer(answer);
    },
  };
}

/**
 * Read the person's decision out of the answer.
 *
 * Only `granted: true` runs the task. Anything else — `granted: false`, a
 * missing payload, a shape this code does not recognise — is a refusal:
 * between "run something nobody clearly approved" and "make the person say it
 * again", the second is always the right failure. What the person supplied
 * beyond the decision rides along for the interaction and nothing else; it is
 * never spliced into the task's script.
 */
function parseAnswer(answer: { senderId: string; payload?: unknown }): ConfirmationOutcome {
  const payload = answer.payload;
  const granted =
    typeof payload === 'object' && payload !== null && (payload as Record<string, unknown>)['granted'] === true;
  const approvedDigest =
    typeof payload === 'object' && payload !== null && typeof (payload as Record<string, unknown>)['approvedDigest'] === 'string'
      ? ((payload as Record<string, unknown>)['approvedDigest'] as string)
      : undefined;
  const supplementary =
    typeof payload === 'object' && payload !== null && typeof (payload as Record<string, unknown>)['supplementaryInformation'] === 'string'
      ? ((payload as Record<string, unknown>)['supplementaryInformation'] as string)
      : undefined;
  return {
    granted,
    answeredBy: answer.senderId,
    ...(approvedDigest !== undefined ? { approvedDigest } : {}),
    ...(supplementary !== undefined ? { supplementaryInformation: supplementary } : {}),
  };
}

/**
 * Probe a Connector for the interaction primitive.
 *
 * Returns a channel when the running SDK carries `ask`, and `undefined` when
 * it does not — in which case the Widget keeps its fail-closed path: a task
 * needing a human is stopped and nobody is asked, which is what
 * `HUMAN_REVIEW_UNAVAILABLE` says.
 */
export function buildConfirmationChannel(connector: unknown): ConfirmationChannel | undefined {
  if (typeof connector === 'object' && connector !== null && typeof (connector as Record<string, unknown>)['ask'] === 'function') {
    return askConfirmationChannel(connector as Asker);
  }
  return undefined;
}

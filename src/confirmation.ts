import type { OriginActor } from './types.js';

/**
 * Asking a person to decide, from inside a running command.
 *
 * This Widget detects that a task needs a human and puts the question; the
 * Widget does not choose a recipient. Deriving who to ask, and reaching them
 * on whichever interactive layer they are on, is the Platform's to do from the
 * identity credential the execution request carried — and is Platform-side
 * work that does not exist yet (xtrape-docs#241). Today the question is posted
 * into a conversation and a person reads it there.
 *
 * That is also why this is an interface rather than an implementation.
 * `src/confirmation-ask.ts` binds it to the Connector SDK's `ask()` primitive
 * (xtrape-connector-nodejs#87), which posts the question and correlates the
 * answer — and since the 0.8.1 bump the pinned SDK carries the method, so
 * every build from this lockfile configures the channel. Two things beyond
 * this repository still stand between a posted question and a person: the
 * Platform grant to create the `apr_*` conversation (an operational grant,
 * server-ce#94), and routing the question to the requester's interactive
 * layer (xtrape-docs#241, unbuilt). On an SDK without the method the probe
 * declines and the fail-closed path below is what runs.
 */
export interface ConfirmationRequest {
  /**
   * WHAT is being approved: server, task, version, script digest and
   * arguments. It identifies CONTENT, not a run — two separate executions
   * share it whenever those five match — so an answer cannot be carried to
   * different content, and editing the task's script invalidates it (the rule
   * Fence states for an approval bound to a payload digest). Which run is
   * asking is `interactionId`.
   */
  executionHash: string;
  serverId: string;
  taskId: string;
  taskVersion: string;
  scriptDigest: string;
  riskLevel: string;
  /** Why confirmation is required — the policy rule that asked for it. */
  rule: string;
  /** The reason the caller gave for this invocation. */
  reason: string;
  /** What the person is being asked. */
  question: string;
  /** Who asked for the run, when the caller declared it. */
  originActor?: OriginActor | undefined;
  /** The Account the Platform delivered the carrying command under (#256) — context, not originator. */
  account?: string | undefined;
  /** The Platform command this execution settles, when there is one. */
  commandId?: string | undefined;
  /**
   * Identifier for THIS confirmation, unique per execution. The executionHash
   * says WHAT is approved (server + task + version + script + args) and two
   * distinct runs — different commands, even different users — share it when
   * the content matches; it cannot double as the conversation, or their two
   * questions would collide in one thread (review 2172). This is the commandId
   * when there is one, or a per-invocation nonce otherwise.
   */
  interactionId: string;
}

export interface ConfirmationOutcome {
  granted: boolean;
  /** Who answered, as the Platform identified them. */
  answeredBy?: string | undefined;
  /**
   * The script digest the answer EXPLICITLY approved (#53, review 2328).
   * The question discloses the digest; disclosure is not binding — only an
   * answer that repeats it proves the approval was made about THIS object
   * and not a stale or paraphrased rendition. Required for MCP-level
   * evidence (a person acting through an AI device); the Panel's own
   * surfaces carry platform-rendered evidence instead.
   */
  approvedDigest?: string | undefined;
  /**
   * Anything the person supplied beyond the decision.
   *
   * It serves the interaction and nothing else. It is never spliced into the
   * task's script and never becomes a word of a command — the same boundary a
   * parameter crosses, for the same reason: the difference between data and
   * instruction, not distrust of the person.
   */
  supplementaryInformation?: string | undefined;
}

export interface ConfirmationChannel {
  /**
   * Put the question to a person and wait for their answer.
   *
   * Waiting has no deadline of its own: a person may take hours, and the
   * Worker imposes no clock on a task. `signal` is aborted when the Platform
   * cancels the command, which is what ends a wait nobody answers.
   */
  ask(request: ConfirmationRequest, signal?: AbortSignal): Promise<ConfirmationOutcome>;
}

/**
 * What a task-file declaration and a policy rule together mean, in a sentence
 * a person can act on.
 *
 * Disclosure is the obligation: which task, on which server, why it stopped,
 * who asked for it. Being understood is not — someone who cannot follow this
 * and answers anyway still owns their answer, and nothing here should bend to
 * that.
 */
export function describeRequest(request: ConfirmationRequest): string {
  const who = request.originActor ? `${request.originActor.type} ${request.originActor.id}` : 'an unnamed caller';
  const under = request.account !== undefined ? ` (Account ${request.account})` : '';
  return [
    `${request.taskId}@${request.taskVersion} on ${request.serverId}`,
    `requested by ${who}${under}, reason: ${request.reason}`,
    `held for confirmation by rule "${request.rule}" (risk: ${request.riskLevel})`,
    `script ${request.scriptDigest}`,
    `execution ${request.executionHash}`,
  ].join(' · ');
}

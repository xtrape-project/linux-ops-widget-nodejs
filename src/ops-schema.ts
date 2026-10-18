/**
 * The ONE text of a library task on the wire (linux-ops#98, found live on m1).
 *
 * A task's ops catalog entry (what the Connector serves) and the execution
 * `inputSchema` its Checkpoint registers with the Platform come from ONE
 * canonical rich source; the registered record is the deterministic
 * enforceable projection of that source (checkpoints.ts
 * `enforceableInputSchema` + canonicalization: rich keywords such as
 * `format` / `default` / `readOnly` / constraints are dropped there, `required`
 * and the property set are kept). The review face declares
 * `candidateParameter: "serverId"`, and the Platform refuses (422,
 * runtime-platform/13 §4.2) a definition whose execution schema does not
 * declare that property. Before this module the growth paths
 * (governed content poll, tasks.enable) looked the schema up BY NAME in the
 * startup catalog; a task not in that catalog yet — every new task, every
 * held "re-version required" task — registered an EMPTY schema and was refused
 * forever ("content poll failed … keeping the last effective version" every
 * tick). The registered schema is now derived from the definition itself.
 */
import type { ActionDefinition } from './types.js';
import { describedSchema } from './schema-titles.js';

/**
 * What `policy.ts` will do with this task, said in the order policy.ts decides
 * it — the catalogue must not warn about a hold that a higher-priority denial
 * pre-empts, nor stay silent about one policy will actually apply (reviews
 * 2167 / 2176).
 *
 * `forbidden` is a hard DENY and comes first, so such a task is never also
 * described as needing approval: nobody can approve it. `always_human` and
 * high/critical risk hold unconditionally. `production-write` holds too, but
 * only on a production server — the catalogue line is one static sentence per
 * task while the target is chosen per call, so it is stated as the condition
 * it is.
 *
 * The other denials policy.ts applies (server-scope, missing-reason,
 * fail-safe-control-plane) are properties of the CALL, not of the task, and
 * belong to the refusal a caller gets, not to a task's description.
 */
export function policyNotice(action: { approvalPolicy: string; riskLevel: string }): string[] {
  if (action.approvalPolicy === 'forbidden') return ['not runnable through this surface'];
  if (action.approvalPolicy === 'always_human' || action.riskLevel === 'high' || action.riskLevel === 'critical') {
    return ['requires human approval'];
  }
  // Risk is the single axis (#61): a `medium` task runs automatically on the
  // Panel surface but is raised a notch by a production target or by the MCP
  // surface, which is what a chooser needs told up front.
  if (action.riskLevel === 'medium') return ['requires human approval on a production server or over MCP'];
  return [];
}

/** The catalog entry's own words: id as the wire name, title as the label, the chooser line, the `ops` domain. */
export function opsEntryText(action: ActionDefinition): { name: string; label: string; description: string; category: 'ops' } {
  return {
    name: action.id,
    // The display name a chooser reads (#61 / review 2365); the id stays the
    // wire name and the label falls back to it when no title is set.
    label: action.title ?? action.id,
    // Everything a chooser should know BEFORE picking this task, in the one
    // line they will actually read. This Widget does not gate a task an
    // operator approved; surfacing what it is, is the whole of the obligation.
    description: [
      action.description ?? action.id,
      `risk: ${action.riskLevel}`,
      // Silent before: a task needing a human could only be discovered by
      // trying it and being refused. See `policyNotice` for why this mirrors
      // policy.ts in policy.ts's own order.
      ...policyNotice(action),
    ].join(' — '),
    category: 'ops',
  };
}

export const paramProps = (a: ActionDefinition): Record<string, unknown> =>
  ((a.params as { properties?: Record<string, unknown> }).properties ?? {});
export const paramRequired = (a: ActionDefinition): string[] =>
  ((a.params as { required?: string[] }).required ?? []);

/** inputSchema for an ops action: serverId (+ live enum) + reason + dryRun + the action's own params. */
export function opsInputSchema(action: ActionDefinition, serverIds?: string[]): Record<string, unknown> {
  const scopes = action.serverScopes.join(', ');
  return {
    type: 'object',
    properties: {
      serverId: {
        type: 'string',
        // An empty match must SAY so (#48): the field used to degrade
        // silently into free text, inviting a value the policy engine was
        // always going to refuse. `serverIds === undefined` is the
        // catalog-time schema (no fleet read); `[]` is a live prepare that
        // found nothing.
        description:
          serverIds !== undefined && serverIds.length === 0
            ? `Target server (scopes: ${scopes}) — NO admitted server currently matches these scopes; admit one via manageServers first, any value here will be refused`
            : `Target server (scopes: ${scopes})`,
        // A live prepare ALWAYS renders a selector (#48): an empty match
        // gives an empty enum — a picker with nothing to pick, next to the
        // description saying why — rather than a free-text field inviting a
        // value the policy engine refuses regardless. The catalog-time
        // schema (serverIds === undefined) stays enum-less: no fleet read.
        ...(serverIds !== undefined ? { enum: serverIds } : {}),
      },
      reason: { type: 'string', format: 'textarea', description: 'Human-readable reason; recorded in audit' },
      dryRun: { type: 'boolean', description: 'Render the command without executing', default: false },
      // The review-to-execution binding (reviews 2322/2324): issued by
      // prepare as an HMAC-sealed token over the reviewed digest — see
      // sealReviewBinding for why a plain digest field was forgeable. On the
      // Platform surface every ops execute follows a prepare (these actions
      // declare one, and a bare execute gets ACTION_REQUIRES_PREPARE), so a
      // valid token is always demanded there.
      // hidden + readOnly (#51, panel-ce#155): a prepare-issued technical
      // token the user has no need to see — it rides the payload from
      // initialPayload and never enters their view; the raw JSON editor
      // still shows it, and tampering is refused by the HMAC check either
      // way (hiding is UX, not the security boundary).
      reviewBinding: {
        type: 'string',
        format: 'hidden',
        readOnly: true,
        description: 'Issued by prepare; opaque. Binds this run to the script version the review card showed AND to the Worker incarnation that showed it.',
      },
      ...paramProps(action),
    },
    required: ['serverId', 'reason', ...(serverIds !== undefined ? ['reviewBinding'] : []), ...paramRequired(action)],
    additionalProperties: false,
  };
}

/**
 * The canonical rich execution schema of a task — the served catalog entry's
 * `inputSchema` (schema-titles.ts), derived from the definition so the growth
 * paths never depend on the task already being in the served catalog. What the
 * Checkpoint REGISTERS is `enforceableInputSchema(...)` of this (the
 * deterministic projection), never this text itself.
 */
export function registrationSchemaForTask(action: ActionDefinition): Record<string, unknown> {
  return describedSchema(opsInputSchema(action), opsEntryText(action));
}

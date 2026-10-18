import { Ajv, type ValidateFunction } from 'ajv';
import type { ActionDefinition } from './types.js';

const SCALAR_PARAM_TYPES = new Set(['string', 'integer', 'number', 'boolean']);

const actionMetaSchema = {
  type: 'object',
  properties: {
    // Unified with the Checkpoint identity grammar (linux-ops#80 review 2674
    // P1-3): every task id must be a legal `task.<id>` checkpointId, so the
    // AUTHORING boundary enforces the checkpoint grammar — letter-start
    // dot-separated lowercase kebab, no underscores, no digit-start segments.
    // A non-conforming id is refused at write time, never discovered at
    // Checkpoint publication.
    id: { type: 'string', pattern: '^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$' },
    title: { type: 'string' },
    version: { type: 'string', pattern: '^\\d+\\.\\d+\\.\\d+$' },
    description: { type: 'string' },
    executor: { type: 'string', minLength: 1 },
    riskLevel: { enum: ['low', 'medium', 'high', 'critical'] },
    readonly: { type: 'boolean' },
    serverScopes: { type: 'array', items: { type: 'string', minLength: 1 }, minItems: 1 },
    approvalPolicy: { enum: ['policy', 'always_human', 'forbidden'] },
    params: { type: 'object' },
    interpreter: { type: 'string', minLength: 1 },
    interpreterArgs: { type: 'array', items: { type: 'string', minLength: 1 } },
    interpreterStdinArg: { type: 'string', minLength: 1 },
    script: { type: 'string', minLength: 1 },
    scriptDigest: { type: 'string', pattern: '^sha256:[0-9a-f]{64}$' },
    sourceFile: { type: 'string', minLength: 1 },
    // Governed content version of the revision (xtrape-docs#255): carried so
    // execution evidence can name the reviewed version it ran from.
    sourceVersion: { type: 'string', minLength: 1 },
    timeoutSeconds: { type: 'integer', minimum: 1 },
    outputPolicy: {
      type: 'object',
      properties: {
        redact: { type: 'array', items: { type: 'string' } },
        maxBytes: { type: 'integer', minimum: 1 },
      },
      additionalProperties: false,
    },
  },
  required: [
    'id',
    'version',
    'executor',
    'riskLevel',
    'readonly',
    'serverScopes',
    'approvalPolicy',
    'params',
    'interpreter',
    'script',
    'scriptDigest',
    'sourceFile',
  ],
  additionalProperties: false,
} as const;

export class ActionRegistry {
  private readonly actions = new Map<string, ActionDefinition>();
  private readonly validators = new Map<string, ValidateFunction>();
  private readonly ajv = new Ajv({ allErrors: true, strict: true });
  private readonly validateMeta = this.ajv.compile(actionMetaSchema);

  /** Register one action definition; throws on any spec violation. */
  register(definition: ActionDefinition): void {
    const label = typeof definition?.id === 'string' ? definition.id : '<unknown>';
    if (!this.validateMeta(definition)) {
      const detail = this.ajv.errorsText(this.validateMeta.errors);
      throw new Error(`invalid action definition ${label}: ${detail}`);
    }
    if (this.actions.has(definition.id)) {
      throw new Error(`duplicate action id "${definition.id}"`);
    }
    const params = definition.params as { type?: string; additionalProperties?: boolean; properties?: Record<string, unknown> };
    if (params.type !== 'object' || params.additionalProperties !== false) {
      throw new Error(
        `action "${definition.id}": params schema must be an object schema with additionalProperties: false`,
      );
    }
    const declared = new Set(Object.keys(params.properties ?? {}));
    // serverId/reason/dryRun are top-level ops inputs merged around the action's
    // own params (see ce-actions opsInputSchema). An action must not declare a
    // param with a reserved name, or it would shadow the live serverId enum /
    // reason and let one field be both a control field and a command arg,
    // violating the exact input contract (#27, archived review).
    for (const reserved of ['serverId', 'reason', 'dryRun']) {
      if (declared.has(reserved)) {
        throw new Error(`action "${definition.id}": param "${reserved}" is a reserved top-level ops input and cannot be an action param`);
      }
    }
    // Every declared parameter crosses the boundary as an environment
    // variable, so each must be a scalar with a portable name. A composite
    // value has no faithful environment representation, and `String(value)`
    // would hand the script something it cannot parse back.
    for (const [name, schema] of Object.entries(params.properties ?? {})) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        throw new Error(`action "${definition.id}": param "${name}" is not a usable environment variable name`);
      }
      const type = (schema as { type?: unknown }).type;
      if (typeof type !== 'string' || !SCALAR_PARAM_TYPES.has(type)) {
        throw new Error(
          `action "${definition.id}": param "${name}" must be a scalar (string, integer, number, boolean); parameters reach the script as environment variables`,
        );
      }
    }
    this.validators.set(definition.id, this.ajv.compile(definition.params));
    this.actions.set(definition.id, definition);
  }

  /**
   * Remove one action from the runtime registry (#55: disabling or replacing
   * a task at runtime). Unknown ids are a no-op — the caller's file-level
   * state is the truth this mirrors.
   */
  unregister(actionId: string): void {
    this.actions.delete(actionId);
    this.validators.delete(actionId);
  }

  get(actionId: string): ActionDefinition | undefined {
    return this.actions.get(actionId);
  }

  /**
   * Replace the whole live catalog with `definitions`.
   *
   * A governed library's content arrives as a SET, not as a stream of edits
   * (xtrape-docs#255): applying it one register/unregister at a time would
   * leave the catalog briefly describing neither the old version nor the new.
   */
  reset(definitions: ActionDefinition[]): void {
    for (const existing of this.list()) this.unregister(existing.id);
    for (const definition of definitions) this.register(definition);
  }

  list(): ActionDefinition[] {
    return [...this.actions.values()];
  }

  /** Validate caller args against the action's params schema. */
  validateArgs(actionId: string, args: Record<string, unknown>): { ok: true } | { ok: false; errors: string } {
    const validate = this.validators.get(actionId);
    if (!validate) return { ok: false, errors: `unknown action "${actionId}"` };
    if (validate(args)) return { ok: true };
    return { ok: false, errors: this.ajv.errorsText(validate.errors) };
  }

}

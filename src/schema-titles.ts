/**
 * Widget Design Conventions §5 (xtrape-docs products/service/01, owner
 * 2026-09-06): an AI host sees ONLY the admitted input schema plus a
 * description, and the Panel labels a field `title ?? key`. So every Action's
 * inputSchema carries a root `title` (= the label) and `description`, and
 * every property carries a human `title` (full words, no abbreviations) and a
 * `description`. Applied ONCE, at catalog assembly, to the static schemas and
 * to every schema a prepare hands back — no author has to remember it.
 */
import type { CeActionPrepareResult, CeServiceActionDefinition } from '@xtrape/connector';

/** Which element cluster an Action belongs to — decides what an ambiguous key such as `id` names (review 3177). */
export type FieldDomain = 'server' | 'task' | 'none';

export const FIELD_TITLES: Readonly<Record<string, string>> = {
  serverId: 'Target server', reason: 'Reason', dryRun: 'Dry run', reviewBinding: 'Review binding',
  host: 'Host', port: 'SSH port', username: 'SSH user', authMethod: 'Authentication method',
  privateKey: 'Private key', passphrase: 'Passphrase', password: 'Password', hostKeyFingerprint: 'Host key fingerprint',
  environment: 'Environment', shells: 'Available interpreters',
  expectedHost: 'Expected host', expectedPort: 'Expected port', expectedFingerprint: 'Expected fingerprint',
  expectedGeneration: 'Expected record generation', newFingerprint: 'New fingerprint', probeBinding: 'Probe binding',
  state: 'Task state', baseRevision: 'Base revision',
};

/** Keys whose meaning depends on the cluster: the same `id` is a Server on `_servers` and a Task on `_tasks`. */
export const DOMAIN_FIELD_TITLES: Readonly<Record<Exclude<FieldDomain, 'none'>, Readonly<Record<string, string>>>> = {
  server: { id: 'Server ID' },
  task: { id: 'Task ID' },
};
const DOMAIN_FIELD_DESCRIPTIONS: Readonly<Record<Exclude<FieldDomain, 'none'>, Readonly<Record<string, string>>>> = {
  server: { id: 'Identifier of the admitted server this operation targets — take it from the Managed Servers list row, do not guess.' },
  task: { id: 'Identifier of the task this operation targets (lowercase, dot-separated, e.g. system.uptime) — take it from the Task Library list row, do not guess.' },
};

/**
 * The cluster an Action's fields belong to, from its category: `_servers` /
 * the fleet entry → server; `_tasks` / the library entry → task. An `ops`
 * Action (a task run) stays NEUTRAL (review 3178): its task identity is the
 * Action name, and an input named `id` there is an ordinary business
 * parameter the task author declared — never the task identity.
 */
export function fieldDomainOf(action: { name: string; category?: string }): FieldDomain {
  const c = action.category ?? '';
  if (c === '_servers' || action.name === 'manageServers') return 'server';
  if (c === '_tasks' || action.name === 'manageTasks') return 'task';
  return 'none';
}

/** Descriptions for fields whose declaring schema says nothing (the AI-facing text). */
export const FIELD_DESCRIPTIONS: Readonly<Record<string, string>> = {
  state: 'Which stored copy: "enabled" (the executable, approved version) or "draft" (the pending edit).',
  environment: 'What the target is used for: production, staging or development. A production target raises the effective risk of every task run on it by one step.',
  reviewBinding: 'Issued by prepare; opaque — do not edit.',
  label: 'Human-readable label shown for this parameter in forms.',
  type: 'Value type of the parameter: string, integer, number or boolean.',
  required: 'Whether the caller must supply this parameter.',
  default: 'Value used when the caller supplies none.',
  pattern: 'Regular expression the value must match.',
  description: 'What this parameter means, shown to the person or AI filling it in.',
};

const humanize = (key: string): string => key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').replace(/^./, (c) => c.toUpperCase());

/** Fill `title` / `description` where a property (nested object members and array items included) declares none. */
export function withFieldTitles(schema: Record<string, unknown>, domain: FieldDomain = 'none'): Record<string, unknown> {
  const props = schema['properties'] as Record<string, Record<string, unknown>> | undefined;
  if (!props) return schema;
  const byDomain = domain === 'none' ? {} : DOMAIN_FIELD_TITLES[domain];
  const descByDomain = domain === 'none' ? {} : DOMAIN_FIELD_DESCRIPTIONS[domain];
  const next: Record<string, Record<string, unknown>> = {};
  for (const [k, v] of Object.entries(props)) {
    const title = typeof v['title'] === 'string' && v['title'].trim() !== '' ? (v['title'] as string) : byDomain[k] ?? FIELD_TITLES[k] ?? humanize(k);
    const description = typeof v['description'] === 'string' && v['description'].trim() !== '' ? (v['description'] as string) : descByDomain[k] ?? FIELD_DESCRIPTIONS[k] ?? title;
    let prop: Record<string, unknown> = { title, description, ...v, ...(typeof v['title'] === 'string' ? {} : { title }), ...(typeof v['description'] === 'string' && (v['description'] as string).trim() !== '' ? {} : { description }) };
    if (prop['type'] === 'object') prop = withFieldTitles(prop, domain);
    const items = prop['items'] as Record<string, unknown> | undefined;
    if (items && items['type'] === 'object') prop = { ...prop, items: withFieldTitles(items, domain) };
    next[k] = prop;
  }
  return { ...schema, properties: next };
}

/** Root title/description from the Action's own label/description, then every field. */
export function describedSchema(schema: Record<string, unknown>, action: { label?: string; description?: string; name: string; category?: string }): Record<string, unknown> {
  const titled = withFieldTitles(schema, fieldDomainOf(action));
  return {
    ...(typeof titled['title'] === 'string' ? {} : { title: action.label ?? action.name }),
    ...(typeof titled['description'] === 'string' ? {} : { description: action.description ?? action.label ?? action.name }),
    ...titled,
  };
}

/** An Action whose static schema AND every prepare-issued schema are self-describing. */
export function describedAction(action: CeServiceActionDefinition): CeServiceActionDefinition {
  // No schema = no input; still an object schema so the record carries the
  // Action's title/description to the AI host.
  const schema = (action.inputSchema as Record<string, unknown> | undefined) ?? { type: 'object', properties: {}, additionalProperties: false };
  const prepare = action.prepare;
  return {
    ...action,
    inputSchema: describedSchema(schema, action),
    ...(prepare
      ? {
          prepare: async (...args: Parameters<typeof prepare>): Promise<CeActionPrepareResult> => {
            const r = await prepare(...args);
            return r.inputSchema ? { ...r, inputSchema: describedSchema(r.inputSchema, action) } : r;
          },
        }
      : {}),
  };
}

/**
 * The schema a Checkpoint REGISTERS with (index.ts): the same described entry
 * the live catalog serves — for management rows AND ops tasks — so the
 * admitted record and the Panel form are one text. Found live on m1
 * (linux-ops#93): task rows registered the bare `opsInputSchema` and the AI
 * host saw every task field untitled while the catalog was described.
 */
export function registrationInputSchemaFor(catalog: readonly CeServiceActionDefinition[], name: string): Record<string, unknown> | undefined {
  return catalog.find((a) => a.name === name)?.inputSchema as Record<string, unknown> | undefined;
}

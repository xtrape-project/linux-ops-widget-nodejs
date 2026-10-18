import { CE_CONTRACT_VERSION, type ServiceManifest } from '@xtrape/contracts';

export const LINUX_OPS_WIDGET_VERSION = '0.8.7';
// Pinned for this CE phase: the current Platform CE is single-tenant (`default`).
export const LINUX_OPS_WIDGET_TENANT = 'default';

/**
 * Default logical Service ID — the **single switch point** for this Service's
 * identity. Nothing else in this repository hard-codes the value: the manifest,
 * the Checkpoint namespace, the Exposure Selection value and the Resource form
 * all derive from it, so changing this one line renames the Service everywhere
 * on this side.
 *
 * It is a *logical Service ID*: deliberately not a Worker identity and not a
 * package name. The value currently spells the repository name in full
 * (`linux-ops-widget-nodejs`) because that is what the maintainer asked to see
 * in the Panel — the retired short name `ops-linux` names a repository that is
 * slated for deletion, so a Service called after it would outlive its referent.
 *
 * Caveat worth knowing before it bites: `-nodejs` is an *implementation
 * language* suffix, a repository-naming dimension (docs D22). A logical Service
 * ID does not otherwise carry one, so re-implementing this Widget in another
 * language would force a second rename. `linux-ops-widget` is the more stable
 * spelling if that ever matters; flipping to it is this one line plus the
 * matching default in xtrape-deployment's `m1-local/.env.example`.
 *
 * See xtrape-docs architecture/16 and products/mcp/00-overview.
 */
export const DEFAULT_SERVICE_ID = 'linux-ops-widget-nodejs';

export function buildManifest(
  // `||`, not `??`: an env var that is present but empty must fall back too. A
  // deployment that passes the variable through from its own environment
  // (docker compose `${VAR:-}`) delivers "" rather than unset, and "" is never a
  // valid Service ID — registering under it would fail the Platform's kebab
  // pattern at best, and silently create a nameless Service at worst.
  serviceId = process.env.LINUX_OPS_WIDGET_SERVICE_ID || DEFAULT_SERVICE_ID,
): ServiceManifest {
  return {
    contractVersion: CE_CONTRACT_VERSION,
    tenant: LINUX_OPS_WIDGET_TENANT,
    service: {
      id: serviceId,
      name: 'linux-ops-widget',
      version: LINUX_OPS_WIDGET_VERSION,
      description:
        'Linux Ops Widget: controlled Linux host operations as structured actions over a managed server fleet, no raw shell.',
    },
    // `runtime.agent` is a frozen wire key of the CE registration contract; the
    // value names the Connector SDK package actually embedded here.
    runtime: { language: 'nodejs', agent: '@xtrape/connector' },
    capabilities: ['ops.execute', 'server.management', 'health.check'],
    // APPROVAL_REQUEST / APPROVAL_RESPONSE are declared because this Widget
    // uses them: a dangerous task puts a question to a person and waits for the
    // answer (the confirmation mechanism). Declaring only QUERY/SUMMARY while
    // emitting APPROVAL_REQUEST would misdescribe the Service to the Platform.
    message: { supportedTypes: ['QUERY', 'SUMMARY', 'APPROVAL_REQUEST', 'APPROVAL_RESPONSE'] },
  };
}

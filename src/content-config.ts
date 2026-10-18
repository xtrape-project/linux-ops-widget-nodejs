import { CuratorContentSource, type ContentSource } from './content-source.js';

/**
 * Build the governed content source from the environment, or `undefined` for
 * a locally managed library (xtrape-docs#255).
 *
 * The source is the **Curator Widget** (curator-git-widget-nodejs) over the
 * CE s2s convention — this Widget carries no git client, no forge token and
 * no review logic; versioning and approval are the Curator's whole job.
 *
 * All-or-nothing on purpose: a half-configured source would silently fall
 * back to the local library, so an operator who meant to govern this Widget
 * would get an ungoverned one and no error.
 */
export function contentSourceFromEnv(env: NodeJS.ProcessEnv): { source: ContentSource; path: (taskId: string) => string; describe: string } | undefined {
  const baseUrl = env.LINUX_OPS_WIDGET_CURATOR_URL?.trim();
  const serviceToken = env.LINUX_OPS_WIDGET_CURATOR_TOKEN?.trim();
  const declared = [baseUrl, serviceToken].filter((v) => v !== undefined && v !== '');
  if (declared.length === 0) return undefined;
  if (!baseUrl || !serviceToken) {
    throw new Error(
      'a governed task library needs LINUX_OPS_WIDGET_CURATOR_URL and LINUX_OPS_WIDGET_CURATOR_TOKEN together; ' +
        'set both or neither (a partial setting would silently run an ungoverned library)',
    );
  }
  const dir = (env.LINUX_OPS_WIDGET_CURATOR_DIR?.trim() || 'tasks').replace(/^\/+|\/+$/g, '');
  // Who an edit through this surface speaks for is NOT configured here: the
  // Platform delivers the authenticated Account with every command
  // (xtrape-docs runtime-platform/12, #256) and the proposal forwards that
  // origin unchanged. The pre-#256 per-deployment identity
  // (LINUX_OPS_WIDGET_SUBMIT_AS) is refused rather than ignored, so a
  // deployment cannot keep believing its edits are attributed to it.
  if (env.LINUX_OPS_WIDGET_SUBMIT_AS !== undefined) {
    throw new Error('LINUX_OPS_WIDGET_SUBMIT_AS is no longer read: proposals carry the Account the Platform delivers with each command (#256); remove the variable');
  }
  const reviewUrlBase = env.LINUX_OPS_WIDGET_CURATOR_REVIEW_URL?.trim();
  return {
    source: new CuratorContentSource({ baseUrl, serviceToken, dir, ...(reviewUrlBase ? { reviewUrlBase } : {}) }),
    // One task, one file, named by its id — so a reviewer reading the diff
    // sees which task changed without opening the file. Anything that is not
    // a plain name character collapses to a dash and leading dots are
    // dropped: task ids are validated elsewhere, and this is the layer that
    // must not turn one into a path.
    path: (taskId: string) => `${dir}/${(taskId.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^\.+/, '') || 'task')}.sh`,
    describe: `curator at ${baseUrl} (${dir}/)`,
  };
}

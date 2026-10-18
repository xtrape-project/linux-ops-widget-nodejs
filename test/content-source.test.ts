import { describe, expect, it } from 'vitest';
import { CuratorContentSource, S2S_ORIGIN_HEADER, S2S_TOKEN_HEADER } from '../src/content-source.js';

interface Call { method: string; url: string; body?: unknown | undefined; headers: Record<string, string> }

/** A Curator that answers the two routes this client uses, and records what it was asked. */
function fakeCurator(options: { files?: Array<{ path: string; bytes: string }>; versionId?: string; sequence?: number } = {}) {
  const calls: Call[] = [];
  const impl: typeof fetch = async (input, init) => {
    const url = String(input);
    const method = init?.method ?? 'GET';
    calls.push({ method, url, body: init?.body ? JSON.parse(String(init.body)) : undefined, headers: (init?.headers ?? {}) as Record<string, string> });
    const json = (value: unknown): Response => new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } });
    if (method === 'GET' && url.includes('/v1/current')) {
      return json({ versionId: options.versionId ?? 'commit-abc', sequence: options.sequence ?? 7, files: options.files ?? [] });
    }
    if (method === 'POST' && url.endsWith('/v1/submit')) return json({ id: 'deploy.sh-12ab34cd', commit: 'c1', contentDigest: 'sha256:x' });
    return new Response(JSON.stringify({ code: 'NOT_FOUND' }), { status: 404 });
  };
  return { impl, calls };
}

const source = (impl: typeof fetch): CuratorContentSource =>
  new CuratorContentSource({ baseUrl: 'http://127.0.0.1:8790', serviceToken: 'deployment-shared-token', dir: 'tasks', fetchImpl: impl });

describe('CuratorContentSource (xtrape-docs#255, s2s convention)', () => {
  it('reads the effective set and presents the shared credential on every call', async () => {
    const curator = fakeCurator({ files: [{ path: 'tasks/a.sh', bytes: 'echo a' }] });
    const effective = await source(curator.impl).fetchEffective();
    expect(effective).toEqual({ versionId: 'commit-abc', sequence: 7, files: [{ path: 'tasks/a.sh', bytes: 'echo a' }] });
    for (const call of curator.calls) {
      expect(call.headers[S2S_TOKEN_HEADER]).toBe('deployment-shared-token');
      expect(call.url).not.toContain('deployment-shared-token'); // header only, never the URL
    }
  });

  it('a submission carries the delivered origin as the s2s HEADER, not as body data', async () => {
    const curator = fakeCurator();
    const result = await source(curator.impl).submit({
      path: 'tasks/deploy.sh', bytes: 'echo deploy', message: 'add deploy',
      origin: { account: 'acct_owner', traceId: 'tr_1' },
    });
    expect(result.submissionId).toBe('deploy.sh-12ab34cd');
    const submit = curator.calls.find((c) => c.url.endsWith('/v1/submit'))!;
    // The origin header is what the Curator records and enforces
    // approver ≠ author against; a body field would be a caller's claim.
    // It travels VERBATIM in the contracts CommandOrigin shape (#256) — no
    // rewriting, no filling from a deployment identity.
    expect(JSON.parse(submit.headers[S2S_ORIGIN_HEADER]!)).toEqual({ account: 'acct_owner', traceId: 'tr_1' });
    expect(submit.body).not.toHaveProperty('origin');
    expect(submit.body).not.toHaveProperty('author');
  });

  it('a content set with sequence missing is refused whole', async () => {
    const impl: typeof fetch = async () => new Response(JSON.stringify({ versionId: 'x', files: [] }), { status: 200 });
    await expect(source(impl).fetchEffective()).rejects.toThrow(/no usable content set/);
  });

  it('a malformed FILE entry refuses the whole set, not just that entry', async () => {
    const impl: typeof fetch = async () =>
      new Response(JSON.stringify({ versionId: 'x', sequence: 1, files: [{ path: 'tasks/a.sh', bytes: 'ok' }, { path: 42 }] }), { status: 200 });
    await expect(source(impl).fetchEffective()).rejects.toThrow(/malformed file entry/);
  });

  it('a Curator error names the route and status instead of failing silently', async () => {
    const impl: typeof fetch = async () => new Response('boom', { status: 503 });
    await expect(source(impl).fetchEffective()).rejects.toThrow(/HTTP 503/);
  });

  it('a malformed content set is refused, not half-applied', async () => {
    const impl: typeof fetch = async () => new Response(JSON.stringify({ nope: true }), { status: 200 });
    await expect(source(impl).fetchEffective()).rejects.toThrow(/no usable content set/);
  });
});

describe('contentSourceFromEnv', () => {
  it('is all-or-nothing: a half-configured source refuses instead of silently running ungoverned', async () => {
    const { contentSourceFromEnv } = await import('../src/content-config.js');
    expect(contentSourceFromEnv({})).toBeUndefined();
    expect(() => contentSourceFromEnv({ LINUX_OPS_WIDGET_CURATOR_URL: 'http://127.0.0.1:8790' })).toThrow(/set both or neither/);
  });

  it('refuses the retired per-deployment submitter identity instead of ignoring it (#256)', async () => {
    const { contentSourceFromEnv } = await import('../src/content-config.js');
    expect(() =>
      contentSourceFromEnv({
        LINUX_OPS_WIDGET_CURATOR_URL: 'http://127.0.0.1:8790',
        LINUX_OPS_WIDGET_CURATOR_TOKEN: 'tok',
        LINUX_OPS_WIDGET_SUBMIT_AS: '{"account":"acct_owner"}',
      }),
    ).toThrow(/no longer read/);
  });

  it('derives the per-task path from the configured directory, flattening hostile ids', async () => {
    const { contentSourceFromEnv } = await import('../src/content-config.js');
    const built = contentSourceFromEnv({
      LINUX_OPS_WIDGET_CURATOR_URL: 'http://127.0.0.1:8790',
      LINUX_OPS_WIDGET_CURATOR_TOKEN: 'tok',
    })!;
    expect(built.describe).toBe('curator at http://127.0.0.1:8790 (tasks/)');
    expect(built.path('xtrape.upgrade')).toBe('tasks/xtrape.upgrade.sh');
    // A task id that could climb out of the directory is flattened, not
    // trusted: no slashes survive and it cannot start with a dot.
    expect(built.path('../../etc/passwd')).toBe('tasks/-..-etc-passwd.sh');
    expect(built.path('/etc/shadow')).toBe('tasks/-etc-shadow.sh');
  });
});

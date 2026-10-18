import { describe, expect, it } from 'vitest';
import { ActionRegistry } from '../src/registry.js';
import { makeAction } from './helpers.js';

describe('ActionRegistry', () => {
  it('rejects an action that declares a reserved top-level ops input as a param', () => {
    for (const reserved of ['serverId', 'reason', 'dryRun']) {
      const registry = new ActionRegistry();
      expect(() =>
        registry.register(
          makeAction({
            id: 'bad.action',
            params: { type: 'object', additionalProperties: false, properties: { [reserved]: { type: 'string' } } },
            script: 'echo hi',
          }),
        ),
      ).toThrow(/reserved/);
    }
  });

  it('registers a valid action and validates args', () => {
    const registry = new ActionRegistry();
    registry.register(
      makeAction({
        id: 'nginx.reload',
        params: {
          type: 'object',
          properties: { site: { type: 'string', pattern: '^[a-z0-9-]+$' } },
          required: ['site'],
          additionalProperties: false,
        },
        script: 'nginx-reload {{site}}',
      }),
    );
    expect(registry.validateArgs('nginx.reload', { site: 'example' })).toEqual({ ok: true });
  });

  it('rejects args that violate the schema', () => {
    const registry = new ActionRegistry();
    registry.register(
      makeAction({
        params: {
          type: 'object',
          properties: { site: { type: 'string', pattern: '^[a-z0-9-]+$' } },
          required: ['site'],
          additionalProperties: false,
        },
        script: 'x {{site}}',
      }),
    );
    expect(registry.validateArgs('system.uptime', { site: 'bad value; rm -rf /' }).ok).toBe(false);
    expect(registry.validateArgs('system.uptime', { site: 'ok', extra: 1 }).ok).toBe(false);
    expect(registry.validateArgs('system.uptime', {}).ok).toBe(false);
  });

  it('rejects params schemas without additionalProperties:false', () => {
    const registry = new ActionRegistry();
    expect(() =>
      registry.register(makeAction({ params: { type: 'object', properties: {} } })),
    ).toThrow(/additionalProperties/);
  });

  it('rejects a param whose name is not a usable environment variable name', () => {
    // Parameters cross the boundary as environment variables, so a name the
    // target cannot express is a task that would silently lose an argument.
    const registry = new ActionRegistry();
    expect(() =>
      registry.register(
        makeAction({ params: { type: 'object', properties: { 'my-path': { type: 'string' } }, additionalProperties: false } }),
      ),
    ).toThrow(/environment variable name/);
  });

  it('rejects duplicate ids and malformed definitions', () => {
    const registry = new ActionRegistry();
    registry.register(makeAction());
    expect(() => registry.register(makeAction())).toThrow(/duplicate/);
    expect(() =>
      registry.register(makeAction({ id: 'no-namespace', riskLevel: 'extreme' as never })),
    ).toThrow(/invalid action definition/);
  });

  it('reports unknown actions on args validation', () => {
    const registry = new ActionRegistry();
    expect(registry.validateArgs('nope.nope', {}).ok).toBe(false);
  });
});

import { ActionRegistry } from '../src/registry.js';
import { createHash } from 'node:crypto';
import type { ActionDefinition, CommandInvocation, CommandResult, Executor, ServerDefinition } from '../src/types.js';

export function makeAction(overrides: Partial<ActionDefinition> = {}): ActionDefinition {
  return {
    id: 'system.uptime',
    version: '1.0.0',
    executor: 'ssh',
    riskLevel: 'low',
    readonly: true,
    serverScopes: ['*'],
    approvalPolicy: 'policy',
    params: { type: 'object', properties: {}, additionalProperties: false },
    interpreter: 'bash',
    script: 'uptime\n',
    scriptDigest: `sha256:${createHash('sha256').update(overrides.script ?? 'uptime\n', 'utf8').digest('hex')}`,
    sourceFile: 'system-uptime.sh',
    ...overrides,
  };
}

/** A well-formed OpenSSH host key fingerprint; a digest of a public key, not a secret. */
export const TEST_HOST_KEY_FINGERPRINT = 'SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4';

export function makeServer(overrides: Partial<ServerDefinition> = {}): ServerDefinition {
  return {
    id: 'web-dev-01',
    host: '192.0.2.10',
    username: 'linux-ops',
    environment: 'development',
    hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT,
    ...overrides,
  };
}

export function makeRegistry(...actions: ActionDefinition[]): ActionRegistry {
  const registry = new ActionRegistry();
  for (const action of actions) registry.register(action);
  return registry;
}

/** Records invocations instead of executing them. */
export class FakeExecutor implements Executor {
  readonly name = 'ssh';
  readonly commands: string[] = [];
  readonly invocations: CommandInvocation[] = [];
  constructor(private readonly exitCode: number = 0) {}
  async run(_server: ServerDefinition, invocation: CommandInvocation): Promise<CommandResult> {
    this.commands.push(invocation.command);
    this.invocations.push(invocation);
    const { command } = invocation;
    return { command, exitCode: this.exitCode, stdout: `ran: ${command}`, stderr: '' };
  }
}

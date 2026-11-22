/** Provider-neutral connector API. Never trust caller-provided identity or authorization. */
export type Capability = 'health.read' | 'records.read' | 'records.write' | (string & {});
export type ConnectionState = 'planned' | 'implemented' | 'verified' | 'operational' | 'degraded' | 'unavailable';
export interface ConnectorManifest {
  readonly id: string;
  readonly version: string;
  readonly capabilities: readonly Capability[];
  readonly state: ConnectionState;
}
export interface ExecutionContext {
  readonly tenantId: string;
  readonly actorId: string;
  readonly connectionId: string;
  readonly permittedCapabilities: readonly Capability[];
  readonly approvalId?: string;
}
export interface CapabilityRequest {
  readonly capability: Capability;
  readonly input: Readonly<Record<string, unknown>>;
  readonly idempotencyKey?: string;
}
export interface CapabilityResult {
  readonly data: unknown;
  readonly providerRequestId?: string;
}
export interface Connector {
  readonly manifest: ConnectorManifest;
  execute(context: ExecutionContext, request: CapabilityRequest): Promise<CapabilityResult>;
  healthCheck(): Promise<'healthy' | 'degraded' | 'unavailable'>;
}
export class ConnectorError extends Error {
  readonly code: 'INVALID_REQUEST' | 'NOT_FOUND' | 'NOT_VERIFIED' | 'FORBIDDEN' | 'APPROVAL_REQUIRED' | 'ALREADY_REGISTERED';
  constructor(code: ConnectorError['code'], message: string) {
    super(message);
    this.code = code;
    this.name = 'ConnectorError';
  }
}
const validId = (s: string): boolean => /^[a-z][a-z0-9._-]{1,127}$/.test(s);
const nonempty = (s: string): boolean => typeof s === 'string' && s.trim().length > 0;
export class ConnectorRegistry {
  readonly #connectors = new Map<string, Connector>();
  register(connector: Connector): void {
    const { id, version, capabilities } = connector.manifest;
    if (!validId(id) || !nonempty(version) || !Array.isArray(capabilities) || capabilities.length === 0 || capabilities.some(c => !nonempty(c))) {
      throw new ConnectorError('INVALID_REQUEST', 'Invalid connector manifest');
    }
    if (this.#connectors.has(id)) throw new ConnectorError('ALREADY_REGISTERED', 'Connector already registered');
    this.#connectors.set(id, connector);
  }
  list(): readonly ConnectorManifest[] {
    return [...this.#connectors.values()].map(c => ({...c.manifest, capabilities: [...c.manifest.capabilities]}));
  }
  async execute(context: ExecutionContext, connectorId: string, request: CapabilityRequest): Promise<CapabilityResult> {
    if (![context.tenantId, context.actorId, context.connectionId, connectorId, request.capability].every(nonempty) || !request.input || typeof request.input !== 'object' || Array.isArray(request.input)) {
      throw new ConnectorError('INVALID_REQUEST', 'Invalid request or execution context');
    }
    const connector = this.#connectors.get(connectorId);
    if (!connector) throw new ConnectorError('NOT_FOUND', 'Connector not registered');
    if (!['verified', 'operational'].includes(connector.manifest.state)) throw new ConnectorError('NOT_VERIFIED', 'Connector has not been verified');
    if (!connector.manifest.capabilities.includes(request.capability)) throw new ConnectorError('FORBIDDEN', 'Connector does not support capability');
    if (!context.permittedCapabilities.includes(request.capability)) throw new ConnectorError('FORBIDDEN', 'Capability not authorized');
    if (request.capability.endsWith('.write') && !nonempty(context.approvalId || '')) throw new ConnectorError('APPROVAL_REQUIRED', 'Write operation requires approval');
    // Server MUST verify tenant ownership, identity, policies and approval records before building context.
    return connector.execute(context, request);
  }
}

import {
  ConnectorError, ConnectorRegistry,
  type Capability, type CapabilityRequest, type CapabilityResult,
  type ExecutionContext
} from '../../connector-sdk/src/index.ts';

/** Authenticated, cryptographically verified principal. Must be established by
 * Identity or a trusted service-auth middleware, never copied from a request body. */
export interface Principal {
  readonly subject: string;
  readonly tenantId: string;
  readonly assuranceLevel: number;
}
export interface ConnectionRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly connectorId: string;
  readonly enabled: boolean;
  readonly capabilities: readonly Capability[];
}
export interface ConnectionStore {
  getById(id: string): Promise<ConnectionRecord | null>;
}
export interface AuthorizationDecision {
  readonly allowed: boolean;
  readonly reason?: string;
}
export interface PolicyEngine {
  canExecute(principal: Principal, connection: ConnectionRecord, capability: Capability): Promise<AuthorizationDecision>;
}
export interface ApprovalStore {
  /** Must verify tenant, actor, connection, capability, action details, expiry, and status. */
  verifyAndConsume(input: {
    principal: Principal;
    connection: ConnectionRecord;
    request: CapabilityRequest;
    approvalId: string;
  }): Promise<boolean>;
}
export interface AuditSink {
  record(event: {
    event: 'connector.denied' | 'connector.executed' | 'connector.failed';
    tenantId: string;
    actorId: string;
    connectionId: string;
    connectorId: string;
    capability: Capability;
    reason?: string;
  }): Promise<void>;
}
export interface GatewayInput {
  readonly connectionId: string;
  readonly request: CapabilityRequest;
  readonly approvalId?: string;
}
export class ExecutionGateway {
  constructor(
    private readonly registry: ConnectorRegistry,
    private readonly connections: ConnectionStore,
    private readonly policies: PolicyEngine,
    private readonly approvals: ApprovalStore,
    private readonly audit: AuditSink
  ) {}
  async execute(principal: Principal, input: GatewayInput): Promise<CapabilityResult> {
    if (!principal || !principal.subject?.trim() || !principal.tenantId?.trim() ||
      !Number.isInteger(principal.assuranceLevel) || !input?.connectionId?.trim() ||
      !input.request?.capability?.trim()) {
      throw new ConnectorError('INVALID_REQUEST', 'Missing authenticated principal or request');
    }
    const connection = await this.connections.getById(input.connectionId);
    if (!connection || connection.tenantId !== principal.tenantId || !connection.enabled) {
      // Do not leak whether an inaccessible connection exists.
      throw new ConnectorError('NOT_FOUND', 'Connection unavailable');
    }
    const event = {
      tenantId: principal.tenantId,
      actorId: principal.subject,
      connectionId: connection.id,
      connectorId: connection.connectorId,
      capability: input.request.capability,
    };
    const deny = async (reason: string): Promise<never> => {
      await this.audit.record({ event: 'connector.denied', ...event, reason });
      throw new ConnectorError('FORBIDDEN', 'Connection operation not permitted');
    };
    if (!connection.capabilities.includes(input.request.capability)) return deny('connection_scope');
    const decision = await this.policies.canExecute(principal, connection, input.request.capability);
    if (!decision.allowed) return deny(decision.reason || 'policy');
    const requiresApproval = !input.request.capability.endsWith('.read') &&
      input.request.capability !== 'health.read';
    let approvalId: string | undefined;
    if (requiresApproval) {
      if (!input.approvalId) {
        await this.audit.record({ event: 'connector.denied', ...event, reason: 'approval_missing' });
        throw new ConnectorError('APPROVAL_REQUIRED', 'Verified approval required');
      }
      const valid = await this.approvals.verifyAndConsume({
        principal, connection, request: input.request, approvalId: input.approvalId,
      });
      if (!valid) {
        await this.audit.record({ event: 'connector.denied', ...event, reason: 'approval_invalid' });
        throw new ConnectorError('APPROVAL_REQUIRED', 'Verified approval required');
      }
      approvalId = input.approvalId;
    }
    const context: ExecutionContext = {
      tenantId: principal.tenantId,
      actorId: principal.subject,
      connectionId: connection.id,
      permittedCapabilities: [input.request.capability],
      ...(approvalId ? { approvalId } : {}),
    };
    try {
      const result = await this.registry.execute(context, connection.connectorId, input.request);
      await this.audit.record({ event: 'connector.executed', ...event });
      return result;
    } catch (error) {
      await this.audit.record({ event: 'connector.failed', ...event, reason: 'execution_error' });
      throw error;
    }
  }
}

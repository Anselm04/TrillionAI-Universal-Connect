import { createHash } from 'node:crypto';
import pg from 'pg';
import type { AuditSink, ApprovalStore, ConnectionRecord, ConnectionStore } from '../../gateway/src/index.ts';
import type { CapabilityRequest } from '../../connector-sdk/src/index.ts';

export type SqlPool = Pick<pg.Pool, 'connect'>;
type QueryResult = { rows: any[]; rowCount: number | null };
export interface TenantClient {
  query(sql: string, values?: readonly unknown[]): Promise<QueryResult>;
  release(): void;
}
export interface TenantPool {
  connect(): Promise<TenantClient>;
}
export async function inTenantTransaction<T>(
  pool: TenantPool, tenantId: string, execute: (client: TenantClient) => Promise<T>,
): Promise<T> {
  if (!tenantId || !tenantId.trim() || tenantId.length > 128) throw new Error('Invalid tenant scope');
  const client = await pool.connect();
  let started = false;
  try {
    await client.query('BEGIN');
    started = true;
    // Scope is transaction-local, so a pooled connection cannot leak a prior tenant.
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    const result = await execute(client);
    await client.query('COMMIT');
    started = false;
    return result;
  } catch (error) {
    if (started) {
      try { await client.query('ROLLBACK'); } catch { /* preserve original error */ }
    }
    throw error;
  } finally {
    client.release();
  }
}
function isRecord(x: unknown): x is Record<string, unknown> {
  return x !== null && typeof x === 'object' && !Array.isArray(x) &&
    (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
}
function stableJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']';
  if (isRecord(value)) return '{' + Object.keys(value).sort().map(key =>
    JSON.stringify(key) + ':' + stableJson(value[key])).join(',') + '}';
  throw new TypeError('Approval request contains unsupported JSON data');
}
/** Hash is bound to capability + canonical input + optional idempotency key. */
export function approvalRequestDigest(request: CapabilityRequest): string {
  if (typeof request.capability !== 'string' || !request.capability.trim() || !isRecord(request.input)) {
    throw new TypeError('Invalid approval request');
  }
  const canonical = stableJson({
    capability: request.capability,
    input: request.input,
    idempotencyKey: request.idempotencyKey ?? null,
  });
  return createHash('sha256').update(canonical).digest('hex');
}
export class PostgresConnectionStore implements ConnectionStore {
  constructor(private readonly pool: TenantPool) {}
  async getById(id: string, tenantId: string): Promise<ConnectionRecord | null> {
    return inTenantTransaction(this.pool, tenantId, async client => {
      const result = await client.query(
        `SELECT id,tenant_id,connector_id,enabled,capabilities
           FROM universal_connect.connections
           WHERE id = $1 AND tenant_id = $2 LIMIT 1`, [id, tenantId]);
      const row = result.rows[0];
      if (!row || !Array.isArray(row.capabilities) || row.capabilities.some((x: unknown) => typeof x !== 'string')) return null;
      return {
        id: row.id, tenantId: row.tenant_id, connectorId: row.connector_id,
        enabled: row.enabled, capabilities: row.capabilities,
      };
    });
  }
}
export class PostgresApprovalStore implements ApprovalStore {
  constructor(private readonly pool: TenantPool) {}
  async verifyAndConsume(input: Parameters<ApprovalStore['verifyAndConsume']>[0]): Promise<boolean> {
    const {principal,connection,request,approvalId} = input;
    const digest = approvalRequestDigest(request);
    return inTenantTransaction(this.pool, principal.tenantId, async client => {
      const result = await client.query(
        `UPDATE universal_connect.approvals
           SET consumed_at = NOW()
           WHERE id = $1 AND tenant_id = $2 AND actor_id = $3
             AND connection_id = $4 AND capability = $5
             AND request_digest = $6 AND consumed_at IS NULL AND expires_at > NOW()
           RETURNING id`,
        [approvalId, principal.tenantId, principal.subject, connection.id, request.capability, digest]);
      return result.rowCount === 1;
    });
  }
}
export class PostgresAuditSink implements AuditSink {
  constructor(private readonly pool: TenantPool) {}
  async record(event: Parameters<AuditSink['record']>[0]): Promise<void> {
    await inTenantTransaction(this.pool, event.tenantId, async client => {
      await client.query(
        `INSERT INTO universal_connect.audit_events
          (tenant_id,actor_id,connection_id,connector_id,capability,event,reason)
          VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [event.tenantId,event.actorId,event.connectionId,event.connectorId,event.capability,event.event,event.reason??null]);
    });
  }
}
export function createPostgresPool(connectionString: string): pg.Pool {
  if (!connectionString || !connectionString.trim()) throw new Error('Database URL required');
  return new pg.Pool({ connectionString, max: 10, connectionTimeoutMillis: 5000 });
}

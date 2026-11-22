import type {TenantPool} from '../../persistence/src/index.ts';

/** Customer-facing tables required by the composed service.
 * Privileged management tables are deliberately not accessible by uc_runtime. */
export const runtimeTables=[
  'connections','approvals','audit_events','credentials','provider_rate_limits',
  'oauth_pending','oauth_connection_events','connection_owners','connection_health'
] as const;

export class RuntimePreflightError extends Error {
  constructor(){super('Runtime database role, schema or tenant isolation is not ready');
    this.name='RuntimePreflightError'}
}
/** Fail closed if migrations or tenant RLS are missing, or an administrative DB login is used.
 * Called before binding the service and by /health/ready. No mutations or credentials in logs. */
export async function assertRuntimeDatabaseReady(pool:Pick<TenantPool,'connect'>):Promise<void>{
  const client=await pool.connect();
  try{
    const identity=await client.query(`
      SELECT rolname,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication,rolcanlogin
      FROM pg_catalog.pg_roles WHERE rolname=current_user`);
    const role=identity.rows[0];
    if(identity.rowCount!==1||role.rolname!=='uc_runtime'||role.rolsuper||
      role.rolbypassrls||role.rolcreatedb||role.rolcreaterole||
      role.rolreplication||!role.rolcanlogin)throw new RuntimePreflightError();
    const result=await client.query(`
      SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,
        c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AS owned,
        has_table_privilege(current_user,c.oid,'SELECT') AS can_select
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='universal_connect' AND c.relkind='r'
        AND c.relname=ANY($1::text[])`,[runtimeTables]);
    if(result.rows.length!==runtimeTables.length||
      new Set(result.rows.map(r=>r.relname)).size!==runtimeTables.length||
      result.rows.some(r=>!r.relrowsecurity||!r.relforcerowsecurity||
        r.owned||!r.can_select))throw new RuntimePreflightError();
    // Verify the exact migrations' customer-facing objects, not only PostgreSQL reachability.
    const columns=await client.query(`
      SELECT table_name,column_name FROM information_schema.columns
      WHERE table_schema='universal_connect'
        AND ((table_name='connection_health' AND column_name IN ('checked_at','state'))
          OR (table_name='connection_owners' AND column_name='actor_id')
          OR (table_name='oauth_pending' AND column_name='consumed_at'))`);
    const actual=new Set(columns.rows.map(r=>r.table_name+'.'+r.column_name));
    for(const expected of ['connection_health.checked_at','connection_health.state',
      'connection_owners.actor_id','oauth_pending.consumed_at'])
      if(!actual.has(expected))throw new RuntimePreflightError();
  }catch{
    throw new RuntimePreflightError();
  }finally{client.release()}
}

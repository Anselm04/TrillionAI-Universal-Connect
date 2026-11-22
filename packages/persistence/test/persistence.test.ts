import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { approvalRequestDigest, inTenantTransaction, PostgresApprovalStore, PostgresAuditSink, PostgresConnectionStore } from '../src/index.ts';

test('canonical request digest does not depend on object key order', () => {
  const a = approvalRequestDigest({capability:'records.write',input:{z:1,nested:{b:2,a:3}}});
  const b = approvalRequestDigest({capability:'records.write',input:{nested:{a:3,b:2},z:1}});
  assert.equal(a,b);
  assert.notEqual(a, approvalRequestDigest({capability:'records.write',input:{z:2,nested:{a:3,b:2}}}));
});
test('non-JSON approval input fails closed', () => {
  assert.throws(() => approvalRequestDigest({capability:'records.write',input:{fn:()=>true}}));
});
test('transaction scopes tenant, commits and releases', async () => {
  const queries:string[]=[];
  let released=false;
  const pool={connect:async()=>({
    query:async(sql:string,values?:readonly unknown[])=>{queries.push(sql);assert.ok(!sql.includes("tenant-1"));if (sql.includes('set_config')) assert.deepEqual(values,['tenant-1']);return {rows:[],rowCount:0}},
    release:()=>{released=true}
  })};
  await inTenantTransaction(pool,'tenant-1',async client=>{await client.query('SELECT 1')});
  assert.deepEqual(queries,['BEGIN',"SELECT set_config('app.tenant_id', $1, true)",'SELECT 1','COMMIT']);
  assert.equal(released,true);
});
test('tenant transaction rolls back on failure',async()=>{
  const queries:string[]=[];let released=false;
  const pool={connect:async()=>({query:async(sql:string)=>{queries.push(sql);return {rows:[],rowCount:0}},release:()=>{released=true}})};
  await assert.rejects(inTenantTransaction(pool,'tenant-1',async()=>{throw new Error('failure')}));
  assert.equal(queries.at(-1),'ROLLBACK');assert.equal(released,true);
});

const url=process.env.TEST_RUNTIME_DATABASE_URL;
const adminUrl=process.env.TEST_ADMIN_DATABASE_URL;
if (url && adminUrl) {
  test('real PostgreSQL: tenant RLS, approval consumption, audit append', async()=>{
    const runtime=new pg.Pool({connectionString:url});
    const admin=new pg.Pool({connectionString:adminUrl});
    try {
      await admin.query("DELETE FROM universal_connect.audit_events WHERE tenant_id LIKE 'test-%'");
      await admin.query("DELETE FROM universal_connect.approvals WHERE tenant_id LIKE 'test-%'");
      await admin.query("DELETE FROM universal_connect.connections WHERE tenant_id LIKE 'test-%'");
      await admin.query(`INSERT INTO universal_connect.connections(id,tenant_id,connector_id,enabled,capabilities)
       VALUES ('test-conn-a','test-tenant-a','crm.example',true,'["records.read","records.write"]'::jsonb),
              ('test-conn-b','test-tenant-b','crm.example',true,'["records.read"]'::jsonb)`);
      const store=new PostgresConnectionStore(runtime);
      assert.equal((await store.getById('test-conn-a','test-tenant-a'))?.id,'test-conn-a');
      assert.equal(await store.getById('test-conn-b','test-tenant-a'),null);
      assert.equal(await store.getById('test-conn-a','test-tenant-b'),null);
      const unscoped=await runtime.query('SELECT * FROM universal_connect.connections');
      assert.equal(unscoped.rows.length,0,'RLS denies queries without a tenant scope');
      const request={capability:'records.write' as const,input:{id:'x',value:1}};
      const digest=approvalRequestDigest(request);
      await admin.query(`INSERT INTO universal_connect.approvals
        (id,tenant_id,actor_id,connection_id,capability,request_digest,expires_at)
        VALUES('test-approval-1','test-tenant-a','test-actor','test-conn-a','records.write',$1,now()+interval '10 minutes')`,[digest]);
      const approvals=new PostgresApprovalStore(runtime);
      const context={principal:{tenantId:'test-tenant-a',subject:'test-actor',assuranceLevel:2},
        connection:{id:'test-conn-a',tenantId:'test-tenant-a',connectorId:'crm.example',enabled:true,capabilities:['records.write']},
        request,approvalId:'test-approval-1'};
      assert.equal(await approvals.verifyAndConsume({...context,request:{...request,input:{id:'other',value:1}}}),false);
      assert.equal(await approvals.verifyAndConsume({...context,principal:{...context.principal,tenantId:'test-tenant-b'}}),false);
      assert.equal(await approvals.verifyAndConsume(context),true);
      assert.equal(await approvals.verifyAndConsume(context),false,'approval can be consumed once only');
      const audit=new PostgresAuditSink(runtime);
      await audit.record({tenantId:'test-tenant-a',actorId:'test-actor',connectionId:'test-conn-a',connectorId:'crm.example',capability:'records.read',event:'connector.executed'});
      assert.equal((await admin.query("SELECT count(*)::int AS n FROM universal_connect.audit_events WHERE tenant_id='test-tenant-a'")).rows[0].n,1);
      await assert.rejects(runtime.query("DELETE FROM universal_connect.audit_events WHERE tenant_id='test-tenant-a'"));
    } finally {
      await admin.query("DELETE FROM universal_connect.audit_events WHERE tenant_id LIKE 'test-%'");
      await admin.query("DELETE FROM universal_connect.approvals WHERE tenant_id LIKE 'test-%'");
      await admin.query("DELETE FROM universal_connect.connections WHERE tenant_id LIKE 'test-%'");
      await runtime.end();
      await admin.end();
    }
  });
}

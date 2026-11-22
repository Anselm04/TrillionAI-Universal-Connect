import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {AuthorizedWorkflowExecutor,PostgresDelegationStore,AuditedWorkflowRecovery,WorkerAuthorizationError} from '../src/index.ts';
import {PostgresWorkflowEngine} from '../../workflow/src/index.ts';
const tenant='test-worker-tenant',actor='test-worker-actor';
const principal={tenantId:tenant,subject:actor,assuranceLevel:1};
const request={capability:'records.read',input:{id:123}};
const step={kind:'read' as const,connectionId:'test-connection',request};
const write={kind:'write' as const,connectionId:'test-connection',
  request:{capability:'records.write',input:{id:123},idempotencyKey:'write-98765'},approvalId:'approved-1'};
test('worker rejects missing delegation and never calls gateway',async()=>{
  let calls=0;
  const w=new AuthorizedWorkflowExecutor(
    {lookup:async()=>({id:actor,tenantId:tenant,emailVerified:true,activeMembership:true,role:'customer'})},
    {valid:async()=>false},
    {execute:async()=>{calls++;return {data:{}}}}
  );
  await assert.rejects(w.execute(tenant,actor,{connectionId:step.connectionId,request},'run-1'),WorkerAuthorizationError);
  assert.equal(calls,0);
});
test('worker checks current actor and only permits scoped delegated execution',async()=>{
  let calls=0;
  const gateway={execute:async(p:unknown,i:unknown)=>{
    calls++;assert.deepEqual(p,{tenantId:tenant,subject:actor,assuranceLevel:1});
    assert.deepEqual(i,{connectionId:'test-connection',request});return {data:{ok:true}};
  }};
  const actorRecord={id:actor,tenantId:tenant,emailVerified:true,activeMembership:true,role:'staff' as const};
  const w=new AuthorizedWorkflowExecutor({lookup:async()=>actorRecord},{valid:async()=>true},gateway);
  await assert.rejects(w.execute(tenant,actor,{connectionId:step.connectionId,request}),WorkerAuthorizationError);
  assert.deepEqual(await w.execute(tenant,actor,{connectionId:step.connectionId,request},'run-1'),{data:{ok:true}});
  assert.equal(calls,1);
  const revoked=new AuthorizedWorkflowExecutor({lookup:async()=>({...actorRecord,activeMembership:false})},{valid:async()=>true},gateway);
  await assert.rejects(revoked.execute(tenant,actor,{connectionId:step.connectionId,request},'run-1'),WorkerAuthorizationError);
  assert.equal(calls,1);
});
if(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_RUNTIME_DATABASE_URL){
  test('real PostgreSQL: delegations expire, revoke, remain tenant scoped',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const engine=new PostgresWorkflowEngine(runtime);
    try{
      const runId=await engine.enqueue(principal,{idempotencyKey:'delegation-1234',steps:[step]});
      const store=new PostgresDelegationStore(runtime);
      assert.equal(await store.valid(runId,tenant,actor),false);
      await admin.query(`INSERT INTO universal_connect.workflow_delegations(tenant_id,run_id,actor_id,expires_at)
        VALUES($1,$2,$3,now()+interval '10 minutes')`,[tenant,runId,actor]);
      assert.equal(await store.valid(runId,tenant,actor),true);
      assert.equal(await store.valid(runId,'test-worker-other',actor),false);
      assert.equal(await store.valid(runId,tenant,'someone-else'),false);
      await admin.query(`UPDATE universal_connect.workflow_delegations SET revoked_at=now() WHERE run_id=$1`,[runId]);
      assert.equal(await store.valid(runId,tenant,actor),false);
    }finally{
      await admin.query("DELETE FROM universal_connect.workflow_delegations WHERE tenant_id LIKE 'test-worker-%'");
      await admin.query("DELETE FROM universal_connect.workflow_runs WHERE tenant_id LIKE 'test-worker-%'");
      await runtime.end();await admin.end();
    }
  });
  test('real PostgreSQL: uncertain write reconciles once with durable evidence; never replays',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const engine=new PostgresWorkflowEngine(runtime);
    let checks=0;
    const recovery=new AuditedWorkflowRecovery(runtime,{authorize:async(t,reviewer)=>{
      checks++;return t===tenant&&reviewer==='approved-reviewer'
    }});
    try{
      const id=await engine.enqueue(principal,{idempotencyKey:'reconcile-12345',steps:[write,step]});
      const claimed=await engine.claim(tenant);
      assert.equal(claimed?.runId,id);
      await engine.fail(claimed!);
      assert.deepEqual(await engine.status(tenant,id),{status:'uncertain',currentStep:0});
      const params={tenantId:tenant,runId:id,stepIndex:0,reviewerId:'approved-reviewer',
        outcome:'confirmed_completed' as const,evidenceReference:'provider-request-12345'};
      await assert.rejects(recovery.reconcile({...params,reviewerId:'unapproved'}),WorkerAuthorizationError);
      assert.equal(await recovery.reconcile(params),true);
      assert.equal(await recovery.reconcile(params),false);
      assert.deepEqual(await engine.status(tenant,id),{status:'pending',currentStep:1});
      const second=await engine.claim(tenant);
      assert.equal(second?.index,1);
      await engine.complete(second!,{success:true});
      assert.deepEqual(await engine.status(tenant,id),{status:'completed',currentStep:2});
      const audit=await admin.query(`SELECT decision,reviewer_id,evidence_reference FROM universal_connect.workflow_reconciliations WHERE run_id=$1`,[id]);
      assert.equal(audit.rows.length,1);assert.equal(audit.rows[0].decision,'confirmed_completed');
      assert.equal(checks,3);
      const unscoped=await runtime.query('SELECT * FROM universal_connect.workflow_reconciliations');
      assert.equal(unscoped.rowCount,0);
      await assert.rejects(runtime.query(`DELETE FROM universal_connect.workflow_reconciliations WHERE run_id=$1`,[id]));
      const negativeId=await engine.enqueue(principal,{idempotencyKey:'reconcile-negative-1',steps:[write]});
      const negativeClaim=await engine.claim(tenant);await engine.fail(negativeClaim!);
      assert.equal(await recovery.reconcile({...params,runId:negativeId,
        outcome:'confirmed_not_executed',evidenceReference:'provider-evidence-verified'}),true);
      assert.deepEqual(await engine.status(tenant,negativeId),{status:'failed',currentStep:0});
      assert.equal(await engine.claim(tenant),null);
    }finally{
      await admin.query("DELETE FROM universal_connect.workflow_reconciliations WHERE tenant_id LIKE 'test-worker-%'");
      await admin.query("DELETE FROM universal_connect.workflow_delegations WHERE tenant_id LIKE 'test-worker-%'");
      await admin.query("DELETE FROM universal_connect.workflow_runs WHERE tenant_id LIKE 'test-worker-%'");
      await runtime.end();await admin.end();
    }
  });
}

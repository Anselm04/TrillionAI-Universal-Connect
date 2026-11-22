import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {PostgresWorkflowEngine,WorkflowError,runOne} from '../src/index.ts';

const tenant='test-workflow-tenant';
const otherTenant='test-workflow-other';
const actor='test-workflow-actor';
const first={kind:'read' as const,connectionId:'test-connection',
  request:{capability:'records.read',input:{id:1}}};
const write={kind:'write' as const,connectionId:'test-connection',
  request:{capability:'records.write',input:{id:1},idempotencyKey:'write-12345'},approvalId:'approval-123'};

if(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_RUNTIME_DATABASE_URL){
  test('real PostgreSQL: idempotency, tenant isolation, ordered steps and fenced completion',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL,max:8});
    const engine=new PostgresWorkflowEngine(runtime);
    try{
      const def={idempotencyKey:'workflow-123456',steps:[first,first]};
      const id=await engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:2},def);
      assert.equal(id,await engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:2},def));
      await assert.rejects(
        engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:2},
          {idempotencyKey:'workflow-123456',steps:[write]}),
        (e:unknown)=>e instanceof WorkflowError&&e.code==='CONFLICT');
      assert.equal(await engine.status(otherTenant,id),null);
      assert.equal(await engine.claim(otherTenant),null);
      const [a,b]=await Promise.all([engine.claim(tenant),engine.claim(tenant)]);
      const claimed=[a,b].filter(x=>x!==null);
      assert.equal(claimed.length,1,'only one worker claims the same step');
      const one=claimed[0]!;
      assert.equal(one.index,0);
      assert.equal(await engine.complete({...one,leaseToken:'00000000-0000-4000-8000-000000000000'},{ok:false}),false);
      assert.equal(await engine.complete(one,{ok:true}),true);
      assert.equal(await engine.complete(one,{ok:true}),false,'cannot finish twice');
      const two=await engine.claim(tenant);
      assert.equal(two?.index,1);
      assert.equal(await engine.complete(two!,{ok:true}),true);
      assert.deepEqual(await engine.status(tenant,id),{status:'completed',currentStep:2});
      assert.equal(await engine.claim(tenant),null);
      const count=await admin.query('SELECT count(*)::int AS n FROM universal_connect.workflow_steps WHERE run_id=$1',[id]);
      assert.equal(count.rows[0].n,2);
      const unscoped=await runtime.query('SELECT * FROM universal_connect.workflow_runs');
      assert.equal(unscoped.rows.length,0);
    }finally{
      await admin.query("DELETE FROM universal_connect.workflow_runs WHERE tenant_id LIKE 'test-workflow-%'");
      await runtime.end();await admin.end();
    }
  });
  test('real PostgreSQL: expired read retries, expired write becomes uncertain',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const engine=new PostgresWorkflowEngine(runtime);
    try{
      const readId=await engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:1},
        {idempotencyKey:'expired-read-123',steps:[first]});
      const readClaim=await engine.claim(tenant);
      assert.equal(readClaim?.runId,readId);
      await admin.query(`UPDATE universal_connect.workflow_steps
         SET leased_until=now()-interval '1 minute' WHERE run_id=$1`,[readId]);
      const retried=await engine.claim(tenant);
      assert.equal(retried?.runId,readId);
      assert.notEqual(retried?.leaseToken,readClaim?.leaseToken);
      assert.equal(await engine.complete(readClaim!,{ok:true}),false,'expired worker cannot commit');
      await engine.complete(retried!,{ok:true});
      const writeId=await engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:2},
        {idempotencyKey:'expired-write-123',steps:[write]});
      const writeClaim=await engine.claim(tenant);
      assert.equal(writeClaim?.runId,writeId);
      await admin.query(`UPDATE universal_connect.workflow_steps
        SET leased_until=now()-interval '1 minute' WHERE run_id=$1`,[writeId]);
      assert.equal(await engine.claim(tenant),null,'write must not replay');
      assert.deepEqual(await engine.status(tenant,writeId),{status:'uncertain',currentStep:0});
    }finally{
      await admin.query("DELETE FROM universal_connect.workflow_runs WHERE tenant_id LIKE 'test-workflow-%'");
      await runtime.end();await admin.end();
    }
  });
  test('real PostgreSQL: execution worker persists completion and never reruns the same work',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const engine=new PostgresWorkflowEngine(runtime);
    let calls=0;
    try{
      await engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:1},
        {idempotencyKey:'worker-read-123',steps:[first]});
      const executor={execute:async(t:string,a:string,input:unknown)=>{
        assert.equal(t,tenant);assert.equal(a,actor);assert.ok(input);calls++;return {data:{ok:true}}}};
      assert.equal(await runOne(engine,executor,tenant),true);
      assert.equal(await runOne(engine,executor,tenant),false);
      assert.equal(calls,1);
    }finally{
      await admin.query("DELETE FROM universal_connect.workflow_runs WHERE tenant_id LIKE 'test-workflow-%'");
      await runtime.end();await admin.end();
    }
  });
}
test('workflow validation blocks missing write approval and invalid input',async()=>{
  const engine=new PostgresWorkflowEngine({connect:async()=>{throw Error('must not open database')}});
  await assert.rejects(engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:2},
    {idempotencyKey:'bad-write-123',steps:[{...write,approvalId:undefined}]}),
    (e:unknown)=>e instanceof WorkflowError&&e.code==='INVALID');
  await assert.rejects(engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:2},
    {idempotencyKey:'bad-read-123',steps:[{...first,request:{capability:'records.write',input:{}}}]}),
    (e:unknown)=>e instanceof WorkflowError&&e.code==='INVALID');
});

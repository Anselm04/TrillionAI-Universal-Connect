import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import express from 'express';
import {once} from 'node:events';
import {createManagementRouter,requireFreshTotp,ManagedDelegations,ManagementDenied} from '../src/index.ts';
import {PostgresWorkflowEngine} from '../../workflow/src/index.ts';
import type {VerifiedIdentity} from '../../identity/src/index.ts';

const tenant='11111111-1111-4111-8111-111111111111';
const actor='22222222-2222-4222-8222-222222222222';
const token=(method='totp',timestamp=Math.floor(Date.now()/1000))=>'header.'+
  Buffer.from(JSON.stringify({sub:actor,aal:'aal2',amr:[{method,timestamp}]})).toString('base64url')+'.signature';
const verified:VerifiedIdentity={principal:{tenantId:tenant,subject:actor,assuranceLevel:2},organisationRole:'owner'};
test('fresh verified TOTP is required for privileged workflow management',()=>{
  requireFreshTotp(verified,token());
  assert.throws(()=>requireFreshTotp(verified,token('password')),ManagementDenied);
  assert.throws(()=>requireFreshTotp(verified,token('totp',Math.floor(Date.now()/1000)-901)),ManagementDenied);
  assert.throws(()=>requireFreshTotp({...verified,organisationRole:'staff'},token()),ManagementDenied);
  assert.throws(()=>requireFreshTotp({...verified,principal:{...verified.principal,assuranceLevel:1}},token()),ManagementDenied);
  assert.throws(()=>requireFreshTotp(verified,token('totp',Math.floor(Date.now()/1000)+20)),ManagementDenied);
});
if(process.env.TEST_ADMIN_DATABASE_URL && process.env.TEST_RUNTIME_DATABASE_URL){
  test('real PostgreSQL: authenticated management issues/revokes delegations, reconciles only verified provider evidence',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const managerUrl=process.env.TEST_ADMIN_DATABASE_URL.replace('postgres:ci-only-admin@','uc_manager:ci-only-manager@');
    const manager=new pg.Pool({connectionString:managerUrl});
    const engine=new PostgresWorkflowEngine(runtime);
    const connId='test-management-conn';
    const write={kind:'write' as const,connectionId:connId,
      request:{capability:'records.write',input:{value:1},idempotencyKey:'approved-write-1'},
      approvalId:'approved-1'};
    let server:ReturnType<ReturnType<typeof express>['listen']>|null=null;
    try{
      const runId=await engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:2},
        {idempotencyKey:'management-test-1',steps:[write]});
      const otherRunId=await engine.enqueue({tenantId:tenant,subject:actor,assuranceLevel:2},
        {idempotencyKey:'management-test-2',steps:[write]});
      const app=express();
      let evidenceCalls=0;
      app.use('/internal',createManagementRouter({
        identity:{authenticate:async(raw,organisation)=>{
          if(raw!==tokenValue||organisation!==tenant)throw new ManagementDenied();
          return verified;
        }},
        pool:manager,
        evidence:{verify:async(x)=>{
          evidenceCalls++;
          return x.evidenceReference==='provider-confirmation-123' &&
            x.runId===runId && x.tenantId===tenant && x.outcome==='confirmed_completed';
        }}
      }));
      const tokenValue=token();
      server=app.listen(0,'127.0.0.1');
      await once(server,'listening');
      const addr=server.address();
      if(!addr||typeof addr==='string')throw Error('server port unavailable');
      const base='http://127.0.0.1:'+addr.port+'/internal';
      async function call(path:string,method:string,payload?:unknown,auth=true){
        const r=await fetch(base+path,{method,headers:{
          ...(auth?{authorization:'Bearer '+tokenValue,'x-organisation-id':tenant}:{}),
          ...(payload?{'content-type':'application/json'}:{})
        },...(payload?{body:JSON.stringify(payload)}:{})});
        return {status:r.status,body:await r.json()};
      }
      const delegation='/delegations/'+runId;
      assert.equal((await call(delegation,'POST',{expiresMinutes:5},false)).status,403);
      assert.equal((await call('/delegations/invalid','POST',{expiresMinutes:5})).status,403);
      assert.equal((await call(delegation,'POST',{expiresMinutes:5})).status,201);
      assert.equal((await call(delegation,'POST',{expiresMinutes:5})).status,409,'duplicate requires explicit revoke');
      const active=await manager.query('SELECT count(*)::int AS count FROM universal_connect.workflow_delegations');
      assert.equal(active.rows.length,0,'RLS denies manager without tenant context');
      const storeCheck=await admin.query('SELECT revoked_at FROM universal_connect.workflow_delegations WHERE run_id=$1',[runId]);
      assert.equal(storeCheck.rows.length,1);assert.equal(storeCheck.rows[0].revoked_at,null);
      assert.equal((await call(delegation,'DELETE')).status,200);
      assert.equal((await call(delegation,'DELETE')).status,404);
      const audits=await admin.query('SELECT action FROM universal_connect.workflow_management_audit WHERE run_id=$1 ORDER BY created_at',[runId]);
      assert.deepEqual(audits.rows.map(x=>x.action),['delegation.issued','delegation.revoked']);
      const claim=await engine.claim(tenant);
      assert.equal(claim?.runId,runId);
      await engine.fail(claim!);
      assert.equal((await call('/recover/'+runId+'/0','POST',{outcome:'confirmed_completed',evidenceReference:'unknown-ref-123'})).status,403);
      assert.equal((await call('/recover/'+runId+'/0','POST',{outcome:'confirmed_completed',evidenceReference:'provider-confirmation-123'})).status,200);
      assert.equal((await call('/recover/'+runId+'/0','POST',{outcome:'confirmed_completed',evidenceReference:'provider-confirmation-123'})).status,409);
      assert.equal(evidenceCalls,3);
      assert.deepEqual(await engine.status(tenant,runId),{status:'completed',currentStep:1});
      const reconciled=await admin.query('SELECT reviewer_id FROM universal_connect.workflow_reconciliations WHERE run_id=$1',[runId]);
      assert.equal(reconciled.rows.length,1);assert.equal(reconciled.rows[0].reviewer_id,actor);
      assert.equal((await call('/delegations/'+otherRunId,'POST',{expiresMinutes:120})).status,403);
      await assert.rejects(manager.query('DELETE FROM universal_connect.workflow_management_audit'));
    }finally{
      if(server)await new Promise<void>((resolve,reject)=>server!.close(e=>e?reject(e):resolve()));
      await admin.query('DELETE FROM universal_connect.workflow_reconciliations WHERE tenant_id=$1',[tenant]);
      await admin.query('DELETE FROM universal_connect.workflow_management_audit WHERE tenant_id=$1',[tenant]);
      await admin.query('DELETE FROM universal_connect.workflow_delegations WHERE tenant_id=$1',[tenant]);
      await admin.query('DELETE FROM universal_connect.workflow_runs WHERE tenant_id=$1',[tenant]);
      await runtime.end();await manager.end();await admin.end();
    }
  });
}

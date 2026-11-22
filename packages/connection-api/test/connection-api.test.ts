import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {once} from 'node:events';
import pg from 'pg';
import {createOAuthConnectionRouter} from '../src/index.ts';
import type {OAuthRouteOptions} from '../src/index.ts';

const tenant='11111111-1111-4111-8111-111111111111';
const other='33333333-3333-4333-8333-333333333333';
const actor='22222222-2222-4222-8222-222222222222';
const verified={principal:{tenantId:tenant,subject:actor,assuranceLevel:1},organisationRole:'customer' as const};
const browserOrigin='https://app.example.com';
const fakeBearer='token-that-was-verified-by-identity';
const conn='connection-customer';
const basePath='/connections/'+conn;
const authHeaders={'authorization':'Bearer '+fakeBearer,'x-organisation-id':tenant,origin:browserOrigin,'content-type':'application/json'};
if(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_RUNTIME_DATABASE_URL){
  test('OAuth HTTP API enforces identity, consent, origin, policy, quotas, and tenant audit',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const seen:{method:string;actor:string;state?:string;code?:string}[]=[];
    let identityChecks=0,policyChecks=0,limitChecks=0;
    const options:OAuthRouteOptions={
      identity:{authenticate:async(token,tenantId)=>{
        identityChecks++;
        if(token!==fakeBearer||tenantId!==tenant)throw Error('invalid identity');
        return verified;
      }},
      oauth:{
        begin:async(principal,scope,providerId)=>{
          seen.push({method:'begin',actor:principal.subject});
          assert.equal(scope.tenantId,tenant);assert.equal(providerId,'github.oauth');
          return {state:'state-not-returned',url:'https://github.com/login/oauth/authorize?state=fake'};
        },
        complete:async(principal,scope,providerId,state,code)=>{
          seen.push({method:'complete',actor:principal.subject,state,code});
          assert.equal(scope.connectionId,conn);assert.equal(providerId,'github.oauth');
        },
        disconnect:async(principal,scope,providerId)=>{
          seen.push({method:'disconnect',actor:principal.subject});
          return true;
        }
      },
      pool:runtime,
      policy:{authorize:async(identity,connectionId,provider,operation,approval)=>{
        policyChecks++;
        assert.equal(identity.principal.subject,actor);
        return connectionId===conn&&provider==='github.oauth'&&
          (approval!=='repositories')&&['connect','complete','disconnect'].includes(operation);
      }},
      limiter:{acquire:async(t,p)=>{limitChecks++;return t===tenant&&p==='github.oauth.oauth'}},
      allowedOrigin:browserOrigin,providerId:'github.oauth',supportsRepositoryAccess:false
    };
    const app=express();
    app.use('/connections',createOAuthConnectionRouter(options));
    const server=app.listen(0,'127.0.0.1');
    await once(server,'listening');
    const address=server.address();
    if(!address||typeof address==='string')throw Error('bad port');
    const base='http://127.0.0.1:'+address.port;
    async function send(method:string,path:string,body?:unknown,headers:Record<string,string>=authHeaders){
      const response=await fetch(base+path,{
        method,headers,...(body?{body:JSON.stringify(body)}:{})
      });
      return {status:response.status,headers:response.headers,body:await response.json()};
    }
    try{
      assert.equal((await send('POST',basePath+'/start',{consent:true,requestedAccess:'profile'},
        {...authHeaders,origin:'https://evil.example.com'})).status,403);
      assert.equal((await send('POST',basePath+'/start',{consent:false,requestedAccess:'profile'})).status,403);
      assert.equal((await send('POST',basePath+'/start',{consent:true,requestedAccess:'repositories'})).status,403);
      assert.equal((await send('POST',basePath+'/start',{consent:true,requestedAccess:'profile'},
        {...authHeaders,'x-organisation-id':other})).status,403);
      assert.equal((await send('POST',basePath+'/start',{consent:true,requestedAccess:'profile'})).status,200);
      assert.equal(seen.length,1);
      assert.equal((await send('POST',basePath+'/complete',{state:'short',code:'x'})).status,403);
      const completed=await send('POST',basePath+'/complete',{state:'s'.repeat(43),code:'provider-code'});
      assert.equal(completed.status,200);
      assert.equal(completed.body.connected,true);
      assert.equal((await send('DELETE',basePath)).status,200);
      assert.equal(seen.length,3);
      assert.equal(seen[1].state,'s'.repeat(43));
      const audit=await admin.query(
        `SELECT action,tenant_id,actor_id FROM universal_connect.oauth_connection_events
          WHERE tenant_id=$1 ORDER BY created_at,id`,[tenant]);
      assert.deepEqual(audit.rows.map(x=>x.action).sort(),['oauth.connected','oauth.disconnected','oauth.started']);
      assert.ok(audit.rows.every(x=>x.actor_id===actor&&x.tenant_id===tenant));
      const unscoped=await runtime.query('SELECT * FROM universal_connect.oauth_connection_events');
      assert.equal(unscoped.rows.length,0);
      await assert.rejects(runtime.query('DELETE FROM universal_connect.oauth_connection_events'));
      assert.ok(identityChecks>=3);assert.equal(limitChecks,3);assert.equal(policyChecks,3);
      const response=await send('POST',basePath+'/start',{consent:true,requestedAccess:'profile'});
      assert.equal(response.headers.get('cache-control'),'no-store');
      assert.equal(response.headers.get('referrer-policy'),'no-referrer');
    }finally{
      await new Promise<void>((resolve,reject)=>server.close(err=>err?reject(err):resolve()));
      await admin.query('DELETE FROM universal_connect.oauth_connection_events WHERE tenant_id=$1',[tenant]);
      await runtime.end();await admin.end();
    }
  });
}
test('router refuses an insecure browser origin',()=>{
  assert.throws(()=>createOAuthConnectionRouter({
    identity:{authenticate:async()=>verified},oauth:{} as never,pool:{} as never,
    policy:{authorize:async()=>true},limiter:{acquire:async()=>true},
    allowedOrigin:'http://app.example.com',providerId:'github.oauth',supportsRepositoryAccess:false
  }));
});

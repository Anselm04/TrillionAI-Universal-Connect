import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {once} from 'node:events';
import pg from 'pg';
import {createSelfServiceConnectionRouter,ownerConnectionPolicy,PostgresSelfServiceConnections} from '../src/index.ts';
import type {VerifiedIdentity} from '../../identity/src/index.ts';
const tenant='11111111-1111-4111-8111-111111111111';
const foreignTenant='33333333-3333-4333-8333-333333333333';
const owner='22222222-2222-4222-8222-222222222222';
const outsider='44444444-4444-4444-8444-444444444444';
const identity=(tenantId=tenant,subject=owner):VerifiedIdentity=>({
  principal:{tenantId,subject,assuranceLevel:1},organisationRole:'customer'
});
if(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_RUNTIME_DATABASE_URL){
  test('real PostgreSQL: customer provisions, lists, and owns only their own connection',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const store=new PostgresSelfServiceConnections(runtime);
    const createdIds:string[]=[];
    try{
      const a=await store.create(identity());createdIds.push(a.id);
      const b=await store.create(identity());createdIds.push(b.id);
      assert.equal(a.status,'awaiting_authorization');
      assert.equal(a.providerId,'github.oauth');
      assert.ok(/^[a-zA-Z0-9_-]{1,128}$/.test(a.id));
      assert.equal((await store.list(identity())).length,2);
      assert.equal((await store.list(identity(tenant,outsider))).length,0);
      assert.equal((await store.list(identity(foreignTenant,owner))).length,0);
      assert.equal(await store.get(identity(tenant,outsider),a.id),null);
      assert.equal(await store.owns(identity(tenant,outsider),a.id),false);
      assert.equal(await store.owns(identity(foreignTenant,owner),a.id),false);
      assert.equal(await store.owns(identity(),a.id),true);
      const policy=ownerConnectionPolicy(store);
      assert.equal(await policy.authorize(identity(),a.id,'github.oauth','connect','profile'),true);
      assert.equal(await policy.authorize(identity(tenant,outsider),a.id,'github.oauth','disconnect',null),false);
      assert.equal(await policy.authorize(identity(),a.id,'untrusted.oauth','connect','profile'),false);
      const unscoped=await runtime.query('SELECT * FROM universal_connect.connection_owners');
      assert.equal(unscoped.rowCount,0);
      await assert.rejects(runtime.query('DELETE FROM universal_connect.connection_owners WHERE connection_id=$1',[a.id]));
      await admin.query(`INSERT INTO universal_connect.credentials
        (id,tenant_id,connection_id,name,key_version,nonce,tag,ciphertext)
        VALUES($1,$2,$3,'oauth_tokens','v1',$4,$5,$6)`,[
          'test-selfservice-credential',tenant,a.id,Buffer.alloc(12),Buffer.alloc(16),Buffer.from('fake-ciphertext')
        ]);
      assert.equal((await store.get(identity(),a.id))?.status,'connected');
    }finally{
      await admin.query('DELETE FROM universal_connect.credentials WHERE tenant_id=$1 AND connection_id=ANY($2)',[tenant,createdIds]);
      await admin.query('DELETE FROM universal_connect.connection_owners WHERE tenant_id=$1 AND connection_id=ANY($2)',[tenant,createdIds]);
      await admin.query('DELETE FROM universal_connect.connections WHERE tenant_id=$1 AND id=ANY($2)',[tenant,createdIds]);
      await runtime.end();await admin.end();
    }
  });
  test('real HTTP: authorized provision/list/status, denied foreign identities and invalid origin',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const ids:string[]=[];
    let checks=0;
    const app=express();
    app.use('/managed-connections',createSelfServiceConnectionRouter({
      pool:runtime,allowedOrigin:'https://connect.example.com',
      identity:{authenticate:async(token,t)=>{
        checks++;
        if(token!=='identity-token'||t!==tenant)throw Error('denied');
        return identity();
      }},
      limiter:{acquire:async()=>true}
    }));
    const server=app.listen(0,'127.0.0.1');
    await once(server,'listening');
    try{
      const addr=server.address();if(!addr||typeof addr==='string')throw Error('invalid port');
      const base='http://127.0.0.1:'+addr.port+'/managed-connections';
      const headers={'authorization':'Bearer identity-token','x-organisation-id':tenant,
        origin:'https://connect.example.com','content-type':'application/json'};
      const send=async(method:string,path='',body?:unknown,provided=headers)=>{
        const res=await fetch(base+path,{method,headers:provided,...(body!==undefined?{body:JSON.stringify(body)}:{})});
        return {status:res.status,json:await res.json()};
      };
      assert.equal((await send('POST','/',{}, {...headers,origin:'https://wrong.example.com'})).status,403);
      assert.equal((await send('POST','/',{connectorId:'attacker-controlled'})).status,403);
      const created=await send('POST','/',{});
      assert.equal(created.status,201);
      const id=created.json.connection.id as string;ids.push(id);
      assert.equal((await send('GET','/')).json.connections.length,1);
      assert.equal((await send('GET','/'+id)).json.connection.status,'awaiting_authorization');
      assert.equal((await send('GET','/not-a-connection')).status,404);
      assert.equal((await send('GET','/',undefined,{...headers,'x-organisation-id':foreignTenant})).status,403);
      assert.ok(checks>=4);
    }finally{
      await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
      await admin.query('DELETE FROM universal_connect.connection_owners WHERE connection_id=ANY($1)',[ids]);
      await admin.query('DELETE FROM universal_connect.connections WHERE id=ANY($1)',[ids]);
      await runtime.end();await admin.end();
    }
  });
}

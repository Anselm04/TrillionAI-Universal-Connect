import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {once} from 'node:events';
import pg from 'pg';
import {createServiceApp,parseServiceConfig,environmentClientSecrets,
  environmentKeyProvider,type ServiceConfig,type ServiceDependencies} from '../src/index.ts';
import {PostgresSelfServiceConnections} from '../../self-service/src/index.ts';
import {inTenantTransaction} from '../../persistence/src/index.ts';
import {assertRuntimeDatabaseReady,RuntimePreflightError} from '../src/preflight.ts';
import {PostgresCredentialVault} from '../../vault/src/index.ts';

const env={
  PORT:'8080',PUBLIC_ORIGIN:'https://connect.example.com',
  DATABASE_URL:'postgresql://uc_runtime:test-password@127.0.0.1:5432/universal_connect_test',
  SUPABASE_URL:'https://example.supabase.co',
  SUPABASE_PUBLISHABLE_KEY:'test-public-key',
  SUPABASE_SERVICE_ROLE_KEY:'test-private-service-role-key',
  GITHUB_CLIENT_ID:'client123456',
  GITHUB_CLIENT_SECRET:'test-backend-client-secret',
  GITHUB_CALLBACK_URL:'https://connect.example.com/oauth/callback',
  VAULT_KEY_BASE64:Buffer.alloc(32,31).toString('base64'),
  VAULT_KEY_VERSION:'v1'
};
test('service validation rejects missing, mismatched, unsafe or plaintext key material',()=>{
  assert.deepEqual(parseServiceConfig(env).githubClientId,'client123456');
  for(const overrides of [
    {GITHUB_CLIENT_SECRET:undefined},
    {PUBLIC_ORIGIN:'http://connect.example.com'},
    {GITHUB_CALLBACK_URL:'https://different.example.com/oauth/callback'},
    {DATABASE_URL:'http://example.com'},
    {SUPABASE_PUBLISHABLE_KEY:env.SUPABASE_SERVICE_ROLE_KEY},
    {VAULT_KEY_BASE64:'not-a-real-key'},
    {PORT:'0'},
    {VAULT_PREVIOUS_KEYS_JSON:'[]'},
    {VAULT_PREVIOUS_KEYS_JSON:JSON.stringify({v1:Buffer.alloc(32,12).toString('base64')})},
    {VAULT_PREVIOUS_KEYS_JSON:JSON.stringify({v0:'not-valid'})},
    {VAULT_PREVIOUS_KEYS_JSON:'{"__proto__":"invalid"}'}
  ]){
    assert.throws(()=>parseServiceConfig({...env,...overrides}));
  }
});
test('environment key provider supports only current key version and secret callback is erased',async()=>{
  const config=parseServiceConfig(env);
  const keys=environmentKeyProvider(config);
  assert.equal((await keys.keyForVersion('v1')).length,32);
  await assert.rejects(keys.keyForVersion('unknown'));
  const secrets=environmentClientSecrets(config);
  let seen:Buffer|undefined;
  await secrets.withClientSecret('github.oauth',async b=>{seen=b;assert.equal(b.toString('utf8'),env.GITHUB_CLIENT_SECRET)});
  assert.ok(seen?.every(b=>b===0));
  await assert.rejects(secrets.withClientSecret('unknown',async()=>true));
});
test('key ring retains historical decryption keys and refuses unknown versions',async()=>{
  const older=Buffer.alloc(32,42).toString('base64');
  const config=parseServiceConfig({...env,VAULT_KEY_VERSION:'v2',
    VAULT_PREVIOUS_KEYS_JSON:JSON.stringify({v1:env.VAULT_KEY_BASE64,v0:older})});
  const keys=environmentKeyProvider(config);
  assert.equal((await keys.keyForVersion('v2')).toString('base64'),env.VAULT_KEY_BASE64);
  assert.equal((await keys.keyForVersion('v1')).toString('base64'),env.VAULT_KEY_BASE64);
  assert.equal((await keys.keyForVersion('v0')).toString('base64'),older);
  await assert.rejects(keys.keyForVersion('v3'));
});
if(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_RUNTIME_DATABASE_URL){
  const tenant='11111111-1111-4111-8111-111111111111';
  const actor='22222222-2222-4222-8222-222222222222';
  const verified={principal:{subject:actor,tenantId:tenant,assuranceLevel:1},organisationRole:'customer' as const};
  test('runtime preflight rejects admin DB roles and detects all required RLS schema',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    try{
      await assertRuntimeDatabaseReady(runtime);
      await assert.rejects(assertRuntimeDatabaseReady(admin),RuntimePreflightError);
      const fake={connect:async()=>({
        query:async()=>({rows:[],rowCount:0}),release:()=>{}
      })};
      await assert.rejects(assertRuntimeDatabaseReady(fake),RuntimePreflightError);
    }finally{await runtime.end();await admin.end()}
  });
  test('PostgreSQL key rotation preserves old ciphertext during staged rollout',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const connection='service-rotation-'+Date.now();
    const scope={tenantId:tenant,connectionId:connection};
    const first=parseServiceConfig(env);
    const second=parseServiceConfig({...env,
      VAULT_KEY_VERSION:'v2',
      VAULT_KEY_BASE64:Buffer.alloc(32,71).toString('base64'),
      VAULT_PREVIOUS_KEYS_JSON:JSON.stringify({v1:env.VAULT_KEY_BASE64})
    });
    try{
      await admin.query(`INSERT INTO universal_connect.connections
        (id,tenant_id,connector_id,enabled,capabilities)
        VALUES ($1,$2,'github.oauth',true,'[]'::jsonb)`,[connection,tenant]);
      const before=new PostgresCredentialVault(runtime,environmentKeyProvider(first));
      await before.put(scope,'oauth_tokens',Buffer.from('fixture-encrypted-token'));
      const after=new PostgresCredentialVault(runtime,environmentKeyProvider(second));
      assert.equal(await after.withCredential(scope,'oauth_tokens',async b=>b.toString()),
        'fixture-encrypted-token');
      assert.equal(await after.rotate(scope,'oauth_tokens'),true);
      const row=await admin.query(`SELECT key_version FROM universal_connect.credentials
        WHERE connection_id=$1`,[connection]);
      assert.equal(row.rows[0].key_version,'v2');
      assert.equal(await after.withCredential(scope,'oauth_tokens',async b=>b.toString()),
        'fixture-encrypted-token');
      await assert.rejects(before.withCredential(scope,'oauth_tokens',async b=>b.toString()));
    }finally{
      await admin.query('DELETE FROM universal_connect.credentials WHERE connection_id=$1',[connection]);
      await admin.query('DELETE FROM universal_connect.connections WHERE id=$1',[connection]);
      await runtime.end();await admin.end();
    }
  });
  test('composed service: profile OAuth routes enforce real owner policy; health and discovery are mounted',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const store=new PostgresSelfServiceConnections(runtime);
    const createdIds:string[]=[];
    let issued=0,completed=0,revoked=0,deleted=0;
    const dependencies={
      pool:runtime,
      identity:{
        authenticate:async(token:string,t:string)=>{
          if(token!=='verified-user-bearer'||t!==tenant)throw Error('invalid authentication');
          return verified;
        },
        organizations:async(token:string)=>{
          if(token!=='verified-user-bearer')throw Error('invalid');
          return [{id:tenant,role:'customer'}];
        }
      },
      limiter:{acquire:async()=>true},
      oauth:{
        begin:async()=>{issued++;return {state:'some-state',url:'https://github.com/login/oauth/authorize?state=test'}},
        complete:async()=>{completed++},
        disconnect:async()=>false
      },
      githubLifecycle:{check:async()=> 'unavailable' as const,revoke:async()=>{revoked++}},
      vault:{revoke:async()=>{deleted++;return true}},
      close:async()=>{await runtime.end()}
    } as unknown as ServiceDependencies;
    const app=createServiceApp(parseServiceConfig(env),dependencies);
    const server=app.listen(0,'127.0.0.1');await once(server,'listening');
    try{
      const address=server.address();
      if(!address||typeof address==='string')throw Error('address unavailable');
      const base='http://127.0.0.1:'+address.port;
      const headers={
        origin:env.PUBLIC_ORIGIN,
        'authorization':'Bearer verified-user-bearer',
        'x-organisation-id':tenant,'content-type':'application/json'
      };
      const request=async(method:string,path:string,body?:unknown,h=headers)=>{
        const result=await fetch(base+path,{method,headers:h,
          ...(body!==undefined?{body:JSON.stringify(body)}:{})});
        return {status:result.status,body:await result.json()};
      };
      assert.equal((await request('GET','/health/live')).status,200);
      assert.equal((await request('GET','/health/ready')).status,200);
      assert.equal((await request('GET','/organizations')).body.organizations[0].id,tenant);
      const created=await request('POST','/managed-connections/',{});
      assert.equal(created.status,201);
      const id=created.body.connection.id as string;createdIds.push(id);
      const denied=await request('POST','/connections/foreign/start',{consent:true,requestedAccess:'profile'});
      assert.equal(denied.status,403);
      assert.equal(issued,0);
      const permitted=await request('POST','/connections/'+id+'/start',{consent:true,requestedAccess:'profile'});
      assert.equal(permitted.status,200);assert.equal(issued,1);
      const noRepo=await request('POST','/connections/'+id+'/start',{consent:true,requestedAccess:'repositories'});
      assert.equal(noRepo.status,403);
      assert.equal(issued,1);
      const verification=await request('POST','/managed-connections/'+id+'/verify',{});
      assert.equal(verification.status,200);
      // No real token was installed, so a simulated upstream result cannot turn missing credentials into connected.
      assert.equal(verification.body.connection.status,'awaiting_authorization');
      const gone=await request('DELETE','/connections/'+id);
      assert.equal(gone.status,200);
      assert.equal(gone.body.providerRevocationConfirmed,true);
      assert.equal(revoked,1);assert.equal(deleted,1);
      assert.equal((await request('GET','/not-a-route')).status,404);
    }finally{
      await new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
      await admin.query('DELETE FROM universal_connect.connection_health WHERE connection_id=ANY($1)',[createdIds]);
      await admin.query('DELETE FROM universal_connect.oauth_connection_events WHERE tenant_id=$1 AND connection_id=ANY($2)',[tenant,createdIds]);
      await admin.query('DELETE FROM universal_connect.connection_owners WHERE connection_id=ANY($1)',[createdIds]);
      await admin.query('DELETE FROM universal_connect.connections WHERE id=ANY($1)',[createdIds]);
      await admin.end();await runtime.end();
    }
  });
}

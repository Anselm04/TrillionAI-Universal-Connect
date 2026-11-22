import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {randomBytes} from 'node:crypto';
import {OAuthConnectionService,OAuthError,type OAuthVault, type OAuthProvider} from '../src/index.ts';
import {PostgresCredentialVault,type VaultKeyProvider} from '../../vault/src/index.ts';
import {type ProviderTransport} from '../../rest-adapter/src/index.ts';
const tenant='test-oauth-tenant',other='test-oauth-other',actor='test-oauth-actor',connection='test-oauth-connection';
const principal={tenantId:tenant,subject:actor,assuranceLevel:1};
const scope={tenantId:tenant,connectionId:connection};
const provider:OAuthProvider={id:'oauth.test',authorizationUrl:'https://auth.example.com/authorize',
  tokenUrl:'https://auth.example.com/token',clientId:'public-client',
  redirectUri:'https://app.example.com/oauth/callback',scopes:['records.read','records.write'],
  revokeUrl:'https://auth.example.com/revoke'};
const key=randomBytes(32);
const keys:VaultKeyProvider={currentVersion:async()=> 'v1',keyForVersion:async()=>key};
const respond=(obj:unknown,status=200)=>new Response(JSON.stringify(obj),{status,headers:{'content-type':'application/json'}});
test('provider configuration denies insecure and local URLs',()=>{
  const transport:ProviderTransport={send:async()=>respond({})};
  const vault={} as OAuthVault;
  const pool={connect:async()=>{throw Error('db access must not occur')}};
  for(const url of ['http://auth.example.com/token','https://127.0.0.1/token','https://localhost/token','https://auth.example.com:8443/token']){
    assert.throws(()=>new OAuthConnectionService(pool,keys,vault,transport,[{...provider,tokenUrl:url}]),OAuthError);
  }
});
if(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_RUNTIME_DATABASE_URL){
  test('real PostgreSQL: PKCE, one-time state, scoped tokens, refresh, revoke',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL,max:10});
    const vault=new PostgresCredentialVault(runtime,keys);
    let exchanges=0,refreshes=0,revocations=0;
    const transport:ProviderTransport={send:async(url,init)=>{
      assert.equal(init.redirect,'error');
      assert.equal(init.method,'POST');
      const params=new URLSearchParams(init.body as string);
      assert.equal(params.get('client_id'),'public-client');
      if(url===provider.tokenUrl){
        if(params.get('grant_type')==='authorization_code'){
          exchanges++;
          assert.equal(params.get('code'),'provider-code-123');
          assert.ok((params.get('code_verifier')??'').length>=43);
          return respond({access_token:'access-1',refresh_token:'refresh-1',token_type:'Bearer',expires_in:3600});
        }
        if(params.get('grant_type')==='refresh_token'){
          refreshes++;
          assert.equal(params.get('refresh_token'),'refresh-1');
          return respond({access_token:'access-2',refresh_token:'refresh-2',token_type:'Bearer',expires_in:3600});
        }
      }
      if(url===provider.revokeUrl){
        revocations++;assert.equal(params.get('token'),'refresh-2');
        return respond({ok:true});
      }
      throw Error('unexpected OAuth call');
    }};
    const service=new OAuthConnectionService(runtime,keys,vault,transport,[provider]);
    try{
      await admin.query(`INSERT INTO universal_connect.connections
        (id,tenant_id,connector_id,enabled,capabilities)
        VALUES($1,$2,$3,true,'["records.read"]'::jsonb)`,[connection,tenant,provider.id]);
      const start=await service.begin(principal,scope,provider.id);
      const auth=new URL(start.url);
      assert.equal(auth.searchParams.get('response_type'),'code');
      assert.equal(auth.searchParams.get('code_challenge_method'),'S256');
      assert.equal(auth.searchParams.get('scope'),'records.read records.write');
      assert.equal(auth.searchParams.get('state'),start.state);
      const pending=await admin.query('SELECT state_hash,verifier_ciphertext FROM universal_connect.oauth_pending WHERE connection_id=$1',[connection]);
      assert.equal(pending.rows.length,1);
      assert.notEqual(pending.rows[0].state_hash,start.state);
      assert.ok(pending.rows[0].verifier_ciphertext.length>0);
      await assert.rejects(service.complete({...principal,tenantId:other},{...scope,tenantId:other},provider.id,start.state,'provider-code-123'),OAuthError);
      await assert.rejects(service.complete(principal,scope,provider.id,'wrong-state','provider-code-123'),OAuthError);
      await service.complete(principal,scope,provider.id,start.state,'provider-code-123');
      assert.equal(exchanges,1);
      await assert.rejects(service.complete(principal,scope,provider.id,start.state,'provider-code-123'),OAuthError);
      assert.equal(exchanges,1,'replay must never reach provider');
      const encrypted=await admin.query("SELECT ciphertext FROM universal_connect.credentials WHERE tenant_id=$1 AND name='oauth_tokens'",[tenant]);
      assert.equal(encrypted.rows.length,1);
      assert.ok(!encrypted.rows[0].ciphertext.toString().includes('access-1'));
      await service.refresh(principal,scope,provider.id);
      assert.equal(refreshes,1);
      await vault.withCredential(scope,'oauth_tokens',async buf=>{
        const body=JSON.parse(buf.toString());assert.equal(body.access_token,'access-2');assert.equal(body.refresh_token,'refresh-2');
      });
      assert.equal(await service.disconnect(principal,scope,provider.id),true);
      assert.equal(revocations,1);
      const after=await admin.query("SELECT count(*)::int AS n FROM universal_connect.credentials WHERE tenant_id=$1 AND name='oauth_tokens'",[tenant]);
      assert.equal(after.rows[0].n,0);
      const unscoped=await runtime.query('SELECT * FROM universal_connect.oauth_pending');
      assert.equal(unscoped.rows.length,0);
    }finally{
      await admin.query('DELETE FROM universal_connect.oauth_pending WHERE tenant_id=$1',[tenant]);
      await admin.query('DELETE FROM universal_connect.credentials WHERE tenant_id=$1',[tenant]);
      await admin.query('DELETE FROM universal_connect.connections WHERE tenant_id=$1',[tenant]);
      await runtime.end();await admin.end();
    }
  });
  test('real PostgreSQL: unknown or expired state cannot be exchanged',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    let calls=0;
    const service=new OAuthConnectionService(runtime,keys,{
      put:async()=>{},withCredential:async()=>{throw Error('not used')},revoke:async()=>false
    },{send:async()=>{calls++;return respond({access_token:'x',token_type:'Bearer'})}},[provider]);
    try{
      await admin.query(`INSERT INTO universal_connect.connections
        (id,tenant_id,connector_id,enabled,capabilities)
        VALUES($1,$2,$3,true,'["records.read"]'::jsonb)`,[connection,tenant,provider.id]);
      const pending=await service.begin(principal,scope,provider.id);
      await admin.query('UPDATE universal_connect.oauth_pending SET expires_at=now()-interval \'1 minute\' WHERE tenant_id=$1',[tenant]);
      await assert.rejects(service.complete(principal,scope,provider.id,pending.state,'provider-code-123'),OAuthError);
      assert.equal(calls,0);
    }finally{
      await admin.query('DELETE FROM universal_connect.oauth_pending WHERE tenant_id=$1',[tenant]);
      await admin.query('DELETE FROM universal_connect.connections WHERE tenant_id=$1',[tenant]);
      await runtime.end();await admin.end();
    }
  });
}

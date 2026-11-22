import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {randomBytes} from 'node:crypto';
import {OAuthConnectionService,OAuthError} from '../../oauth/src/index.ts';
import {PostgresCredentialVault} from '../../vault/src/index.ts';
import {githubOAuthProvider} from '../src/oauth.ts';
const tenant='test-github-oauth-tenant',conn='test-github-oauth-conn';
const actor='test-github-oauth-actor';
const scope={tenantId:tenant,connectionId:conn};
const principal={subject:actor,tenantId:tenant,assuranceLevel:1};
if(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_RUNTIME_DATABASE_URL){
  test('GitHub PKCE requires server client secret, normalizes lowercase bearer, refreshes rotated secrets',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    const key=randomBytes(32);
    const keys={currentVersion:async()=> 'v1',keyForVersion:async()=>key};
    const vault=new PostgresCredentialVault(runtime,keys);
    const provider=githubOAuthProvider({
      clientId:'client123456',redirectUri:'https://app.example.com/oauth/github'
    });
    let exchanges=0,refreshes=0,clientSecretUses=0,cleared=false;
    const clientSecrets={withClientSecret:async <T>(_id:string,fn:(secret:Buffer)=>Promise<T>):Promise<T>=>{
      const secret=Buffer.from('fake-server-only-secret');
      clientSecretUses++;
      try{return await fn(secret)}finally{secret.fill(0);cleared=true}
    }};
    const transport={send:async(url:string,init:RequestInit):Promise<Response>=>{
      assert.equal(url,provider.tokenUrl);
      const params=new URLSearchParams(init.body as string);
      assert.equal(params.get('client_secret'),'fake-server-only-secret');
      assert.equal(params.get('client_id'),'client123456');
      if(params.get('grant_type')==='authorization_code'){
        exchanges++;assert.ok((params.get('code_verifier')??'').length>=43);
        return new Response(JSON.stringify({access_token:'gho-test-1',refresh_token:'ghr-test-1',token_type:'bearer'}),
          {headers:{'content-type':'application/json'}});
      }
      if(params.get('grant_type')==='refresh_token'){
        refreshes++;assert.equal(params.get('refresh_token'),'ghr-test-1');
        return new Response(JSON.stringify({access_token:'gho-test-2',refresh_token:'ghr-test-2',token_type:'bearer'}),
          {headers:{'content-type':'application/json'}});
      }
      throw new Error('unexpected request');
    }};
    try{
      assert.throws(()=>new OAuthConnectionService(runtime,keys,vault,transport,[provider]),OAuthError);
      await admin.query(`INSERT INTO universal_connect.connections(id,tenant_id,connector_id,enabled,capabilities)
        VALUES($1,$2,$3,true,'["github.profile.read"]'::jsonb)`,[conn,tenant,provider.id]);
      const svc=new OAuthConnectionService(runtime,keys,vault,transport,[provider],clientSecrets);
      const pending=await svc.begin(principal,scope,provider.id);
      assert.equal(new URL(pending.url).searchParams.get('code_challenge_method'),'S256');
      await svc.complete(principal,scope,provider.id,pending.state,'fake-code');
      await svc.refresh(principal,scope,provider.id);
      assert.equal(exchanges,1);assert.equal(refreshes,1);assert.equal(clientSecretUses,2);assert.equal(cleared,true);
      await vault.withCredential(scope,'oauth_tokens',async bytes=>{
        const parsed=JSON.parse(bytes.toString('utf8'));
        assert.equal(parsed.token_type,'Bearer');
        assert.equal(parsed.access_token,'gho-test-2');
        assert.equal(parsed.refresh_token,'ghr-test-2');
      });
      await assert.rejects(svc.complete(principal,scope,provider.id,pending.state,'fake-code'),OAuthError);
      assert.equal(exchanges,1);
    }finally{
      await admin.query('DELETE FROM universal_connect.oauth_pending WHERE tenant_id=$1',[tenant]);
      await admin.query('DELETE FROM universal_connect.credentials WHERE tenant_id=$1',[tenant]);
      await admin.query('DELETE FROM universal_connect.connections WHERE tenant_id=$1',[tenant]);
      await runtime.end();await admin.end();
    }
  });
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {GitHubReadConnector,GitHubProviderError} from '../src/index.ts';
import {githubOAuthProvider} from '../src/oauth.ts';
import {ConnectorRegistry} from '../../connector-sdk/src/index.ts';
import type {ProviderTransport} from '../../rest-adapter/src/index.ts';
const ctx={tenantId:'tenant-a',actorId:'user-a',connectionId:'connection-a',permittedCapabilities:['github.profile.read','github.repositories.read']};
const tokenBytes=(expiresAt?:number)=>Buffer.from(JSON.stringify({
  token_type:'Bearer',access_token:'test-oauth-token',...(expiresAt?{expires_at:expiresAt}:{})
}));
function fixture(override?:{
  transport?:ProviderTransport;
  limiter?:{acquire:(tenant:string,provider:string)=>Promise<boolean>};
  bytes?:Buffer;
}){
  let calls=0;let wiped=false;const observed:{url:string;init:RequestInit}[]=[];
  const transport:ProviderTransport=override?.transport??{send:async(url,init)=>{
    calls++;observed.push({url,init});
    return new Response(JSON.stringify(url.endsWith('/repos')?[{
      id:100,name:'Test',full_name:'example/Test',private:true,default_branch:'main',
      html_url:'https://github.com/example/Test'
    }]:{
      id:123,login:'example',name:'Example User',avatar_url:null,html_url:'https://github.com/example'
    }),{headers:{'content-type':'application/json','x-github-request-id':'r-test'}})
  }};
  const vault={withCredential:async(_scope:unknown,name:string,use:(raw:Buffer)=>Promise<unknown>)=>{
    assert.equal(name,'oauth_tokens');
    const raw=Buffer.from(override?.bytes??tokenBytes());
    try{return await use(raw)}finally{raw.fill(0);wiped=true}
  }};
  const limiter=override?.limiter??{acquire:async(t:string,p:string)=>t==='tenant-a'&&p==='github.oauth'};
  return {connector:new GitHubReadConnector(vault,transport,limiter),calls:()=>calls,observed,wiped:()=>wiped};
}
test('GitHub OAuth provider requires protected server client secret and default minimal scope',()=>{
  const a=githubOAuthProvider({clientId:'client123456',redirectUri:'https://app.example.com/callback'});
  assert.deepEqual(a.scopes,['read:user']);
  assert.equal(a.requiresClientSecret,true);
  assert.equal(a.tokenUrl,'https://github.com/login/oauth/access_token');
  assert.deepEqual(githubOAuthProvider({clientId:'client123456',redirectUri:'https://app.example.com/callback',includePrivateRepositories:true}).scopes,['read:user','repo']);
});
test('profile uses fixed GitHub API path, vault token and selected profile fields',async()=>{
  const f=fixture();
  const result=await f.connector.execute(ctx,{capability:'github.profile.read',input:{}});
  assert.deepEqual(result,{data:{id:123,login:'example',name:'Example User',avatarUrl:null,profileUrl:'https://github.com/example'},providerRequestId:'r-test'});
  assert.equal(f.calls(),1);
  assert.equal(f.observed[0]?.url,'https://api.github.com/user');
  assert.equal((f.observed[0]?.init.headers as Record<string,string>).authorization,'Bearer test-oauth-token');
  assert.equal(f.observed[0]?.init.redirect,'error');
  assert.equal(f.wiped(),true);
});
test('list repository metadata without mutating GitHub resources',async()=>{
  const f=fixture();
  const result=await f.connector.execute(ctx,{capability:'github.repositories.read',input:{}});
  assert.deepEqual(result.data,[{id:100,name:'Test',fullName:'example/Test',private:true,defaultBranch:'main',htmlUrl:'https://github.com/example/Test'}]);
  assert.equal(f.observed[0]?.init.method,'GET');
  assert.equal(f.observed[0]?.url,'https://api.github.com/user/repos');
});
test('reject arbitrary request fields and unauthorized capabilities without provider calls',async()=>{
  const f=fixture();
  await assert.rejects(f.connector.execute(ctx,{capability:'github.profile.read',input:{url:'https://evil.example.com'}}),GitHubProviderError);
  await assert.rejects(f.connector.execute({...ctx,permittedCapabilities:[]},{capability:'github.profile.read',input:{}}),GitHubProviderError);
  await assert.rejects(f.connector.execute(ctx,{capability:'github.repositories.write',input:{}}),GitHubProviderError);
  assert.equal(f.calls(),0);
});
test('expired access token fails closed before HTTP call',async()=>{
  const f=fixture({bytes:tokenBytes(Date.now()-60000)});
  await assert.rejects(f.connector.execute(ctx,{capability:'github.profile.read',input:{}}),
    (e:unknown)=>e instanceof GitHubProviderError&&e.code==='TOKEN_EXPIRED');
  assert.equal(f.calls(),0);
});
test('denied quota prevents HTTP call',async()=>{
  const f=fixture({limiter:{acquire:async()=>false}});
  await assert.rejects(f.connector.execute(ctx,{capability:'github.profile.read',input:{}}),
    (e:unknown)=>e instanceof GitHubProviderError&&e.code==='RATE_LIMITED');
  assert.equal(f.calls(),0);
});
test('GitHub 401 and invalid response schemas fail closed',async()=>{
  const f=fixture({transport:{send:async()=>new Response('{}',{status:401,headers:{'content-type':'application/json'}})}});
  await assert.rejects(f.connector.execute(ctx,{capability:'github.profile.read',input:{}}),
    (e:unknown)=>e instanceof GitHubProviderError&&e.code==='TOKEN_EXPIRED');
  const bad=fixture({transport:{send:async()=>new Response(JSON.stringify({login:'no-id'}),{headers:{'content-type':'application/json'}})}});
  await assert.rejects(bad.connector.execute(ctx,{capability:'github.profile.read',input:{}}),
    (e:unknown)=>e instanceof GitHubProviderError&&e.code==='INVALID_RESPONSE');
});
test('unverified GitHub connector cannot execute through production registry yet',async()=>{
  const f=fixture(),registry=new ConnectorRegistry();
  registry.register(f.connector);
  await assert.rejects(registry.execute(ctx,'github.oauth',{capability:'github.profile.read',input:{}}));
  assert.equal(f.calls(),0);
});

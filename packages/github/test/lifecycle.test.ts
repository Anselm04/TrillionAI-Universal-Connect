import test from 'node:test';
import assert from 'node:assert/strict';
import {GitHubLifecycleService,GitHubLifecycleError} from '../src/lifecycle.ts';
const scope={tenantId:'test-lifecycle-tenant',connectionId:'test-lifecycle-connection'};
function harness(status:number) {
  const sent:{url:string;init:RequestInit}[]=[];
  const vault={withCredential:async <T>(_scope:unknown,_name:string,fn:(buf:Buffer)=>Promise<T>)=>
    fn(Buffer.from(JSON.stringify({access_token:'fixture-access',token_type:'Bearer'})))};
  const transport={send:async(url:string,init:RequestInit):Promise<Response>=>{
    sent.push({url,init});
    return new Response(status===204?null:'{}',{status,headers:{'content-type':'application/json'}});
  }};
  const secrets={withClientSecret:async <T>(_id:string,fn:(buf:Buffer)=>Promise<T>)=>
    fn(Buffer.from('fixture-secret'))};
  const service=new GitHubLifecycleService(vault,transport,{acquire:async()=>true},secrets,'client123456');
  return {service,sent};
}
test('token health distinguishes authenticated, expired and unavailable',async()=>{
  assert.equal(await harness(200).service.check(scope),'connected');
  assert.equal(await harness(401).service.check(scope),'reconnect_required');
  assert.equal(await harness(403).service.check(scope),'unavailable');
});
test('revocation needs GitHub 204 and targets exact application token path',async()=>{
  const f=harness(204);
  await f.service.revoke(scope);
  assert.equal(f.sent[0]?.url,'https://api.github.com/applications/client123456/token');
  assert.equal(f.sent[0]?.init.method,'DELETE');
  assert.equal((f.sent[0]?.init.headers as Record<string,string>).authorization,
    'Basic '+Buffer.from('client123456:fixture-secret').toString('base64'));
  await assert.rejects(harness(401).service.revoke(scope),GitHubLifecycleError);
});

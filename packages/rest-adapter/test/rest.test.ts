import test from 'node:test';
import assert from 'node:assert/strict';
import {FixedRestConnector,ProviderRequestError,providerOrigin,type ProviderTransport} from '../src/index.ts';
const ctx={tenantId:'tenant-1',actorId:'actor-1',connectionId:'connection-1',permittedCapabilities:['records.read','records.write'],approvalId:'approval-1'};
const config={id:'crm.example',origin:'https://api.example.com',verified:true,operations:[
  {capability:'records.read' as const,method:'GET' as const,path:'/v1/records'},
  {capability:'records.write' as const,method:'POST' as const,path:'/v1/records'}
]};
const response=(value:unknown,status=200,headers:Record<string,string>={})=>new Response(JSON.stringify(value),
  {status,headers:{'content-type':'application/json',...headers}});
test('approved read routes to fixed provider and parses JSON',async()=>{
  const calls:{url:string;init:RequestInit}[]=[];
  const transport:ProviderTransport={send:async(url,init)=>{calls.push({url,init});return response({records:[{id:1}]},200,{'x-request-id':'r-1'})}};
  const adapter=new FixedRestConnector(config,transport);
  const result=await adapter.execute(ctx,{capability:'records.read',input:{ignored:'not sent'}});
  assert.deepEqual(result,{data:{records:[{id:1}]},providerRequestId:'r-1'});
  assert.equal(calls[0]?.url,'https://api.example.com/v1/records');
  assert.equal(calls[0]?.init.method,'GET');
  assert.equal(calls[0]?.init.redirect,'error');
  assert.equal(calls[0]?.init.body,undefined);
});
test('writes require approval and idempotency and never auto retry',async()=>{
  let calls=0;
  const adapter=new FixedRestConnector(config,{send:async(_url,init)=>{calls++;assert.equal((init.headers as Record<string,string>)['idempotency-key'],'event-123456');return response({ok:true})}});
  await assert.rejects(adapter.execute({...ctx,approvalId:undefined},
    {capability:'records.write',input:{id:1},idempotencyKey:'event-123456'}));
  assert.equal(calls,0);
  await adapter.execute(ctx,{capability:'records.write',input:{id:1},idempotencyKey:'event-123456'});
  assert.equal(calls,1);
});
test('vault injects credential and scopes to tenant and connection',async()=>{
  let wiped=false;
  const adapter=new FixedRestConnector({...config,credentialName:'access_token'},
    {send:async(_url,init)=>{assert.equal((init.headers as Record<string,string>).authorization,'Bearer fake-token');return response({ok:true})}},
    async(scope,name,callback)=>{assert.deepEqual(scope,{tenantId:ctx.tenantId,connectionId:ctx.connectionId});assert.equal(name,'access_token');const raw=Buffer.from('fake-token');try{return await callback(raw)}finally{raw.fill(0);wiped=true}});
  await adapter.execute(ctx,{capability:'records.read',input:{}});
  assert.equal(wiped,true);
});
test('rejects unapproved origins, credentials in URLs, paths and redirects',()=>{
  for(const origin of ['http://api.example.com','https://localhost','https://127.0.0.1','https://api.example.com:444','https://api.example.com/path','https://user:pass@api.example.com']){
    assert.throws(()=>providerOrigin(origin),(e:unknown)=>e instanceof ProviderRequestError&&e.code==='CONFIG');
  }
  assert.throws(()=>new FixedRestConnector({...config,operations:[{capability:'records.read',method:'GET',path:'/../secret'}]}, {send:async()=>response({})}));
});
test('caps response size and rejects non-JSON responses',async()=>{
  const large=new FixedRestConnector({...config,maxResponseBytes:10},{send:async()=>response({value:'something larger'})});
  await assert.rejects(large.execute(ctx,{capability:'records.read',input:{}}),(e:unknown)=>e instanceof ProviderRequestError&&e.code==='RESPONSE_INVALID');
  const html=new FixedRestConnector(config,{send:async()=>new Response('<html></html>',{headers:{'content-type':'text/html'}})});
  await assert.rejects(html.execute(ctx,{capability:'records.read',input:{}}));
});
test('GET retries transient 503 but POST does not retry',async()=>{
  let reads=0;
  const adapter=new FixedRestConnector({...config,retries:2},{send:async(_url,init)=>{
    if(init.method==='GET'){reads++;return reads<2?response({error:true},503):response({ok:true})}
    return response({error:true},503);
  }});
  assert.deepEqual((await adapter.execute(ctx,{capability:'records.read',input:{}})).data,{ok:true});
  assert.equal(reads,2);
  await assert.rejects(adapter.execute(ctx,{capability:'records.write',input:{id:1},idempotencyKey:'event-123456'}));
});
test('non-verified adapters cannot be run through registry',async()=>{
  const {ConnectorRegistry}=await import('../../connector-sdk/src/index.ts');
  const registry=new ConnectorRegistry();
  registry.register(new FixedRestConnector({...config,verified:false},{send:async()=>response({})}));
  await assert.rejects(registry.execute(ctx,config.id,{capability:'records.read',input:{}}));
});

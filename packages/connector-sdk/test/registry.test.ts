import test from 'node:test';
import assert from 'node:assert/strict';
import {ConnectorRegistry, ConnectorError, type Connector, type ExecutionContext} from '../src/index.ts';
const ctx: ExecutionContext = {tenantId:'t1',actorId:'a1',connectionId:'c1',permittedCapabilities:['records.read','records.write']};
function adapter(state: Connector['manifest']['state']='verified'): Connector {
  return {manifest:{id:'example.adapter',version:'1.0.0',state,capabilities:['records.read','records.write']},
    execute: async (_context,request)=>({data:{capability:request.capability}}),healthCheck:async()=> 'healthy'};
}
const read = {capability:'records.read',input:{id:'r1'}};
test('verified authorized read succeeds',async()=>{const r=new ConnectorRegistry();r.register(adapter());assert.deepEqual(await r.execute(ctx,'example.adapter',read),{data:{capability:'records.read'}})});
test('planned connector cannot execute',async()=>{const r=new ConnectorRegistry();r.register(adapter('planned'));await assert.rejects(r.execute(ctx,'example.adapter',read),(e:unknown)=>e instanceof ConnectorError&&e.code==='NOT_VERIFIED')});
test('missing permission is denied',async()=>{const r=new ConnectorRegistry();r.register(adapter());await assert.rejects(r.execute({...ctx,permittedCapabilities:[]},'example.adapter',read),(e:unknown)=>e instanceof ConnectorError&&e.code==='FORBIDDEN')});
test('write requires approval reference',async()=>{const r=new ConnectorRegistry();r.register(adapter());await assert.rejects(r.execute(ctx,'example.adapter',{capability:'records.write',input:{id:'r1'}}),(e:unknown)=>e instanceof ConnectorError&&e.code==='APPROVAL_REQUIRED');assert.deepEqual(await r.execute({...ctx,approvalId:'approval1'},'example.adapter',{capability:'records.write',input:{id:'r1'}}),{data:{capability:'records.write'}})});
test('duplicate ids rejected',()=>{const r=new ConnectorRegistry();r.register(adapter());assert.throws(()=>r.register(adapter()),(e:unknown)=>e instanceof ConnectorError&&e.code==='ALREADY_REGISTERED')});

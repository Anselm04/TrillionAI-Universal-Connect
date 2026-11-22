import test from 'node:test';
import assert from 'node:assert/strict';
import {ConnectorRegistry, ConnectorError, type Connector} from '../../connector-sdk/src/index.ts';
import {ExecutionGateway, type Principal, type ConnectionRecord, type AuditSink} from '../src/index.ts';

const principal: Principal = {subject:'person-1',tenantId:'org-1',assuranceLevel:2};
const connection: ConnectionRecord = {id:'connection-1',tenantId:'org-1',connectorId:'crm.example',enabled:true,capabilities:['records.read','records.write']};
let adapterCalls=0, approvalCalls=0;
const events: string[]=[];
function setup(record: ConnectionRecord|null=connection, policyAllowed=true, approvalValid=true) {
  adapterCalls=0;approvalCalls=0;events.length=0;
  const registry=new ConnectorRegistry();
  const adapter: Connector={
    manifest:{id:'crm.example',version:'1',state:'verified',capabilities:['records.read','records.write']},
    execute:async (_ctx,request)=>{adapterCalls++;return {data:request.input}},
    healthCheck:async()=> 'healthy'
  };
  registry.register(adapter);
  const audit:AuditSink={record:async e=>{events.push(e.event+':'+(e.reason||''))}};
  return new ExecutionGateway(registry,
    {getById:async()=>record},
    {canExecute:async()=>({allowed:policyAllowed})},
    {verifyAndConsume:async()=>{approvalCalls++;return approvalValid}},
    audit);
}
const read={connectionId:'connection-1',request:{capability:'records.read',input:{id:1}}};
const write={connectionId:'connection-1',request:{capability:'records.write',input:{id:1}},approvalId:'approval-1'};
test('authorized scoped read executes and audits',async()=>{const gw=setup();assert.deepEqual(await gw.execute(principal,read),{data:{id:1}});assert.equal(adapterCalls,1);assert.deepEqual(events,['connector.executed:'])});
test('cross-tenant access rejected without leaking connection',async()=>{const gw=setup({...connection,tenantId:'org-2'});await assert.rejects(gw.execute(principal,read),(e:unknown)=>e instanceof ConnectorError&&e.code==='NOT_FOUND');assert.equal(adapterCalls,0)});
test('disabled connection rejected',async()=>{const gw=setup({...connection,enabled:false});await assert.rejects(gw.execute(principal,read),(e:unknown)=>e instanceof ConnectorError&&e.code==='NOT_FOUND')});
test('connection scope is enforced',async()=>{const gw=setup({...connection,capabilities:['records.read']});await assert.rejects(gw.execute(principal,write),(e:unknown)=>e instanceof ConnectorError&&e.code==='FORBIDDEN');assert.equal(adapterCalls,0)});
test('policy denial prevents provider call',async()=>{const gw=setup(connection,false);await assert.rejects(gw.execute(principal,read),(e:unknown)=>e instanceof ConnectorError&&e.code==='FORBIDDEN');assert.equal(adapterCalls,0)});
test('write demands verified approval',async()=>{const gw=setup();await assert.rejects(gw.execute(principal,{...write,approvalId:undefined}),(e:unknown)=>e instanceof ConnectorError&&e.code==='APPROVAL_REQUIRED');assert.equal(adapterCalls,0);assert.equal(approvalCalls,0)});
test('invalid approval does not reach adapter',async()=>{const gw=setup(connection,true,false);await assert.rejects(gw.execute(principal,write),(e:unknown)=>e instanceof ConnectorError&&e.code==='APPROVAL_REQUIRED');assert.equal(adapterCalls,0);assert.equal(approvalCalls,1)});
test('verified approval allows write',async()=>{const gw=setup();assert.deepEqual(await gw.execute(principal,write),{data:{id:1}});assert.equal(adapterCalls,1);assert.equal(approvalCalls,1)});
test('missing authenticated identity is rejected',async()=>{const gw=setup();await assert.rejects(gw.execute({...principal,subject:''},read),(e:unknown)=>e instanceof ConnectorError&&e.code==='INVALID_REQUEST');assert.equal(adapterCalls,0)});

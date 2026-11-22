import {createHash,randomUUID} from 'node:crypto';
import {inTenantTransaction,type TenantPool} from '../../persistence/src/index.ts';
import type {CapabilityRequest,CapabilityResult} from '../../connector-sdk/src/index.ts';
import type {GatewayInput,Principal} from '../../gateway/src/index.ts';

/** A workflow stores only bounded, non-secret JSON. Do not put credentials in input/output. */
export interface WorkflowStep {
  readonly kind:'read'|'write';
  readonly connectionId:string;
  readonly request:CapabilityRequest;
  readonly approvalId?:string;
}
export interface WorkflowDefinition {
  readonly idempotencyKey:string;
  readonly steps:readonly WorkflowStep[];
}
export interface WorkflowExecutor {
  /** Must revalidate actor/session and all current policies before each execution. */
  execute(tenantId:string,actorId:string,input:GatewayInput):Promise<CapabilityResult>;
}
export interface ClaimedStep {
  readonly runId:string;
  readonly tenantId:string;
  readonly actorId:string;
  readonly index:number;
  readonly kind:'read'|'write';
  readonly connectionId:string;
  readonly request:CapabilityRequest;
  readonly approvalId?:string;
  readonly leaseToken:string;
}
export class WorkflowError extends Error {
  readonly code:'INVALID'|'CONFLICT'|'NOT_FOUND'|'STALE'|'UNCERTAIN';
  constructor(code:WorkflowError['code']){super(code);this.name='WorkflowError';this.code=code}
}
const validKey=(x:unknown):x is string=>typeof x==='string'&&/^[a-zA-Z0-9_-]{8,128}$/.test(x);
const validText=(x:unknown):x is string=>typeof x==='string'&&x.trim().length>0&&x.length<=128;
const record=(x:unknown):x is Record<string,unknown>=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
function normalize(def:WorkflowDefinition):string {
  if(!def||!validKey(def.idempotencyKey)||!Array.isArray(def.steps)||def.steps.length<1||def.steps.length>32)
    throw new WorkflowError('INVALID');
  for(const s of def.steps){
    if(!s||!['read','write'].includes(s.kind)||!validText(s.connectionId)||
       !s.request||!validText(s.request.capability)||!record(s.request.input)||
       (s.kind==='write'&&(!validText(s.approvalId)||!validKey(s.request.idempotencyKey)))||
       (s.kind==='read'&&s.request.capability!=='health.read'&&!s.request.capability.endsWith('.read'))||
       (s.kind==='write'&&s.request.capability.endsWith('.read')))
      throw new WorkflowError('INVALID');
  }
  let json:string;
  try{json=JSON.stringify(def)}catch{throw new WorkflowError('INVALID')}
  if(!json||Buffer.byteLength(json)>131072)throw new WorkflowError('INVALID');
  return json;
}
export class PostgresWorkflowEngine {
  private readonly pool:TenantPool;
  constructor(pool:TenantPool){this.pool=pool}
  async enqueue(principal:Principal,def:WorkflowDefinition):Promise<string>{
    if(!principal||!validText(principal.tenantId)||!validText(principal.subject))throw new WorkflowError('INVALID');
    const json=normalize(def);
    const digest=createHash('sha256').update(json).digest('hex');
    const id=randomUUID();
    return inTenantTransaction(this.pool,principal.tenantId,async client=>{
      const row=await client.query(
        `INSERT INTO universal_connect.workflow_runs
           (id,tenant_id,actor_id,idempotency_key,definition_digest)
           VALUES($1,$2,$3,$4,$5)
           ON CONFLICT(tenant_id,idempotency_key) DO NOTHING RETURNING id`,
        [id,principal.tenantId,principal.subject,def.idempotencyKey,digest]);
      if(row.rowCount===0){
        const existing=await client.query(
          `SELECT id,definition_digest,actor_id FROM universal_connect.workflow_runs
            WHERE tenant_id=$1 AND idempotency_key=$2`,[principal.tenantId,def.idempotencyKey]);
        if(existing.rows[0]?.definition_digest!==digest||existing.rows[0]?.actor_id!==principal.subject)
          throw new WorkflowError('CONFLICT');
        return existing.rows[0].id as string;
      }
      for(const [index,step] of def.steps.entries()){
        await client.query(
          `INSERT INTO universal_connect.workflow_steps
            (run_id,tenant_id,step_index,kind,connection_id,request,approval_id)
            VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`,
          [id,principal.tenantId,index,step.kind,step.connectionId,JSON.stringify(step.request),step.approvalId??null]);
      }
      return id;
    });
  }
  /** Atomic SKIP LOCKED claim. Expired writes go uncertain rather than replay. */
  async claim(tenantId:string,leaseSeconds=30):Promise<ClaimedStep|null>{
    if(!Number.isInteger(leaseSeconds)||leaseSeconds<5||leaseSeconds>300)throw new WorkflowError('INVALID');
    return inTenantTransaction(this.pool,tenantId,async client=>{
      // Reconcile crashed workers: reads may be safely retried; writes need manual reconciliation.
      await client.query(
        `WITH expired AS (
           SELECT s.run_id,s.step_index,s.kind FROM universal_connect.workflow_steps s
           WHERE s.tenant_id=$1 AND s.status='running' AND s.leased_until<clock_timestamp()
           FOR UPDATE SKIP LOCKED
         ), changed AS (
           UPDATE universal_connect.workflow_steps s
           SET status=CASE WHEN e.kind='read' AND s.attempt_count<3 THEN 'pending'
                           ELSE CASE WHEN e.kind='write' THEN 'uncertain' ELSE 'failed' END END,
               lease_token=NULL,leased_until=NULL,updated_at=now()
           FROM expired e WHERE s.run_id=e.run_id AND s.step_index=e.step_index
           RETURNING s.run_id,s.status
         )
         UPDATE universal_connect.workflow_runs r
           SET status=CASE WHEN c.status='uncertain' THEN 'uncertain' ELSE 'failed' END,updated_at=now()
         FROM changed c WHERE r.id=c.run_id AND c.status IN ('uncertain','failed')`,
        [tenantId]);
      const token=randomUUID();
      const result=await client.query(
        `WITH candidate AS (
           SELECT s.run_id,s.step_index
             FROM universal_connect.workflow_steps s
             JOIN universal_connect.workflow_runs r ON r.id=s.run_id
           WHERE s.tenant_id=$1 AND r.tenant_id=$1 AND s.status='pending'
             AND r.status IN ('pending','running') AND r.current_step=s.step_index
           ORDER BY r.created_at,r.id
           FOR UPDATE OF s SKIP LOCKED LIMIT 1
         )
         UPDATE universal_connect.workflow_steps s
           SET status='running',attempt_count=attempt_count+1,
               lease_token=$2::uuid,leased_until=clock_timestamp()+($3::int*interval '1 second'),updated_at=now()
           FROM candidate c
           WHERE s.run_id=c.run_id AND s.step_index=c.step_index
           RETURNING s.run_id,s.tenant_id,s.step_index,s.kind,s.connection_id,
             s.request,s.approval_id,s.lease_token`,[tenantId,token,leaseSeconds]);
      if(result.rowCount!==1)return null;
      const row=result.rows[0];
      const run=await client.query(
        `UPDATE universal_connect.workflow_runs SET status='running',updated_at=now()
         WHERE id=$1 AND tenant_id=$2 RETURNING actor_id`,[row.run_id,tenantId]);
      return {runId:row.run_id,tenantId,actorId:run.rows[0].actor_id,
        index:row.step_index,kind:row.kind,connectionId:row.connection_id,
        request:row.request,approvalId:row.approval_id??undefined,leaseToken:row.lease_token};
    });
  }
  /** Fenced completion: stale claims cannot commit. */
  async complete(step:ClaimedStep,data:unknown):Promise<boolean>{
    let payload:string;
    try{payload=JSON.stringify(data)}catch{throw new WorkflowError('INVALID')}
    if(!payload||Buffer.byteLength(payload)>65536)throw new WorkflowError('INVALID');
    return inTenantTransaction(this.pool,step.tenantId,async client=>{
      const updated=await client.query(
        `UPDATE universal_connect.workflow_steps SET status='completed',
          output=$1::jsonb,lease_token=NULL,leased_until=NULL,updated_at=now()
         WHERE run_id=$2 AND step_index=$3 AND tenant_id=$4
           AND status='running' AND lease_token=$5::uuid AND leased_until>clock_timestamp()
         RETURNING run_id`,[payload,step.runId,step.index,step.tenantId,step.leaseToken]);
      if(updated.rowCount!==1)return false;
      const r=await client.query(
        `UPDATE universal_connect.workflow_runs SET current_step=current_step+1,updated_at=now()
         WHERE id=$1 AND tenant_id=$2 AND current_step=$3 RETURNING current_step`,
         [step.runId,step.tenantId,step.index]);
      if(r.rowCount!==1)throw new WorkflowError('STALE');
      const next=await client.query(
        `SELECT 1 FROM universal_connect.workflow_steps
           WHERE run_id=$1 AND tenant_id=$2 AND step_index=$3`,[step.runId,step.tenantId,step.index+1]);
      if(next.rowCount===0)await client.query(
        `UPDATE universal_connect.workflow_runs SET status='completed',updated_at=now()
         WHERE id=$1 AND tenant_id=$2`,[step.runId,step.tenantId]);
      return true;
    });
  }
  async fail(step:ClaimedStep):Promise<boolean>{
    return inTenantTransaction(this.pool,step.tenantId,async client=>{
      // Do not claim that a write failed safely after it may have reached a provider.
      const status=step.kind==='write'?'uncertain':'failed';
      const r=await client.query(
        `UPDATE universal_connect.workflow_steps SET status=$1,lease_token=NULL,
           leased_until=NULL,last_error='execution_failed',updated_at=now()
         WHERE run_id=$2 AND step_index=$3 AND tenant_id=$4
           AND status='running' AND lease_token=$5::uuid RETURNING run_id`,
        [status,step.runId,step.index,step.tenantId,step.leaseToken]);
      if(r.rowCount!==1)return false;
      await client.query(
        `UPDATE universal_connect.workflow_runs SET status=$1,updated_at=now()
         WHERE id=$2 AND tenant_id=$3`,[status,step.runId,step.tenantId]);
      return true;
    });
  }
  async status(tenantId:string,runId:string):Promise<{status:string;currentStep:number}|null>{
    return inTenantTransaction(this.pool,tenantId,async client=>{
      const r=await client.query(
        `SELECT status,current_step FROM universal_connect.workflow_runs
          WHERE id=$1 AND tenant_id=$2`,[runId,tenantId]);
      return r.rows[0]?{status:r.rows[0].status,currentStep:r.rows[0].current_step}:null;
    });
  }
}
/** Process only a previously verified tenant and an explicitly authorized worker.
 * Executor must verify current authorization before calling ExecutionGateway. */
export async function runOne(engine:PostgresWorkflowEngine,executor:WorkflowExecutor,tenantId:string):Promise<boolean>{
  const step=await engine.claim(tenantId);
  if(!step)return false;
  try{
    const result=await executor.execute(step.tenantId,step.actorId,{
      connectionId:step.connectionId,request:step.request,...(step.approvalId?{approvalId:step.approvalId}:{})
    });
    const committed=await engine.complete(step,result.data);
    if(!committed)throw new WorkflowError('STALE');
  }catch(error){
    await engine.fail(step);
    throw error;
  }
  return true;
}

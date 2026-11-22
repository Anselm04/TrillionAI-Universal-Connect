import {randomUUID} from 'node:crypto';
import type {GatewayInput,Principal} from '../../gateway/src/index.ts';
import type {CapabilityResult} from '../../connector-sdk/src/index.ts';
import {inTenantTransaction,type TenantPool} from '../../persistence/src/index.ts';
import {PostgresWorkflowEngine,type ClaimedStep,type WorkflowExecutor,type WorkflowError} from '../../workflow/src/index.ts';

export type WorkerRole='owner'|'admin'|'staff'|'customer';
export interface ValidatedActor {
  readonly id:string;
  readonly tenantId:string;
  readonly role:WorkerRole;
  readonly emailVerified:boolean;
  readonly activeMembership:boolean;
}
export interface ActorDirectory {
  /** Must query authenticated server-to-server Identity APIs; not client-supplied identities. */
  lookup(actorId:string,tenantId:string):Promise<ValidatedActor|null>;
}
export interface DelegationStore {
  /** Explicit unexpired, nonrevoked delegation for this exact workflow and actor. */
  valid(runId:string,tenantId:string,actorId:string):Promise<boolean>;
}
export interface AuthorizedGateway {
  execute(principal:Principal,input:GatewayInput):Promise<CapabilityResult>;
}
export class WorkerAuthorizationError extends Error {
  constructor(){super('Workflow authorization unavailable or denied');this.name='WorkerAuthorizationError';}
}
/** Worker identity is SERVICE controlled; stored actor is merely a lookup key, not a login. */
export class AuthorizedWorkflowExecutor implements WorkflowExecutor {
  private readonly directory:ActorDirectory;
  private readonly delegations:DelegationStore;
  private readonly gateway:AuthorizedGateway;
  constructor(directory:ActorDirectory,delegations:DelegationStore,gateway:AuthorizedGateway) {
    this.directory=directory;this.delegations=delegations;this.gateway=gateway;
  }
  async execute(tenantId:string,actorId:string,input:GatewayInput,runId?:string):Promise<CapabilityResult> {
    if(!runId)throw new WorkerAuthorizationError();
    let actor:ValidatedActor|null;
    let delegated:boolean;
    try {
      [actor,delegated]=await Promise.all([
        this.directory.lookup(actorId,tenantId),
        this.delegations.valid(runId,tenantId,actorId)
      ]);
    }catch{throw new WorkerAuthorizationError()}
    if(!actor||!delegated||!actor.emailVerified||!actor.activeMembership||
       actor.id!==actorId||actor.tenantId!==tenantId||
       !['owner','admin','staff','customer'].includes(actor.role))throw new WorkerAuthorizationError();
    // Workflow authorization is NOT a session: no user JWT is forged.
    // The approved delegation authorizes background execution; gateway still
    // enforces connection ownership, capability policy and single-use write approval.
    return this.gateway.execute({subject:actorId,tenantId,assuranceLevel:1},input);
  }
}
export class PostgresDelegationStore implements DelegationStore {
  private readonly pool:TenantPool;
  constructor(pool:TenantPool){this.pool=pool}
  async valid(runId:string,tenantId:string,actorId:string):Promise<boolean>{
    return inTenantTransaction(this.pool,tenantId,async client=>{
      const result=await client.query(
        `SELECT 1 FROM universal_connect.workflow_delegations
         WHERE run_id=$1 AND tenant_id=$2 AND actor_id=$3
           AND revoked_at IS NULL AND expires_at>clock_timestamp()`,
        [runId,tenantId,actorId]);
      return result.rowCount===1;
    });
  }
}
export interface RecoveryApproval {
  /** Requires an authenticated, authorized operator with independent provider evidence. */
  authorize(tenantId:string,reviewerId:string,runId:string):Promise<boolean>;
}
export class AuditedWorkflowRecovery {
  private readonly pool:TenantPool;
  private readonly approval:RecoveryApproval;
  constructor(pool:TenantPool,approval:RecoveryApproval){this.pool=pool;this.approval=approval}
  async reconcile(input:{
    tenantId:string;runId:string;stepIndex:number;reviewerId:string;
    outcome:'confirmed_completed'|'confirmed_not_executed';evidenceReference:string;
  }):Promise<boolean> {
    const {tenantId,runId,stepIndex,reviewerId,outcome,evidenceReference}=input;
    if(!tenantId?.trim()||!reviewerId?.trim()||!runId?.trim()||
       !Number.isInteger(stepIndex)||stepIndex<0||
       !['confirmed_completed','confirmed_not_executed'].includes(outcome)||
       typeof evidenceReference!=='string'||evidenceReference.length<8||evidenceReference.length>512||
       /[\r\n\x00-\x1f]/.test(evidenceReference))
       throw new WorkerAuthorizationError();
    let authorized=false;
    try{authorized=await this.approval.authorize(tenantId,reviewerId,runId)}catch{}
    if(!authorized)throw new WorkerAuthorizationError();
    return inTenantTransaction(this.pool,tenantId,async client=>{
      // Lock both records: enforce one audited reconciliation and prevent race with worker.
      const run=await client.query(
        `SELECT current_step,status FROM universal_connect.workflow_runs
         WHERE id=$1 AND tenant_id=$2 FOR UPDATE`,[runId,tenantId]);
      if(run.rowCount!==1||run.rows[0].status!=='uncertain'||
         run.rows[0].current_step!==stepIndex)return false;
      const step=await client.query(
        `SELECT status,kind FROM universal_connect.workflow_steps
         WHERE run_id=$1 AND tenant_id=$2 AND step_index=$3 FOR UPDATE`,
        [runId,tenantId,stepIndex]);
      if(step.rowCount!==1||step.rows[0].status!=='uncertain'||
         step.rows[0].kind!=='write')return false;
      const target=outcome==='confirmed_completed'?'completed':'failed';
      await client.query(
        `UPDATE universal_connect.workflow_steps SET status=$1,last_error=NULL,updated_at=now()
           WHERE run_id=$2 AND tenant_id=$3 AND step_index=$4 AND status='uncertain'`,
        [target,runId,tenantId,stepIndex]);
      if(target==='completed'){
        const next=await client.query(
          `SELECT 1 FROM universal_connect.workflow_steps
           WHERE run_id=$1 AND tenant_id=$2 AND step_index=$3`,
          [runId,tenantId,stepIndex+1]);
        await client.query(
          `UPDATE universal_connect.workflow_runs SET current_step=current_step+1,
           status=$1,updated_at=now() WHERE id=$2 AND tenant_id=$3`,
          [next.rowCount===1?'pending':'completed',runId,tenantId]);
      }else{
        // Negative confirmation DOES NOT resubmit an old write. It ends the run.
        await client.query(
          `UPDATE universal_connect.workflow_runs SET status='failed',updated_at=now()
           WHERE id=$1 AND tenant_id=$2`,[runId,tenantId]);
      }
      await client.query(
        `INSERT INTO universal_connect.workflow_reconciliations
          (id,tenant_id,run_id,step_index,reviewer_id,decision,evidence_reference)
          VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [randomUUID(),tenantId,runId,stepIndex,reviewerId,outcome,evidenceReference]);
      return true;
    });
  }
}
/** Claim, reauthorize, then execute through gateway. Never blindly use stored user identity. */
export async function runAuthorizedStep(
  engine:PostgresWorkflowEngine,worker:AuthorizedWorkflowExecutor,tenantId:string
):Promise<boolean>{
  const claimed=await engine.claim(tenantId);
  if(!claimed)return false;
  try{
    const result=await worker.execute(claimed.tenantId,claimed.actorId,{
      connectionId:claimed.connectionId,request:claimed.request,
      ...(claimed.approvalId?{approvalId:claimed.approvalId}:{})
    },claimed.runId);
    if(!await engine.complete(claimed,result.data))throw new Error('Stale workflow claim');
    return true;
  }catch(error){
    // Invalid approvals or lost actor permissions must not be retried automatically.
    await engine.fail(claimed);
    throw error;
  }
}

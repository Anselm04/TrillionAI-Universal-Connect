import {randomUUID} from 'node:crypto';
import express, {type Request, type Response, type NextFunction} from 'express';
import {inTenantTransaction,type TenantPool} from '../../persistence/src/index.ts';
import {AuditedWorkflowRecovery} from '../../worker/src/index.ts';
import type {SupabaseIdentityBoundary,VerifiedIdentity} from '../../identity/src/index.ts';

export type Action='delegation.issued'|'delegation.revoked'|'recovery.accepted';
export interface RecoveryEvidence {
  /** Independent provider lookup; never trust a client-provided approval claim. */
  verify(input:{
    tenantId:string;runId:string;stepIndex:number;
    outcome:'confirmed_completed'|'confirmed_not_executed';evidenceReference:string;
  }):Promise<boolean>;
}
export class ManagementDenied extends Error {
  constructor(){super('Management action denied');this.name='ManagementDenied'}
}
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const safeRef=(x:unknown):x is string=>typeof x==='string'&&x.length>=8&&x.length<=512&&
  !/[\x00-\x1f]/.test(x);
/** Trust these JWT claims ONLY after the exact token was verified by Identity.authenticate. */
export function requireFreshTotp(verified:VerifiedIdentity,token:string,now=Math.floor(Date.now()/1000)):void {
  if(!['owner','admin'].includes(verified.organisationRole)||verified.principal.assuranceLevel!==2)
    throw new ManagementDenied();
  try{
    const parts=token.split('.');
    if(parts.length!==3)throw new ManagementDenied();
    const payload=JSON.parse(Buffer.from(parts[1]!,'base64url').toString('utf8')) as {
      sub?:unknown;aal?:unknown;amr?:unknown
    };
    if(payload.sub!==verified.principal.subject||payload.aal!=='aal2'||!Array.isArray(payload.amr))
      throw new ManagementDenied();
    const recent=payload.amr.some((m:unknown)=>{
      if(!m||typeof m!=='object')return false;
      const method=(m as {method?:unknown}).method;
      const timestamp=(m as {timestamp?:unknown}).timestamp;
      return method==='totp'&&typeof timestamp==='number'&&Number.isSafeInteger(timestamp)&&
        timestamp>0&&timestamp<=now&&now-timestamp<=15*60;
    });
    if(!recent)throw new ManagementDenied();
  }catch{throw new ManagementDenied()}
}
export class ManagedDelegations {
  private readonly pool:TenantPool;
  constructor(pool:TenantPool){this.pool=pool}
  async issue(operator:VerifiedIdentity,runId:string,expiresMinutes:number):Promise<boolean>{
    const tenantId=operator.principal.tenantId,actorId=operator.principal.subject;
    if(!uuid.test(runId)||!Number.isInteger(expiresMinutes)||expiresMinutes<1||expiresMinutes>60)
      throw new ManagementDenied();
    return inTenantTransaction(this.pool,tenantId,async client=>{
      const run=await client.query(
        `SELECT actor_id,status FROM universal_connect.workflow_runs
         WHERE id=$1 AND tenant_id=$2 FOR UPDATE`,[runId,tenantId]);
      if(run.rowCount!==1||run.rows[0].actor_id!==actorId||
        !['pending','running'].includes(run.rows[0].status))return false;
      const result=await client.query(
        `INSERT INTO universal_connect.workflow_delegations
          (tenant_id,run_id,actor_id,expires_at)
          VALUES($1,$2,$3,clock_timestamp()+($4::int*interval '1 minute'))
          ON CONFLICT(tenant_id,run_id,actor_id) DO NOTHING
          RETURNING run_id`,[tenantId,runId,actorId,expiresMinutes]);
      if(result.rowCount!==1)return false;
      await client.query(
        `INSERT INTO universal_connect.workflow_management_audit
          (id,tenant_id,run_id,operator_id,action) VALUES($1,$2,$3,$4,'delegation.issued')`,
        [randomUUID(),tenantId,runId,actorId]);
      return true;
    });
  }
  async revoke(operator:VerifiedIdentity,runId:string):Promise<boolean>{
    const tenantId=operator.principal.tenantId,actorId=operator.principal.subject;
    if(!uuid.test(runId))throw new ManagementDenied();
    return inTenantTransaction(this.pool,tenantId,async client=>{
      const result=await client.query(
        `UPDATE universal_connect.workflow_delegations
         SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2
           AND actor_id=$3 AND revoked_at IS NULL RETURNING run_id`,
        [tenantId,runId,actorId]);
      if(result.rowCount!==1)return false;
      await client.query(
        `INSERT INTO universal_connect.workflow_management_audit
         (id,tenant_id,run_id,operator_id,action) VALUES($1,$2,$3,$4,'delegation.revoked')`,
        [randomUUID(),tenantId,runId,actorId]);
      return true;
    });
  }
}
export interface ManagementApiOptions {
  readonly identity:Pick<SupabaseIdentityBoundary,'authenticate'>;
  readonly pool:TenantPool;
  readonly evidence:RecoveryEvidence;
}
/** Internal API router. Mount only behind TLS, firewall, CSRF/cross-origin and request-rate controls. */
export function createManagementRouter(options:ManagementApiOptions):express.Router{
  const router=express.Router();
  const delegations=new ManagedDelegations(options.pool);
  router.use(express.json({limit:'4kb',strict:true}));
  router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next()});
  async function authenticate(req:Request):Promise<{verified:VerifiedIdentity;token:string}>{
    const token=/^Bearer ([^\s]+)$/i.exec(req.header('authorization')??'')?.[1];
    const tenant=req.header('x-organisation-id');
    if(!token||!tenant||!uuid.test(tenant))throw new ManagementDenied();
    const verified=await options.identity.authenticate(token,tenant);
    requireFreshTotp(verified,token);
    return {verified,token};
  }
  function handle(callback:(req:Request,res:Response)=>Promise<void>) {
    return (req:Request,res:Response,next:NextFunction)=>{
      Promise.resolve(callback(req,res)).catch(error=>{
        if(error instanceof ManagementDenied){res.status(403).json({error:'forbidden'});return}
        // Never echo secrets, tokens or untrusted provider evidence.
        res.status(503).json({error:'management_unavailable'});
      });
    };
  }
  router.post('/delegations/:runId',handle(async(req,res)=>{
    const {verified}=await authenticate(req);
    const minutes=req.body?.expiresMinutes;
    const ok=await delegations.issue(verified,req.params.runId,minutes);
    res.status(ok?201:409).json({accepted:ok});
  }));
  router.delete('/delegations/:runId',handle(async(req,res)=>{
    const {verified}=await authenticate(req);
    const ok=await delegations.revoke(verified,req.params.runId);
    res.status(ok?200:404).json({revoked:ok});
  }));
  router.post('/recover/:runId/:stepIndex',handle(async(req,res)=>{
    const {verified}=await authenticate(req);
    const stepIndex=Number(req.params.stepIndex);
    const outcome=req.body?.outcome;
    const evidenceReference=req.body?.evidenceReference;
    if(!uuid.test(req.params.runId)||!/^\d{1,2}$/.test(req.params.stepIndex)||
       !Number.isInteger(stepIndex)||stepIndex>31||
       !['confirmed_completed','confirmed_not_executed'].includes(outcome)||
       !safeRef(evidenceReference))throw new ManagementDenied();
    let supported=false;
    try{supported=await options.evidence.verify({
      tenantId:verified.principal.tenantId,runId:req.params.runId,stepIndex,outcome,evidenceReference
    })}catch{}
    if(!supported)throw new ManagementDenied();
    const recovery=new AuditedWorkflowRecovery(options.pool,{
      authorize:async(t,reviewer,run)=>t===verified.principal.tenantId&&
        reviewer===verified.principal.subject&&run===req.params.runId
    });
    const ok=await recovery.reconcile({
      tenantId:verified.principal.tenantId,reviewerId:verified.principal.subject,
      runId:req.params.runId,stepIndex,outcome,evidenceReference
    });
    res.status(ok?200:409).json({reconciled:ok});
  }));
  return router;
}

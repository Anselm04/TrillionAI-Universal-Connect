import {randomUUID} from 'node:crypto';
import express, {type Request,type Response} from 'express';
import {inTenantTransaction,type TenantPool} from '../../persistence/src/index.ts';
import type {SupabaseIdentityBoundary,VerifiedIdentity} from '../../identity/src/index.ts';
import type {OAuthPermissionPolicy} from '../../connection-api/src/index.ts';
import type {ProviderRateLimiter} from '../../rate-limit/src/index.ts';
import type {GitHubLifecycle,GitHubHealth} from '../../github/src/lifecycle.ts';

export type ManagedConnectionStatus='awaiting_authorization'|'connected'|'disconnected'|'reconnect_required'|'verification_required'|'unavailable';
export interface ManagedConnection {
  readonly id:string;readonly providerId:'github.oauth';
  readonly status:ManagedConnectionStatus;readonly createdAt:string;
  readonly lastVerifiedAt:string|null;
}
export class SelfServiceDenied extends Error {
  constructor(){super('Connection management denied');this.name='SelfServiceDenied'}
}
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const connectionId=/^[a-zA-Z0-9_-]{1,128}$/;
export class PostgresSelfServiceConnections {
  private readonly pool:TenantPool;
  constructor(pool:TenantPool){this.pool=pool}
  async create(identity:VerifiedIdentity):Promise<ManagedConnection>{
    const tenant=identity.principal.tenantId,actor=identity.principal.subject;
    const id=randomUUID().replaceAll('-','');
    return inTenantTransaction(this.pool,tenant,async client=>{
      // Only this actor's managed connections count toward the bounded self-service quota.
      const count=await client.query(
        `SELECT count(*)::int AS total FROM universal_connect.connection_owners
         WHERE tenant_id=$1 AND actor_id=$2`,[tenant,actor]);
      if(count.rows[0].total>=20)throw new SelfServiceDenied();
      await client.query(
        `INSERT INTO universal_connect.connections
         (id,tenant_id,connector_id,enabled,capabilities)
         VALUES ($1,$2,'github.oauth',true,'["github.profile.read","github.repositories.read"]'::jsonb)`,
        [id,tenant]);
      await client.query(
        `INSERT INTO universal_connect.connection_owners(connection_id,tenant_id,actor_id)
         VALUES($1,$2,$3)`,[id,tenant,actor]);
      return {id,providerId:'github.oauth',status:'awaiting_authorization',createdAt:new Date().toISOString(),lastVerifiedAt:null};
    });
  }
  async list(identity:VerifiedIdentity):Promise<ManagedConnection[]>{
    const tenant=identity.principal.tenantId,actor=identity.principal.subject;
    return inTenantTransaction(this.pool,tenant,async client=>{
      const rows=await client.query(
        `SELECT c.id,c.enabled,c.created_at,h.state AS health_state,h.checked_at,
          EXISTS(SELECT 1 FROM universal_connect.credentials v
            WHERE v.connection_id=c.id AND v.tenant_id=c.tenant_id AND v.name='oauth_tokens') AS has_token
         FROM universal_connect.connections c
         LEFT JOIN universal_connect.connection_health h ON h.connection_id=c.id AND h.tenant_id=c.tenant_id
         JOIN universal_connect.connection_owners o ON o.connection_id=c.id AND o.tenant_id=c.tenant_id
         WHERE c.tenant_id=$1 AND o.actor_id=$2 AND c.connector_id='github.oauth'
         ORDER BY c.created_at DESC,c.id LIMIT 20`,[tenant,actor]);
      return rows.rows.map((row):ManagedConnection=>({
        id:row.id,providerId:'github.oauth',
        status:!row.enabled?'disconnected':!row.has_token?'awaiting_authorization':
          row.health_state==='reconnect_required'?'reconnect_required':
          row.health_state==='unavailable'?'unavailable':
          row.health_state==='connected'&&row.checked_at&&
            Date.now()-new Date(row.checked_at).getTime()<15*60*1000?'connected':'verification_required',
        createdAt:new Date(row.created_at).toISOString(),
        lastVerifiedAt:row.checked_at?new Date(row.checked_at).toISOString():null
      }));
    });
  }
  async get(identity:VerifiedIdentity,id:string):Promise<ManagedConnection|null>{
    if(!connectionId.test(id))throw new SelfServiceDenied();
    const connections=await this.list(identity);
    return connections.find(c=>c.id===id)??null;
  }
  async recordHealth(identity:VerifiedIdentity,id:string,state:GitHubHealth):Promise<boolean>{
    if(!connectionId.test(id)||!['connected','reconnect_required','unavailable'].includes(state))
      throw new SelfServiceDenied();
    return inTenantTransaction(this.pool,identity.principal.tenantId,async client=>{
      const r=await client.query(
        `INSERT INTO universal_connect.connection_health(connection_id,tenant_id,state)
         SELECT c.id,c.tenant_id,$4 FROM universal_connect.connections c
         JOIN universal_connect.connection_owners o ON o.connection_id=c.id AND o.tenant_id=c.tenant_id
         WHERE c.id=$1 AND c.tenant_id=$2 AND o.actor_id=$3 AND c.enabled=true
         ON CONFLICT(connection_id) DO UPDATE SET state=EXCLUDED.state,checked_at=clock_timestamp()
         RETURNING connection_id`,[id,identity.principal.tenantId,identity.principal.subject,state]);
      return r.rowCount===1;
    });
  }
  async owns(identity:VerifiedIdentity,id:string):Promise<boolean>{
    if(!connectionId.test(id))return false;
    return inTenantTransaction(this.pool,identity.principal.tenantId,async client=>{
      const row=await client.query(
        `SELECT 1 FROM universal_connect.connection_owners o
         JOIN universal_connect.connections c ON c.id=o.connection_id AND c.tenant_id=o.tenant_id
         WHERE o.connection_id=$1 AND o.tenant_id=$2 AND o.actor_id=$3
           AND c.connector_id='github.oauth' AND c.enabled=true`,
        [id,identity.principal.tenantId,identity.principal.subject]);
      return row.rowCount===1;
    });
  }
}
/** Concrete policy usable by existing OAuth routes: only a verified actor's provisioned connection.
 * No legacy rows or another tenant/member's connections can be connected or disconnected. */
export function ownerConnectionPolicy(store:Pick<PostgresSelfServiceConnections,'owns'>):OAuthPermissionPolicy{
  return {authorize:async(identity,id,provider,operation,scopeApproval)=>{
    if(provider!=='github.oauth'||!['connect','complete','disconnect'].includes(operation))return false;
    if(operation==='connect'&&!['profile','repositories'].includes(scopeApproval??''))return false;
    return store.owns(identity,id);
  }};
}
export interface SelfServiceRoutesOptions{
  readonly pool:TenantPool;
  readonly identity:Pick<SupabaseIdentityBoundary,'authenticate'>;
  readonly limiter:Pick<ProviderRateLimiter,'acquire'>;
  readonly allowedOrigin:string;
  readonly githubLifecycle?:GitHubLifecycle;
}
export function createSelfServiceConnectionRouter(options:SelfServiceRoutesOptions):express.Router{
  const origin=new URL(options.allowedOrigin);
  if(origin.protocol!=='https:'||origin.pathname!=='/'||origin.search||origin.hash||
    origin.username||origin.password)throw new Error('HTTPS origin required');
  const store=new PostgresSelfServiceConnections(options.pool);
  const router=express.Router();
  router.use(express.json({limit:'2kb',strict:true}));
  router.use((_req,res,next)=>{
    res.setHeader('Cache-Control','no-store');
    res.setHeader('Referrer-Policy','no-referrer');
    next();
  });
  async function principal(req:Request):Promise<VerifiedIdentity>{
    if((req.get('origin')!==origin.origin && !(req.method==='GET' && !req.get('origin') && req.get('sec-fetch-site')==='same-origin')) || req.get('sec-fetch-site')==='cross-site')
      throw new SelfServiceDenied();
    const token=/^Bearer ([^\s]+)$/i.exec(req.get('authorization')??'')?.[1];
    const tenant=req.get('x-organisation-id');
    if(!token||!tenant||!uuid.test(tenant))throw new SelfServiceDenied();
    let result:VerifiedIdentity;
    try{result=await options.identity.authenticate(token,tenant)}catch{throw new SelfServiceDenied()}
    const allowed=await options.limiter.acquire(tenant,'github.oauth.management').catch(()=>false);
    if(!allowed)throw new SelfServiceDenied();
    return result;
  }
  const wrap=(fn:(req:Request,res:Response)=>Promise<void>)=>(req:Request,res:Response)=>{
    void fn(req,res).catch(error=>{
      if(res.headersSent)return;
      if(error instanceof SelfServiceDenied)res.status(403).json({error:'connection_forbidden'});
      else res.status(503).json({error:'connection_unavailable'});
    });
  };
  router.post('/',wrap(async(req,res)=>{
    if(!req.is('application/json')||!req.body||typeof req.body!=='object'||
      Array.isArray(req.body)||Object.keys(req.body).length!==0)throw new SelfServiceDenied();
    const identity=await principal(req);
    const result=await store.create(identity);
    res.status(201).json({connection:result});
  }));
  router.get('/',wrap(async(req,res)=>{
    const identity=await principal(req);
    res.status(200).json({connections:await store.list(identity)});
  }));
  router.post('/:connectionId/verify',wrap(async(req,res)=>{
    const identity=await principal(req),id=req.params.connectionId;
    if(!await store.owns(identity,id)){res.status(404).json({error:'not_found'});return}
    if(!options.githubLifecycle)throw new SelfServiceDenied();
    let state:GitHubHealth;
    try{state=await options.githubLifecycle.check({
      tenantId:identity.principal.tenantId,connectionId:id
    })}catch{state='unavailable'}
    await store.recordHealth(identity,id,state);
    const found=await store.get(identity,id);
    res.status(200).json({connection:found});
  }));
  router.get('/:connectionId',wrap(async(req,res)=>{
    const identity=await principal(req);
    const found=await store.get(identity,req.params.connectionId);
    res.status(found?200:404).json(found?{connection:found}:{error:'not_found'});
  }));
  return router;
}

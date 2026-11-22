import {randomUUID} from 'node:crypto';
import express, {type Request,type Response} from 'express';
import {inTenantTransaction,type TenantPool} from '../../persistence/src/index.ts';
import type {SupabaseIdentityBoundary,VerifiedIdentity} from '../../identity/src/index.ts';
import type {OAuthConnectionService} from '../../oauth/src/index.ts';
import type {ProviderRateLimiter} from '../../rate-limit/src/index.ts';

export interface OAuthPermissionPolicy {
  /** Independently enforce organization role, connection ownership, consent, plan and provider scope. */
  authorize(identity:VerifiedIdentity,connectionId:string,providerId:string,
    operation:'connect'|'complete'|'disconnect',scopeApproval:'profile'|'repositories'|null):Promise<boolean>;
}
export interface OAuthRouteOptions {
  readonly identity:Pick<SupabaseIdentityBoundary,'authenticate'>;
  readonly oauth:Pick<OAuthConnectionService,'begin'|'complete'|'disconnect'>;
  readonly pool:TenantPool;
  readonly policy:OAuthPermissionPolicy;
  readonly limiter:Pick<ProviderRateLimiter,'acquire'>;
  readonly allowedOrigin:string;
  readonly providerId:'github.oauth';
  /** Must reflect the registered OAuth provider scopes; repo access is never implied. */
  readonly supportsRepositoryAccess:boolean;
}
export class ConnectionDenied extends Error {
  constructor(){super('Connection action denied');this.name='ConnectionDenied'}
}
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const connectionIdValid=(v:unknown):v is string=>typeof v==='string'&&
  v.length>0&&v.length<=128&&/^[A-Za-z0-9_-]+$/.test(v);
const approvedValue=(v:unknown):v is 'profile'|'repositories'=>v==='profile'||v==='repositories';
function validateJsonObject(v:unknown,keys:readonly string[]):v is Record<string,unknown>{
  return v!==null&&typeof v==='object'&&!Array.isArray(v)&&
    Object.keys(v).every(k=>keys.includes(k));
}
/** Only accept bearer-authenticated same-origin JSON writes: never cookie-authenticate these routes. */
export function createOAuthConnectionRouter(options:OAuthRouteOptions):express.Router{
  const configuredOrigin=new URL(options.allowedOrigin);
  if(configuredOrigin.protocol!=='https:'||configuredOrigin.username||configuredOrigin.password||
    configuredOrigin.pathname!=='/'||configuredOrigin.search||configuredOrigin.hash)
    throw new Error('OAuth API requires an explicit HTTPS browser origin');
  const router=express.Router();
  router.use(express.json({limit:'4kb',strict:true}));
  router.use((_req,res,next)=>{
    res.setHeader('Cache-Control','no-store');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('X-Content-Type-Options','nosniff');
    next();
  });
  async function authorize(req:Request,operation:'connect'|'complete'|'disconnect',
    scopeApproval:'profile'|'repositories'|null):Promise<{identity:VerifiedIdentity;connectionId:string}>{
    if(req.get('origin')!==configuredOrigin.origin || req.get('sec-fetch-site')==='cross-site')
      throw new ConnectionDenied();
    const token=/^Bearer ([^\s]+)$/i.exec(req.get('authorization')??'')?.[1];
    const tenantId=req.get('x-organisation-id'),connectionId=req.params.connectionId;
    if(!token||!tenantId||!uuid.test(tenantId)||!connectionIdValid(connectionId))
      throw new ConnectionDenied();
    let identity:VerifiedIdentity;
    try{identity=await options.identity.authenticate(token,tenantId)}
    catch{throw new ConnectionDenied()}
    // Explicit consent is mandatory for initial connection, while subsequent operations
    // re-check the ongoing policy without trusting request claims.
    if(operation==='connect'&&!scopeApproval)throw new ConnectionDenied();
    const permitted=await options.policy.authorize(identity,connectionId,options.providerId,operation,scopeApproval)
      .catch(()=>false);
    if(!permitted)throw new ConnectionDenied();
    const reserved=await options.limiter.acquire(tenantId,options.providerId+'.oauth').catch(()=>false);
    if(!reserved)throw new ConnectionDenied();
    return {identity,connectionId};
  }
  async function audit(identity:VerifiedIdentity,connectionId:string,
    action:'oauth.started'|'oauth.connected'|'oauth.disconnected'):Promise<void>{
    await inTenantTransaction(options.pool,identity.principal.tenantId,async client=>{
      await client.query(`INSERT INTO universal_connect.oauth_connection_events
        (id,tenant_id,actor_id,connection_id,provider_id,action)
        VALUES($1,$2,$3,$4,$5,$6)`,
        [randomUUID(),identity.principal.tenantId,identity.principal.subject,
          connectionId,options.providerId,action]);
    });
  }
  const wrap=(handler:(req:Request,res:Response)=>Promise<void>)=>(req:Request,res:Response)=>{
    void handler(req,res).catch(error=>{
      if(res.headersSent)return;
      if(error instanceof ConnectionDenied){
        res.status(403).json({error:'connection_forbidden'});
      }else{
        // Do not expose provider codes, OAuth tokens, raw provider errors or internal secrets.
        res.status(503).json({error:'connection_unavailable'});
      }
    });
  };
  router.post('/:connectionId/start',wrap(async(req,res)=>{
    if(!validateJsonObject(req.body,['consent','requestedAccess']) ||
      req.body.consent!==true || !approvedValue(req.body.requestedAccess))
      throw new ConnectionDenied();
    // Broad GitHub repo permission cannot be silently requested by an API client.
    if(req.body.requestedAccess==='repositories'&&!options.supportsRepositoryAccess)
      throw new ConnectionDenied();
    const {identity,connectionId}=await authorize(req,'connect',req.body.requestedAccess);
    const connection= {tenantId:identity.principal.tenantId,connectionId};
    const result=await options.oauth.begin(identity.principal,connection,options.providerId);
    await audit(identity,connectionId,'oauth.started');
    // Return the URL rather than doing a cross-origin 302 from an API POST.
    res.status(200).json({authorizationUrl:result.url,expiresInSeconds:600});
  }));
  router.post('/:connectionId/complete',wrap(async(req,res)=>{
    if(!validateJsonObject(req.body,['state','code'])||
      typeof req.body.state!=='string'||req.body.state.length<32||req.body.state.length>128||
      typeof req.body.code!=='string'||req.body.code.length<1||req.body.code.length>2048)
      throw new ConnectionDenied();
    const {identity,connectionId}=await authorize(req,'complete',null);
    await options.oauth.complete(identity.principal,{tenantId:identity.principal.tenantId,connectionId},
      options.providerId,req.body.state,req.body.code);
    await audit(identity,connectionId,'oauth.connected');
    res.status(200).json({connected:true});
  }));
  router.delete('/:connectionId',wrap(async(req,res)=>{
    const {identity,connectionId}=await authorize(req,'disconnect',null);
    const deleted=await options.oauth.disconnect(identity.principal,
      {tenantId:identity.principal.tenantId,connectionId},options.providerId);
    if(!deleted){res.status(404).json({disconnected:false});return}
    await audit(identity,connectionId,'oauth.disconnected');
    res.status(200).json({disconnected:true,providerRevocationConfirmed:false});
  }));
  return router;
}

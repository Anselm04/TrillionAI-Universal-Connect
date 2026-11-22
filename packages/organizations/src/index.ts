import express,{type Request,type Response} from 'express';
import type {SupabaseIdentityBoundary} from '../../identity/src/index.ts';
import type {ProviderRateLimiter} from '../../rate-limit/src/index.ts';

export interface OrganizationRoutesOptions{
  readonly identity:Pick<SupabaseIdentityBoundary,'organizations'>;
  readonly limiter:Pick<ProviderRateLimiter,'acquire'>;
  readonly allowedOrigin:string;
}
export function createOrganizationRouter(options:OrganizationRoutesOptions):express.Router {
  const origin=new URL(options.allowedOrigin);
  if(origin.protocol!=='https:'||origin.pathname!=='/'||origin.search||origin.hash||
    origin.username||origin.password)throw Error('HTTPS origin required');
  const router=express.Router();
  router.use((_req,res,next)=>{
    res.setHeader('Cache-Control','no-store');
    res.setHeader('Referrer-Policy','no-referrer');next();
  });
  router.get('/',async(req:Request,res:Response)=>{
    if(req.get('origin')!==origin.origin||req.get('sec-fetch-site')==='cross-site'){
      res.status(403).json({error:'forbidden'});return;
    }
    const token=/^Bearer ([^\s]+)$/i.exec(req.get('authorization')??'')?.[1];
    if(!token){res.status(403).json({error:'forbidden'});return}
    try{
      // Quota key is an opaque token digest, NEVER a user-supplied organization ID.
      const {createHash}=await import('node:crypto');
      const digest=createHash('sha256').update(token).digest('hex');
      const allowed=await options.limiter.acquire('identity-discovery-'+digest.slice(0,32),'organization.discovery');
      if(!allowed){res.status(429).json({error:'rate_limited'});return}
      const organizations=await options.identity.organizations(token);
      res.status(200).json({organizations});
    }catch{res.status(403).json({error:'forbidden'})}
  });
  return router;
}

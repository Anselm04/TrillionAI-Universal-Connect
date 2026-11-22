import {Buffer} from 'node:buffer';
import express, {type Express} from 'express';
import type {Server} from 'node:http';
import {createPostgresPool} from '../../persistence/src/index.ts';
import {PostgresProviderRateLimiter} from '../../rate-limit/src/index.ts';
import {PostgresCredentialVault,type VaultKeyProvider} from '../../vault/src/index.ts';
import {createGuardedNetworkTransport} from '../../egress/src/index.ts';
import {makeSupabaseIdentityBoundary} from '../../identity/src/index.ts';
import {OAuthConnectionService,type OAuthClientSecrets} from '../../oauth/src/index.ts';
import {githubOAuthProvider} from '../../github/src/oauth.ts';
import {GitHubLifecycleService} from '../../github/src/lifecycle.ts';
import {PostgresSelfServiceConnections,ownerConnectionPolicy,createSelfServiceConnectionRouter} from '../../self-service/src/index.ts';
import {createOrganizationRouter} from '../../organizations/src/index.ts';
import {createOAuthConnectionRouter} from '../../connection-api/src/index.ts';

export interface ServiceConfig {
  port:number; origin:string; databaseUrl:string;
  supabaseUrl:string;publishableKey:string;serviceRoleKey:string;
  githubClientId:string;githubCallbackUrl:string;githubClientSecret:string;
  vaultKeyBase64:string; vaultKeyVersion:string;
}
export class ConfigurationError extends Error {
  constructor(){super('Invalid or missing backend service configuration');this.name='ConfigurationError'}
}
const safeString=(v:unknown,max=8192):v is string=>typeof v==='string'&&v.length>0&&v.length<=max&&v.trim()===v;
const url=(input:string):URL=>{try{return new URL(input)}catch{throw new ConfigurationError()}};
export function parseServiceConfig(env:Record<string,string|undefined>):ServiceConfig {
  const required=(name:string,max=8192):string=>{
    const value=env[name];if(!safeString(value,max))throw new ConfigurationError();return value;
  };
  const port=Number(required('PORT',5));
  if(!Number.isInteger(port)||port<1||port>65535)throw new ConfigurationError();
  const origin=required('PUBLIC_ORIGIN',256),callback=required('GITHUB_CALLBACK_URL',512);
  const parsedOrigin=url(origin),parsedCallback=url(callback);
  if(parsedOrigin.protocol!=='https:'||parsedOrigin.username||parsedOrigin.password||
    parsedOrigin.search||parsedOrigin.hash||parsedOrigin.pathname!=='/'||
    parsedOrigin.port||parsedOrigin.origin!==origin||!parsedOrigin.hostname.includes('.'))
    throw new ConfigurationError();
  if(parsedCallback.origin!==origin||parsedCallback.pathname!=='/oauth/callback'||
    parsedCallback.search||parsedCallback.hash||parsedCallback.username||parsedCallback.password)
    throw new ConfigurationError();
  const databaseUrl=required('DATABASE_URL',2048),db=url(databaseUrl);
  if(!['postgresql:','postgres:'].includes(db.protocol)||!db.hostname||!db.pathname||!db.password)
    throw new ConfigurationError();
  const supabaseUrl=required('SUPABASE_URL',512),supa=url(supabaseUrl);
  if(supa.protocol!=='https:'||supa.pathname!=='/'||supa.search||supa.hash||!supa.hostname.includes('.'))
    throw new ConfigurationError();
  const publishableKey=required('SUPABASE_PUBLISHABLE_KEY');
  const serviceRoleKey=required('SUPABASE_SERVICE_ROLE_KEY');
  if(publishableKey===serviceRoleKey)throw new ConfigurationError();
  const githubClientId=required('GITHUB_CLIENT_ID',128);
  if(!/^[A-Za-z0-9_-]{8,128}$/.test(githubClientId))throw new ConfigurationError();
  const githubClientSecret=required('GITHUB_CLIENT_SECRET');
  if(githubClientSecret.length<12||githubClientSecret.includes('\n')||githubClientSecret.includes('\r'))
    throw new ConfigurationError();
  const vaultKeyBase64=required('VAULT_KEY_BASE64',128),vaultKey=Buffer.from(vaultKeyBase64,'base64');
  if(vaultKey.length!==32||vaultKey.toString('base64')!==vaultKeyBase64)throw new ConfigurationError();
  vaultKey.fill(0);
  const vaultKeyVersion=required('VAULT_KEY_VERSION',128);
  if(!/^[A-Za-z0-9_-]{1,128}$/.test(vaultKeyVersion))throw new ConfigurationError();
  return {port,origin,databaseUrl,supabaseUrl,publishableKey,serviceRoleKey,
    githubClientId,githubCallbackUrl:callback,githubClientSecret,vaultKeyBase64,vaultKeyVersion};
}
/** One active key for initial deployment; keep prior versions in protected key storage before rotating.
 * This environment adapter never writes keys to source, logs or database. */
export function environmentKeyProvider(config:Pick<ServiceConfig,'vaultKeyBase64'|'vaultKeyVersion'>):VaultKeyProvider {
  return {
    currentVersion:async()=>config.vaultKeyVersion,
    keyForVersion:async(version)=>{
      if(version!==config.vaultKeyVersion)throw new ConfigurationError();
      return Buffer.from(config.vaultKeyBase64,'base64');
    }
  };
}
export function environmentClientSecrets(config:Pick<ServiceConfig,'githubClientSecret'>):OAuthClientSecrets {
  return {withClientSecret:async(_id,fn)=>{
    if(_id!=='github.oauth')throw new ConfigurationError();
    const secret=Buffer.from(config.githubClientSecret);
    try{return await fn(secret)}finally{secret.fill(0)}
  }};
}
export interface ServiceDependencies {
  identity:ReturnType<typeof makeSupabaseIdentityBoundary>;
  pool:ReturnType<typeof createPostgresPool>;
  limiter:PostgresProviderRateLimiter;
  vault:PostgresCredentialVault;
  githubLifecycle:GitHubLifecycleService;
  oauth:OAuthConnectionService;
  close():Promise<void>;
}
/** Bind routes to verified dependencies. No management/recovery routes are exposed publicly.
 * Explicitly disallow the broad GitHub repo scope in initial production configuration. */
export function createServiceApp(config:ServiceConfig,dependencies:ServiceDependencies):Express {
  const app=express();
  app.disable('x-powered-by');
  app.use((_req,res,next)=>{
    res.setHeader('Cache-Control','no-store');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'");
    next();
  });
  app.get('/health/live',(_req,res)=>res.status(200).json({status:'alive'}));
  app.get('/health/ready',async(_req,res)=>{
    try{
      const client=await dependencies.pool.connect();
      try {await client.query('SELECT 1')} finally{client.release()}
      res.status(200).json({status:'ready'});
    }catch{res.status(503).json({status:'unavailable'})}
  });
  const store=new PostgresSelfServiceConnections(dependencies.pool);
  app.use('/organizations',createOrganizationRouter({
    identity:dependencies.identity,limiter:dependencies.limiter,allowedOrigin:config.origin
  }));
  app.use('/managed-connections',createSelfServiceConnectionRouter({
    pool:dependencies.pool,identity:dependencies.identity,limiter:dependencies.limiter,
    allowedOrigin:config.origin,githubLifecycle:dependencies.githubLifecycle
  }));
  app.use('/connections',createOAuthConnectionRouter({
    pool:dependencies.pool,identity:dependencies.identity,limiter:dependencies.limiter,
    oauth:dependencies.oauth,policy:ownerConnectionPolicy(store),
    allowedOrigin:config.origin,providerId:'github.oauth',
    supportsRepositoryAccess:false,githubLifecycle:dependencies.githubLifecycle,
    localTokenVault:dependencies.vault
  }));
  app.use((_req,res)=>res.status(404).json({error:'not_found'}));
  return app;
}
export function createServiceDependencies(config:ServiceConfig):ServiceDependencies {
  const pool=createPostgresPool(config.databaseUrl);
  const transport=createGuardedNetworkTransport({
    allowedOrigins:['https://github.com','https://api.github.com']
  });
  const identity=makeSupabaseIdentityBoundary({
    supabaseUrl:config.supabaseUrl,publishableKey:config.publishableKey,
    serviceRoleKey:config.serviceRoleKey
  });
  const keys=environmentKeyProvider(config);
  const vault=new PostgresCredentialVault(pool,keys);
  const limiter=new PostgresProviderRateLimiter(pool,{maxRequests:100,windowSeconds:60});
  const secrets=environmentClientSecrets(config);
  const provider=githubOAuthProvider({
    clientId:config.githubClientId,redirectUri:config.githubCallbackUrl
  });
  const oauth=new OAuthConnectionService(pool,keys,vault,transport,[provider],secrets);
  const githubLifecycle=new GitHubLifecycleService(vault,transport,limiter,secrets,config.githubClientId);
  return {identity,pool,limiter,vault,oauth,githubLifecycle,
    close:async()=>{await transport.close();await pool.end()}};
}
/** Will not bind a listening socket until database readiness succeeds. */
export async function startService(config:ServiceConfig,dependencies:ServiceDependencies):
  Promise<{server:Server;shutdown:()=>Promise<void>}> {
  const client=await dependencies.pool.connect();
  try{await client.query('SELECT 1')}finally{client.release()}
  const app=createServiceApp(config,dependencies);
  const server=await new Promise<Server>((resolve,reject)=>{
    const result=app.listen(config.port,'127.0.0.1');
    result.once('listening',()=>resolve(result));
    result.once('error',reject);
  });
  return {server,shutdown:async()=>{
    await new Promise<void>((resolve,reject)=>server.close(err=>err?reject(err):resolve()));
    await dependencies.close();
  }};
}

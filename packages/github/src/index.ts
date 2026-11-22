import type {Connector,ConnectorManifest,ExecutionContext,CapabilityRequest,CapabilityResult} from '../../connector-sdk/src/index.ts';
import type {OAuthVault,OAuthTokens} from '../../oauth/src/index.ts';
import type {ProviderTransport} from '../../rest-adapter/src/index.ts';
import type {ProviderRateLimiter} from '../../rate-limit/src/index.ts';

/**
 * GitHub.com account/profile discovery only.
 * No writes; no customer-supplied URL/path/header or arbitrary pagination link.
 * The transport must be createGuardedNetworkTransport({allowedOrigins:['https://api.github.com']}).
 */
export type GitHubReadCapability='github.profile.read'|'github.repositories.read';
export class GitHubProviderError extends Error {
  readonly code:'DENIED'|'UNAVAILABLE'|'RATE_LIMITED'|'INVALID_RESPONSE'|'TOKEN_EXPIRED';
  constructor(code:GitHubProviderError['code']){
    super('GitHub provider request denied or unavailable');
    this.code=code;this.name='GitHubProviderError';
  }
}
const isRecord=(x:unknown):x is Record<string,unknown>=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const nonblank=(x:unknown,max:number):x is string=>typeof x==='string'&&x.length>0&&x.length<=max;
const validToken=(value:unknown):value is string=>nonblank(value,8192)&&!/\s/.test(value);
const integer=(x:unknown)=>typeof x==='number'&&Number.isSafeInteger(x)&&x>=0;

export interface GitHubProfile {
  readonly id:number;
  readonly login:string;
  readonly name:string|null;
  readonly avatarUrl:string|null;
  readonly profileUrl:string;
}
export interface GitHubRepository {
  readonly id:number;
  readonly name:string;
  readonly fullName:string;
  readonly private:boolean;
  readonly defaultBranch:string|null;
  readonly htmlUrl:string;
}
function safeGithubUrl(v:unknown):string{
  if(!nonblank(v,2048))throw new GitHubProviderError('INVALID_RESPONSE');
  try {
    const u=new URL(v);
    if(u.origin!=='https://github.com'||u.username||u.password||u.hash)return '';
    return u.href;
  }catch{throw new GitHubProviderError('INVALID_RESPONSE')}
}
function profile(value:unknown):GitHubProfile{
  if(!isRecord(value)||!integer(value.id)||!nonblank(value.login,128)||
    !(value.name===null||value.name===undefined||typeof value.name==='string')||
    !(value.avatar_url===null||value.avatar_url===undefined||typeof value.avatar_url==='string'))
    throw new GitHubProviderError('INVALID_RESPONSE');
  return {id:value.id as number,login:value.login as string,
    name:typeof value.name==='string'?value.name:null,
    avatarUrl:typeof value.avatar_url==='string'?value.avatar_url:null,
    profileUrl:safeGithubUrl(value.html_url)};
}
function repos(value:unknown):GitHubRepository[]{
  if(!Array.isArray(value)||value.length>100)throw new GitHubProviderError('INVALID_RESPONSE');
  return value.map(v=>{
    if(!isRecord(v)||!integer(v.id)||!nonblank(v.name,256)||!nonblank(v.full_name,512)||
       typeof v.private!=='boolean'||
       !(v.default_branch===null||v.default_branch===undefined||nonblank(v.default_branch,256)))
      throw new GitHubProviderError('INVALID_RESPONSE');
    return {id:v.id as number,name:v.name as string,fullName:v.full_name as string,private:v.private,
      defaultBranch:typeof v.default_branch==='string'?v.default_branch:null,
      htmlUrl:safeGithubUrl(v.html_url)};
  });
}
async function boundedJson(response:Response):Promise<unknown>{
  if(!/^(application\/json|application\/[a-z0-9.+-]+\+json)(?:;|$)/i.test(
    (response.headers.get('content-type')??'').replace(/\s/g,'')))
    throw new GitHubProviderError('INVALID_RESPONSE');
  if(!response.body)throw new GitHubProviderError('INVALID_RESPONSE');
  const reader=response.body.getReader();
  const chunks:Uint8Array[]=[];let count=0;
  try{
    for(;;){
      const r=await reader.read();
      if(r.done)break;
      count+=r.value.byteLength;
      if(count>512*1024)throw new GitHubProviderError('INVALID_RESPONSE');
      chunks.push(r.value);
    }
  }finally{await reader.cancel().catch(()=>{})}
  try {return JSON.parse(Buffer.concat(chunks.map(x=>Buffer.from(x))).toString('utf8'))}
  catch{throw new GitHubProviderError('INVALID_RESPONSE')}
}
export class GitHubReadConnector implements Connector {
  readonly manifest:ConnectorManifest={
    id:'github.oauth',version:'1',state:'implemented',
    capabilities:['github.profile.read','github.repositories.read']
  };
  private readonly vault:Pick<OAuthVault,'withCredential'>;
  private readonly transport:ProviderTransport;
  private readonly limiter:ProviderRateLimiter;
  constructor(vault:Pick<OAuthVault,'withCredential'>,transport:ProviderTransport,limiter:ProviderRateLimiter) {
    this.vault=vault;this.transport=transport;this.limiter=limiter;
  }
  async healthCheck():Promise<'degraded'>{return 'degraded'}
  async execute(context:ExecutionContext,request:CapabilityRequest):Promise<CapabilityResult>{
    if(!context?.tenantId?.trim()||!context.connectionId?.trim()||!context.actorId?.trim()||
       !this.manifest.capabilities.includes(request?.capability)||
       !context.permittedCapabilities.includes(request.capability)||
       !isRecord(request.input)||Object.keys(request.input).length!==0)
      throw new GitHubProviderError('DENIED');
    const path=request.capability==='github.profile.read'?'/user':'/user/repos';
    const allowed=await this.limiter.acquire(context.tenantId,'github.oauth').catch(()=>{throw new GitHubProviderError('UNAVAILABLE')});
    if(!allowed)throw new GitHubProviderError('RATE_LIMITED');
    return this.vault.withCredential({tenantId:context.tenantId,connectionId:context.connectionId},
      'oauth_tokens',async bytes=>{
      let tokens:OAuthTokens;
      try{tokens=JSON.parse(bytes.toString('utf8')) as OAuthTokens}catch{throw new GitHubProviderError('DENIED')}
      if(!validToken(tokens?.access_token)||tokens.token_type!=='Bearer')
        throw new GitHubProviderError('DENIED');
      if(typeof tokens.expires_at==='number'&&tokens.expires_at<=Date.now()+30000)
        throw new GitHubProviderError('TOKEN_EXPIRED');
      let response:Response;
      try{
        response=await this.transport.send('https://api.github.com'+path,{
          method:'GET',redirect:'error',credentials:'omit',signal:AbortSignal.timeout(7000),
          headers:{
            accept:'application/vnd.github+json',
            authorization:'Bearer '+tokens.access_token,
            'x-github-api-version':'2022-11-28',
            'user-agent':'TrillionAI-Universal-Connect'
          }
        });
      }catch{throw new GitHubProviderError('UNAVAILABLE')}
      if(response.status===401)throw new GitHubProviderError('TOKEN_EXPIRED');
      if(response.status===403||response.status===429)throw new GitHubProviderError('RATE_LIMITED');
      if(!response.ok)throw new GitHubProviderError('UNAVAILABLE');
      const json=await boundedJson(response);
      return {
        data:request.capability==='github.profile.read'?profile(json):repos(json),
        providerRequestId:response.headers.get('x-github-request-id')??undefined
      };
    });
  }
}

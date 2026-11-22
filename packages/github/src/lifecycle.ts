import type {OAuthClientSecrets,OAuthVault,OAuthTokens} from '../../oauth/src/index.ts';
import type {ProviderTransport} from '../../rest-adapter/src/index.ts';
import type {ProviderRateLimiter} from '../../rate-limit/src/index.ts';
import type {VaultScope} from '../../vault/src/index.ts';

export type GitHubHealth='connected'|'reconnect_required'|'unavailable';
export class GitHubLifecycleError extends Error {
  constructor(){super('GitHub connection verification unavailable');this.name='GitHubLifecycleError'}
}
export interface GitHubLifecycle {
  check(scope:VaultScope):Promise<GitHubHealth>;
  /** Only returns on GitHub-confirmed revocation (204), never a local-only success. */
  revoke(scope:VaultScope):Promise<void>;
}
const validToken=(s:unknown):s is string=>typeof s==='string'&&s.length>0&&s.length<=8192&&!/\s/.test(s);
function parseTokens(raw:Buffer):OAuthTokens {
  let parsed:unknown;
  try{parsed=JSON.parse(raw.toString('utf8'))}catch{throw new GitHubLifecycleError()}
  if(!parsed||typeof parsed!=='object'||!validToken((parsed as OAuthTokens).access_token)||
    (parsed as OAuthTokens).token_type!=='Bearer')throw new GitHubLifecycleError();
  return parsed as OAuthTokens;
}
export class GitHubLifecycleService implements GitHubLifecycle {
  constructor(
    private readonly vault:Pick<OAuthVault,'withCredential'>,
    private readonly transport:ProviderTransport,
    private readonly limiter:Pick<ProviderRateLimiter,'acquire'>,
    private readonly secrets:OAuthClientSecrets,
    private readonly clientId:string
  ) {
    if(!/^[A-Za-z0-9_-]{8,128}$/.test(clientId))throw new GitHubLifecycleError();
  }
  private async quota(scope:VaultScope):Promise<void>{
    const permitted=await this.limiter.acquire(scope.tenantId,'github.oauth.lifecycle').catch(()=>false);
    if(!permitted)throw new GitHubLifecycleError();
  }
  async check(scope:VaultScope):Promise<GitHubHealth>{
    await this.quota(scope);
    return this.vault.withCredential(scope,'oauth_tokens',async bytes=>{
      const tokens=parseTokens(bytes);
      if(typeof tokens.expires_at==='number'&&tokens.expires_at<=Date.now())return 'reconnect_required';
      let response:Response;
      try{
        response=await this.transport.send('https://api.github.com/user',{
          method:'GET',redirect:'error',credentials:'omit',signal:AbortSignal.timeout(6000),
          headers:{accept:'application/vnd.github+json',authorization:'Bearer '+tokens.access_token,
            'x-github-api-version':'2022-11-28','user-agent':'TrillionAI-Universal-Connect'}
        });
      }catch{return 'unavailable'}
      await response.body?.cancel().catch(()=>{});
      if(response.status===200)return 'connected';
      if(response.status===401)return 'reconnect_required';
      // 403 can mean rate-limit or organization SSO restrictions, not revocation.
      return 'unavailable';
    });
  }
  async revoke(scope:VaultScope):Promise<void>{
    await this.quota(scope);
    await this.vault.withCredential(scope,'oauth_tokens',async bytes=>{
      const tokens=parseTokens(bytes);
      await this.secrets.withClientSecret('github.oauth',async secret=>{
        if(secret.length<1||secret.length>8192)throw new GitHubLifecycleError();
        const auth=Buffer.from(this.clientId+':'+secret.toString('utf8')).toString('base64');
        let response:Response;
        try{
          response=await this.transport.send(
            'https://api.github.com/applications/'+encodeURIComponent(this.clientId)+'/token',{
              method:'DELETE',redirect:'error',credentials:'omit',signal:AbortSignal.timeout(8000),
              headers:{accept:'application/vnd.github+json',
                authorization:'Basic '+auth,'content-type':'application/json',
                'x-github-api-version':'2022-11-28','user-agent':'TrillionAI-Universal-Connect'},
              body:JSON.stringify({access_token:tokens.access_token})
            });
        }catch{throw new GitHubLifecycleError()}
        await response.body?.cancel().catch(()=>{});
        if(response.status!==204)throw new GitHubLifecycleError();
      });
    });
  }
}

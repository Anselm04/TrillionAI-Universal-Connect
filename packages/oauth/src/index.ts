import {createHash,randomBytes} from 'node:crypto';
import {isIP} from 'node:net';
import {inTenantTransaction,type TenantPool} from '../../persistence/src/index.ts';
import {encryptCredential,decryptCredential,type VaultKeyProvider,type VaultScope} from '../../vault/src/index.ts';
import type {Principal} from '../../gateway/src/index.ts';
import type {ProviderTransport} from '../../rest-adapter/src/index.ts';

export interface OAuthProvider {
  readonly id:string;
  readonly authorizationUrl:string;
  readonly tokenUrl:string;
  readonly clientId:string;
  readonly redirectUri:string;
  readonly scopes:readonly string[];
  readonly revokeUrl?:string;
  /** Set for confidential OAuth providers such as GitHub.com. */
  readonly requiresClientSecret?:boolean;
}
export interface OAuthClientSecrets {
  /** Secret is obtained only on a trusted backend. Wipe the Buffer after callback. */
  withClientSecret<T>(providerId:string,use:(secret:Buffer)=>Promise<T>):Promise<T>;
}
export interface OAuthVault {
  put(scope:VaultScope,name:string,plaintext:Buffer):Promise<void>;
  withCredential<T>(scope:VaultScope,name:string,fn:(secret:Buffer)=>Promise<T>):Promise<T>;
  revoke(scope:VaultScope,name:string):Promise<boolean>;
}
export interface OAuthTokens {
  readonly access_token:string;
  readonly refresh_token?:string;
  readonly token_type:'Bearer';
  readonly expires_at?:number;
  readonly scope?:string;
}
export class OAuthError extends Error {
  readonly code:'INVALID'|'DENIED'|'UNAVAILABLE'|'UPSTREAM';
  constructor(code:OAuthError['code']){super('OAuth operation denied or unavailable');this.name='OAuthError';this.code=code}
}
const validId=(s:unknown):s is string=>typeof s==='string'&&/^[a-z][a-z0-9._-]{1,127}$/.test(s);
const validScope=(s:unknown):s is string=>typeof s==='string'&&s.length>0&&s.length<=128&&/^[a-zA-Z0-9.:/_-]+$/.test(s);
const requiredString=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=8192;
const sha=(s:string):string=>createHash('sha256').update(s).digest('hex');
const url64=(bytes:Buffer):string=>bytes.toString('base64url');
function validateProvider(provider:OAuthProvider):void {
  if(!validId(provider.id)||!requiredString(provider.clientId)||provider.clientId.length>256||
    !Array.isArray(provider.scopes)||provider.scopes.length>32||provider.scopes.some(s=>!validScope(s)))throw new OAuthError('INVALID');
  for(const value of [provider.authorizationUrl,provider.tokenUrl,provider.redirectUri,...(provider.revokeUrl?[provider.revokeUrl]:[])]){
    let url:URL;
    try{url=new URL(value)}catch{throw new OAuthError('INVALID')}
    if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search||url.port||
      !url.hostname.includes('.')||isIP(url.hostname)!==0||
      url.hostname==='localhost'||url.hostname.endsWith('.local')||
      url.hostname.endsWith('.internal')||url.hostname.endsWith('.localhost'))throw new OAuthError('INVALID');
  }
  if(provider.authorizationUrl===provider.tokenUrl)throw new OAuthError('INVALID');
}
function tokensFromJson(json:unknown,previous?:OAuthTokens):OAuthTokens {
  if(!json||typeof json!=='object'||Array.isArray(json))throw new OAuthError('UPSTREAM');
  const data=json as Record<string,unknown>;
  if(!requiredString(data.access_token)||typeof data.token_type!=='string'||data.token_type.toLowerCase()!=='bearer')throw new OAuthError('UPSTREAM');
  if(data.refresh_token!==undefined&&!requiredString(data.refresh_token))throw new OAuthError('UPSTREAM');
  if(data.expires_in!==undefined&&(!Number.isInteger(data.expires_in)||Number(data.expires_in)<1||Number(data.expires_in)>31536000))throw new OAuthError('UPSTREAM');
  return {
    access_token:data.access_token,
    token_type:'Bearer',
    ...((data.refresh_token||previous?.refresh_token)?{refresh_token:(data.refresh_token as string|undefined)??previous?.refresh_token}:{}),
    ...(data.expires_in!==undefined?{expires_at:Date.now()+Number(data.expires_in)*1000}:{}),
    ...(typeof data.scope==='string'&&data.scope.length<4096?{scope:data.scope}:{})
  };
}
async function readTokenResponse(response:Response):Promise<unknown>{
  if(!response.ok)throw new OAuthError('UPSTREAM');
  const ct=response.headers.get('content-type')??'';
  if(!/^application\/json(?:\s*;|$)/i.test(ct))throw new OAuthError('UPSTREAM');
  const max=16384;
  if(Number(response.headers.get('content-length'))>max)throw new OAuthError('UPSTREAM');
  if(!response.body)throw new OAuthError('UPSTREAM');
  const reader=response.body.getReader();const data:Uint8Array[]=[];let len=0;
  try{while(true){const r=await reader.read();if(r.done)break;len+=r.value.byteLength;if(len>max)throw new OAuthError('UPSTREAM');data.push(r.value)}}finally{await reader.cancel().catch(()=>{})}
  try{return JSON.parse(Buffer.concat(data.map(x=>Buffer.from(x))).toString('utf8'))}catch{throw new OAuthError('UPSTREAM')}
}
export class OAuthConnectionService {
  private readonly pool:TenantPool;
  private readonly keys:VaultKeyProvider;
  private readonly vault:OAuthVault;
  private readonly transport:ProviderTransport;
  private readonly providers:Map<string,OAuthProvider>;
  private readonly clientSecrets?:OAuthClientSecrets;
  constructor(pool:TenantPool,keys:VaultKeyProvider,vault:OAuthVault,transport:ProviderTransport,providers:readonly OAuthProvider[],clientSecrets?:OAuthClientSecrets) {
    this.pool=pool;this.keys=keys;this.vault=vault;this.transport=transport;this.clientSecrets=clientSecrets;
    this.providers=new Map();
    for(const p of providers){validateProvider(p);if(this.providers.has(p.id)|| (p.requiresClientSecret&&!clientSecrets))throw new OAuthError('INVALID');this.providers.set(p.id,p)}
  }
  private provider(providerId:string):OAuthProvider{
    const value=this.providers.get(providerId);if(!value)throw new OAuthError('DENIED');return value;
  }
  private validate(principal:Principal,scope:VaultScope):void{
    if(!principal?.subject?.trim()||!principal.tenantId?.trim()||!scope?.connectionId?.trim()||
      principal.tenantId!==scope.tenantId)throw new OAuthError('DENIED');
  }
  private async connectionAuthorized(principal:Principal,scope:VaultScope,providerId:string):Promise<boolean>{
    return inTenantTransaction(this.pool,scope.tenantId,async client=>{
      const r=await client.query(`SELECT 1 FROM universal_connect.connections
         WHERE id=$1 AND tenant_id=$2 AND connector_id=$3 AND enabled=true`,
         [scope.connectionId,scope.tenantId,providerId]);
      return r.rowCount===1;
    });
  }
  async begin(principal:Principal,scope:VaultScope,providerId:string):Promise<{url:string;state:string}>{
    this.validate(principal,scope);
    const p=this.provider(providerId);
    if(!await this.connectionAuthorized(principal,scope,providerId))throw new OAuthError('DENIED');
    const verifier=url64(randomBytes(32)),state=url64(randomBytes(32));
    const challenge=url64(createHash('sha256').update(verifier).digest());
    const version=await this.keys.currentVersion();
    const key=await this.keys.keyForVersion(version);
    const enc=await encryptCredential(Buffer.from(verifier),key,scope,'oauth_pkce',version);
    await inTenantTransaction(this.pool,scope.tenantId,async client=>{
      await client.query(`INSERT INTO universal_connect.oauth_pending
       (state_hash,tenant_id,actor_id,connection_id,provider_id,verifier_version,
        verifier_nonce,verifier_tag,verifier_ciphertext,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '10 minutes')`,
       [sha(state),scope.tenantId,principal.subject,scope.connectionId,providerId,version,enc.nonce,enc.tag,enc.ciphertext]);
    });
    const target=new URL(p.authorizationUrl);
    target.searchParams.set('response_type','code');
    target.searchParams.set('client_id',p.clientId);
    target.searchParams.set('redirect_uri',p.redirectUri);
    target.searchParams.set('scope',p.scopes.join(' '));
    target.searchParams.set('state',state);
    target.searchParams.set('code_challenge',challenge);
    target.searchParams.set('code_challenge_method','S256');
    return {url:target.toString(),state};
  }
  private async postToken(p:OAuthProvider,params:URLSearchParams,previous?:OAuthTokens):Promise<OAuthTokens>{
    const send=async(secret?:Buffer):Promise<OAuthTokens>=>{
      const body=new URLSearchParams(params);
      if(p.requiresClientSecret){
        if(!secret||!requiredString(secret.toString('utf8'))||/[\r\n]/.test(secret.toString('utf8')))
          throw new OAuthError('UNAVAILABLE');
        body.set('client_secret',secret.toString('utf8'));
      }
      const response=await this.transport.send(p.tokenUrl,{
        method:'POST',redirect:'error',credentials:'omit',
        headers:{accept:'application/json','content-type':'application/x-www-form-urlencoded'},
        body:body.toString(),signal:AbortSignal.timeout(8000)
      });
      return tokensFromJson(await readTokenResponse(response),previous);
    };
    if(p.requiresClientSecret){
      if(!this.clientSecrets)throw new OAuthError('UNAVAILABLE');
      return this.clientSecrets.withClientSecret(p.id,buffer=>send(buffer));
    }
    return send();
  }
  async complete(principal:Principal,scope:VaultScope,providerId:string,state:string,code:string):Promise<void>{
    this.validate(principal,scope);
    const p=this.provider(providerId);
    if(!requiredString(state)||state.length>128||!requiredString(code)||code.length>2048)
      throw new OAuthError('INVALID');
    // State is consumed atomically *before* remote exchange to prevent callback replay.
    const row=await inTenantTransaction(this.pool,scope.tenantId,async client=>{
      const r=await client.query(`UPDATE universal_connect.oauth_pending SET consumed_at=clock_timestamp()
        WHERE state_hash=$1 AND tenant_id=$2 AND actor_id=$3 AND connection_id=$4
          AND provider_id=$5 AND consumed_at IS NULL AND expires_at>clock_timestamp()
        RETURNING verifier_version,verifier_nonce,verifier_tag,verifier_ciphertext`,
        [sha(state),scope.tenantId,principal.subject,scope.connectionId,providerId]);
      return r.rows[0] as Record<string,unknown>|undefined;
    });
    if(!row)throw new OAuthError('DENIED');
    if(!await this.connectionAuthorized(principal,scope,providerId))throw new OAuthError('DENIED');
    const key=await this.keys.keyForVersion(row.verifier_version as string);
    const verifier=await decryptCredential({
      id:'pending',keyVersion:row.verifier_version as string,nonce:row.verifier_nonce as Buffer,
      tag:row.verifier_tag as Buffer,ciphertext:row.verifier_ciphertext as Buffer
    },key,scope,'oauth_pkce');
    try{
      const form=new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:p.redirectUri,
        client_id:p.clientId,code_verifier:verifier.toString('utf8')});
      const tokens=await this.postToken(p,form);
      const payload=Buffer.from(JSON.stringify(tokens));
      try{await this.vault.put(scope,'oauth_tokens',payload)}finally{payload.fill(0)}
    }finally{verifier.fill(0)}
  }
  async refresh(principal:Principal,scope:VaultScope,providerId:string):Promise<void>{
    this.validate(principal,scope);const p=this.provider(providerId);
    if(!await this.connectionAuthorized(principal,scope,providerId))throw new OAuthError('DENIED');
    // A database advisory lock prevents two workers from rotating a refresh token simultaneously.
    await inTenantTransaction(this.pool,scope.tenantId,async client=>{
      const lock=await client.query(`SELECT pg_try_advisory_xact_lock(hashtextextended($1,0)) AS acquired`,
        [JSON.stringify([scope.tenantId,scope.connectionId,'oauth_refresh'])]);
      if(lock.rows[0]?.acquired!==true)throw new OAuthError('UNAVAILABLE');
      await this.vault.withCredential(scope,'oauth_tokens',async raw=>{
        let existing:OAuthTokens;
        try{existing=JSON.parse(raw.toString('utf8')) as OAuthTokens}catch{throw new OAuthError('UNAVAILABLE')}
        if(!requiredString(existing.refresh_token))throw new OAuthError('DENIED');
        const form=new URLSearchParams({grant_type:'refresh_token',refresh_token:existing.refresh_token,client_id:p.clientId});
        const renewed=await this.postToken(p,form,existing);
        const payload=Buffer.from(JSON.stringify(renewed));
        try{await this.vault.put(scope,'oauth_tokens',payload)}finally{payload.fill(0)}
      });
    });
  }
  async disconnect(principal:Principal,scope:VaultScope,providerId:string):Promise<boolean>{
    this.validate(principal,scope);const p=this.provider(providerId);
    if(!await this.connectionAuthorized(principal,scope,providerId))throw new OAuthError('DENIED');
    if(p.revokeUrl){
      await this.vault.withCredential(scope,'oauth_tokens',async raw=>{
        let tokens:OAuthTokens;
        try{tokens=JSON.parse(raw.toString('utf8')) as OAuthTokens}catch{throw new OAuthError('UNAVAILABLE')}
        const response=await this.transport.send(p.revokeUrl!,{
          method:'POST',redirect:'error',credentials:'omit',signal:AbortSignal.timeout(8000),
          headers:{'content-type':'application/x-www-form-urlencoded'},
          body:new URLSearchParams({token:tokens.refresh_token??tokens.access_token,client_id:p.clientId}).toString()
        });
        if(!response.ok)throw new OAuthError('UPSTREAM');
        await response.body?.cancel().catch(()=>{});
      });
    }
    return this.vault.revoke(scope,'oauth_tokens');
  }
}

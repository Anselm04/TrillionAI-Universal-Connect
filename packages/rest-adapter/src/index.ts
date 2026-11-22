import {setTimeout as sleep} from 'node:timers/promises';
import type {Connector,ConnectorManifest,ExecutionContext,CapabilityRequest,CapabilityResult} from '../../connector-sdk/src/index.ts';
import type {PostgresCredentialVault,VaultScope} from '../../vault/src/index.ts';

/** A fixed provider-origin transport must enforce DNS/IP policy at the egress layer.
 * Never forward caller-supplied URLs, hosts, headers or methods to this transport. */
export interface ProviderTransport {
  send(url:string, init:RequestInit):Promise<Response>;
}
export type ProviderOperation = Readonly<{
  capability:'records.read'|'records.write';
  method:'GET'|'POST';
  path:string;
}>;
export interface RestAdapterConfig {
  readonly id:string;
  readonly origin:string;
  readonly operations:readonly ProviderOperation[];
  readonly verified:boolean;
  readonly maxResponseBytes?:number;
  readonly timeoutMs?:number;
  readonly retries?:number;
  readonly credentialName?:string;
}
export class ProviderRequestError extends Error {
  readonly code:'CONFIG'|'DENIED'|'UPSTREAM'|'RESPONSE_INVALID'|'RATE_LIMITED';
  constructor(code:ProviderRequestError['code'], message:string) {
    super(message); this.code=code; this.name='ProviderRequestError';
  }
}
export type CredentialRunner = <T>(scope:VaultScope,name:string,use:(secret:Buffer)=>Promise<T>)=>Promise<T>;
const allowedPath=(s:string):boolean=> /^\/[a-zA-Z0-9/_-]{0,255}$/.test(s) && !s.includes('//') && !s.split('/').includes('..');
const allowId=(s:string):boolean=>/^[a-z][a-z0-9._-]{1,127}$/.test(s);
const isRecord=(x:unknown):x is Record<string,unknown>=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
export function providerOrigin(value:string):string {
  let u:URL;
  try {u=new URL(value)} catch {throw new ProviderRequestError('CONFIG','Invalid provider origin')}
  if (u.protocol!=='https:' || !u.hostname || u.username || u.password || u.search ||
    u.hash || u.pathname!=='/' || u.port || !/^[a-z0-9.-]+$/i.test(u.hostname) ||
    u.hostname==='localhost' || u.hostname.endsWith('.local') || u.hostname.endsWith('.internal') ||
    u.hostname.endsWith('.localhost') || /^\d+\.\d+\.\d+\.\d+$/.test(u.hostname) ||
    !u.hostname.includes('.')) throw new ProviderRequestError('CONFIG','Only preapproved HTTPS DNS origins are supported');
  return u.origin;
}
function cleanConfig(config:RestAdapterConfig) {
  if(!allowId(config.id)||!config.operations?.length||config.operations.length>32||
    config.operations.some(o=>!allowedPath(o.path) ||
      (o.capability==='records.read'&&o.method!=='GET')||
      (o.capability==='records.write'&&o.method!=='POST')||
      !['records.read','records.write'].includes(o.capability))||
    new Set(config.operations.map(o=>o.capability)).size!==config.operations.length ||
    (config.maxResponseBytes!==undefined&&(!Number.isInteger(config.maxResponseBytes)||config.maxResponseBytes<1||config.maxResponseBytes>1048576))||
    (config.timeoutMs!==undefined&&(!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>30000))||
    (config.retries!==undefined&&(!Number.isInteger(config.retries)||config.retries<0||config.retries>2))||
    (config.credentialName!==undefined&&!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(config.credentialName)))
    throw new ProviderRequestError('CONFIG','Invalid adapter configuration');
  return providerOrigin(config.origin);
}
async function readBounded(response:Response,limit:number):Promise<unknown>{
  if(!/^application\/(json|[a-z0-9.+-]+\+json)(?:\s*;|$)/i.test(response.headers.get('content-type')||'')) throw new ProviderRequestError('RESPONSE_INVALID','Provider did not return JSON');
  if(!response.body)throw new ProviderRequestError('RESPONSE_INVALID','Empty provider response');
  const reader=response.body.getReader();const parts:Uint8Array[]=[];let total=0;
  try{
    while(true){const {done,value}=await reader.read();if(done)break;
      total+=value.byteLength;
      if(total>limit)throw new ProviderRequestError('RESPONSE_INVALID','Provider response too large');
      parts.push(value);
    }
  }finally{await reader.cancel().catch(()=>{});}
  try{return JSON.parse(Buffer.concat(parts.map(v=>Buffer.from(v))).toString('utf8'))}
  catch{throw new ProviderRequestError('RESPONSE_INVALID','Invalid provider JSON')}
}
/** Explicitly approved provider configurations only; no dynamic outbound URL routing. */
export class FixedRestConnector implements Connector {
  readonly manifest:ConnectorManifest;
  private readonly origin:string;
  private readonly config:RestAdapterConfig;
  private readonly transport:ProviderTransport;
  private readonly credential?:CredentialRunner;
  constructor(config:RestAdapterConfig,transport:ProviderTransport,credential?:CredentialRunner) {
    this.origin=cleanConfig(config);
    this.config=config;this.transport=transport;this.credential=credential;
    this.manifest={id:config.id,version:'1',state:config.verified?'verified':'implemented',
      capabilities:config.operations.map(x=>x.capability)};
    if(config.credentialName && !credential)throw new ProviderRequestError('CONFIG','Credential provider required');
  }
  async healthCheck():Promise<'healthy'|'degraded'|'unavailable'>{
    // No unapproved network calls from health checks; monitor via separate authorized probes.
    return 'degraded';
  }
  async execute(context:ExecutionContext,request:CapabilityRequest):Promise<CapabilityResult>{
    const operation=this.config.operations.find(o=>o.capability===request.capability);
    if(!operation||!context.permittedCapabilities.includes(request.capability))
      throw new ProviderRequestError('DENIED','Capability not permitted');
    if(!isRecord(request.input))throw new ProviderRequestError('DENIED','Input must be a JSON object');
    if(operation.method==='POST'&&(!context.approvalId||!request.idempotencyKey ||
      !/^[a-zA-Z0-9_-]{8,128}$/.test(request.idempotencyKey)))
      throw new ProviderRequestError('DENIED','Approved write and idempotency key required');
    const perform=async(secret?:Buffer):Promise<CapabilityResult>=>{
      const headers:Record<string,string>={'accept':'application/json'};
      if(operation.method==='POST'){
        headers['content-type']='application/json';
        headers['idempotency-key']=request.idempotencyKey!;
      }
      if(secret){
        // Third party Authorization header API requires a string; never log it.
        const token=secret.toString('utf8');
        if(!token||/[\r\n]/.test(token))throw new ProviderRequestError('DENIED','Invalid credential');
        headers.authorization='Bearer '+token;
      }
      const body=operation.method==='POST'?JSON.stringify(request.input):undefined;
      const url=this.origin+operation.path;
      const attempts=operation.method==='GET'?1+(this.config.retries??1):1;
      for(let i=0;i<attempts;i++){
        const controller=new AbortController();
        const timeout=setTimeout(()=>controller.abort(),this.config.timeoutMs??5000);
        try{
          const res=await this.transport.send(url,{method:operation.method,headers,
            ...(body?{body}:{}),signal:controller.signal,redirect:'error',credentials:'omit'});
          if(res.status===429) {
            if(i+1<attempts){await res.body?.cancel().catch(()=>{});await sleep(100*(i+1));continue}
            throw new ProviderRequestError('RATE_LIMITED','Provider rate limited the request');
          }
          if([502,503,504].includes(res.status)&&i+1<attempts){
            await res.body?.cancel().catch(()=>{});
            await sleep(100*(i+1));continue;
          }
          if(!res.ok)throw new ProviderRequestError('UPSTREAM','Provider request unsuccessful');
          const data=await readBounded(res,this.config.maxResponseBytes??262144);
          return {data,providerRequestId:res.headers.get('x-request-id')??undefined};
        }catch(error) {
          if(error instanceof ProviderRequestError)throw error;
          // No retry on indeterminate transport failures: operation may have reached provider.
          throw new ProviderRequestError('UPSTREAM','Provider request unavailable');
        }finally{clearTimeout(timeout)}
      }
      throw new ProviderRequestError('UPSTREAM','Provider request unsuccessful');
    };
    if(!this.config.credentialName)return perform();
    if(!this.credential)throw new ProviderRequestError('DENIED','Credential backend unavailable');
    return this.credential({tenantId:context.tenantId,connectionId:context.connectionId},
      this.config.credentialName,secret=>perform(secret));
  }
}
export function vaultCredentialRunner(vault:Pick<PostgresCredentialVault,'withCredential'>):CredentialRunner{
  return (scope,name,use)=>vault.withCredential(scope,name,use);
}
/** Default production network transport MUST use a separately hardened egress proxy.
 * This fetch transport is suitable only for fixed infrastructure-approved origins
 * with DNS/IP allowlisting and private-network blocking enforced outside this process. */
export const networkTransport:ProviderTransport={send:(url,init)=>fetch(url,init)};

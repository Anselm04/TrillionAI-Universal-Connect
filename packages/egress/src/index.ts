import { lookup as systemLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { Agent, fetch as undiciFetch } from 'undici';
import ipaddr from 'ipaddr.js';
import type { ProviderTransport } from '../../rest-adapter/src/index.ts';

export class EgressDenied extends Error {
  constructor() { super('Outbound destination denied by network policy'); this.name='EgressDenied'; }
}
export type ResolvedAddress={address:string;family:number};
export type AddressResolver=(hostname:string)=>Promise<ResolvedAddress[]>;
const defaultResolver:AddressResolver=hostname=>systemLookup(hostname,{all:true,verbatim:true});

/** Reject private, loopback, link-local, reserved, CGNAT, multicast and IPv4-mapped private ranges. */
export function isPublicAddress(address:string):boolean {
  try {
    if(!isIP(address))return false;
    const parsed=ipaddr.parse(address);
    if(parsed.kind()==='ipv6' && parsed.isIPv4MappedAddress()) {
      return parsed.toIPv4Address().range()==='unicast';
    }
    return parsed.range()==='unicast';
  }catch{return false}
}
export async function resolvePublicAddresses(hostname:string,resolver:AddressResolver=defaultResolver):Promise<ResolvedAddress[]> {
  // IDNs/aliases should be configured as DNS names, not literal IPs or local hosts.
  if(!/^[a-z0-9.-]+$/i.test(hostname)||!hostname.includes('.')||isIP(hostname)||
    hostname.toLowerCase()==='localhost' || hostname.endsWith('.local') ||
    hostname.endsWith('.localhost') || hostname.endsWith('.internal'))throw new EgressDenied();
  let records:ResolvedAddress[];
  try {records=await resolver(hostname)}catch{throw new EgressDenied()}
  if(!Array.isArray(records)||records.length<1||records.length>64 ||
    records.some(r=>!r|| ![4,6].includes(r.family)||isIP(r.address)!==r.family||!isPublicAddress(r.address)))
    throw new EgressDenied();
  return records;
}
export interface EgressOptions {
  /** Independently configured, approved HTTPS origins (no client-supplied destinations). */
  readonly allowedOrigins:readonly string[];
  /** Dependency injection for deterministic unit tests. */
  readonly resolver?:AddressResolver;
}
/** Undici socket lookup validates the EXACT DNS answer passed to connect(), avoiding
 * an unsafe pre-flight DNS check followed by a second unchecked resolver lookup.
 * Redirects are disabled and only explicitly configured origins can be requested. */
export function createGuardedNetworkTransport(options:EgressOptions):ProviderTransport&{close():Promise<void>} {
  if(!options.allowedOrigins?.length ||options.allowedOrigins.length>64)throw new EgressDenied();
  const allow=new Set<string>();
  for(const item of options.allowedOrigins){
    let parsed:URL;
    try{parsed=new URL(item)}catch{throw new EgressDenied()}
    if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.search||parsed.hash||
      parsed.pathname!=='/'||parsed.port||!parsed.hostname.includes('.')||
      isIP(parsed.hostname)||parsed.hostname.endsWith('.internal')||parsed.hostname.endsWith('.local'))
      throw new EgressDenied();
    allow.add(parsed.origin);
  }
  const agent=new Agent({
    connect:{
      lookup:(hostname,lookupOptions,callback)=>{
        void resolvePublicAddresses(hostname,options.resolver??defaultResolver).then(records=>{
          if(lookupOptions.all)callback(null,records);
          else callback(null,records[0]!.address,records[0]!.family);
        },()=>callback(new EgressDenied(),'',4));
      },
    },
    maxRedirections:0,
  });
  return {
    async send(url:string, init:RequestInit):Promise<Response>{
      let parsed:URL;
      try{parsed=new URL(url)}catch{throw new EgressDenied()}
      if(!allow.has(parsed.origin)||parsed.protocol!=='https:'||parsed.username||parsed.password||
        parsed.hash || parsed.search)throw new EgressDenied();
      if(init.redirect && init.redirect!=='error')throw new EgressDenied();
      // Explicit, private dispatcher: do not rely on process-wide fetch or proxy settings.
      const response=await undiciFetch(url,{
        method:init.method,
        headers:init.headers as Record<string,string>,
        body:init.body as string|undefined,
        signal:init.signal??undefined,
        redirect:'error',
        dispatcher:agent
      });
      return response as unknown as Response;
    },
    close:()=>agent.close(),
  };
}

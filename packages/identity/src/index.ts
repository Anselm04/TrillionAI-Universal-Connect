import { createClient } from '@supabase/supabase-js';
import type { Principal } from '../../gateway/src/index.ts';

export type OrganisationRole = 'owner' | 'admin' | 'staff' | 'customer';
export class IdentityBoundaryError extends Error {
  readonly code: 'UNAUTHENTICATED' | 'FORBIDDEN' | 'IDENTITY_UNAVAILABLE';
  constructor(code: IdentityBoundaryError['code'], message: string) {
    super(message);
    this.code = code;
    this.name = 'IdentityBoundaryError';
  }
}
export interface VerifiedIdentity {
  readonly principal: Principal;
  readonly organisationRole: OrganisationRole;
}
export interface IdentityAuth {
  getUser(token: string): Promise<{ user: {id:string; email_confirmed_at?: string|null}|null; error?: unknown }>;
}
export interface IdentityDirectory {
  sessionActive(userId: string, sessionId: string): Promise<{active:boolean|null; error?:unknown}>;
  member(userId: string, tenantId: string): Promise<{
    membership: {role:OrganisationRole; status:string}|null; error?:unknown
  }>;
}
export interface IdentityDependencies {
  readonly auth: IdentityAuth;
  readonly directory: IdentityDirectory;
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Only call after getUser() independently verified the actual access token. */
function validatedSessionClaims(token:string, subject:string): { sessionId:string; aal:string }|null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some(p=>!p)) return null;
    const claims: unknown = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return null;
    const payload = claims as Record<string,unknown>;
    // Identity prohibits OAuth client-bound tokens in its account security endpoints.
    if (Object.hasOwn(payload,'client_id') || payload.sub !== subject ||
       typeof payload.session_id !== 'string' || !uuid.test(payload.session_id)) return null;
    if (payload.aal !== 'aal1' && payload.aal !== 'aal2') return null;
    return {sessionId:payload.session_id,aal:payload.aal};
  } catch { return null; }
}
const identityProblem = (code: IdentityBoundaryError['code'], msg: string) =>
  new IdentityBoundaryError(code,msg);

export class SupabaseIdentityBoundary {
  private readonly dependencies: IdentityDependencies;
  constructor(dependencies:IdentityDependencies) { this.dependencies = dependencies; }
  async authenticate(accessToken: string, tenantId:string):Promise<VerifiedIdentity> {
    if (typeof accessToken !== 'string' || accessToken.length < 12 || accessToken.length > 16384 ||
        typeof tenantId !== 'string' || !uuid.test(tenantId)) {
      throw identityProblem('UNAUTHENTICATED', 'Invalid identity token or organization');
    }
    let user: Awaited<ReturnType<IdentityAuth['getUser']>>['user'];
    try {
      const verified = await this.dependencies.auth.getUser(accessToken);
      if (verified.error || !verified.user) throw identityProblem('UNAUTHENTICATED', 'Invalid bearer token');
      user = verified.user;
    } catch (err) {
      if (err instanceof IdentityBoundaryError) throw err;
      throw identityProblem('IDENTITY_UNAVAILABLE','Identity verification unavailable');
    }
    if (!user.id || !uuid.test(user.id) || !user.email_confirmed_at)
      throw identityProblem('FORBIDDEN','Verified email is required');
    const verifiedClaims = validatedSessionClaims(accessToken,user.id);
    if (!verifiedClaims) throw identityProblem('UNAUTHENTICATED','Invalid session-bound access token');

    let active:boolean|null;
    try {
      const result = await this.dependencies.directory.sessionActive(user.id,verifiedClaims.sessionId);
      if (result.error || typeof result.active !== 'boolean')
        throw identityProblem('IDENTITY_UNAVAILABLE','Session validation unavailable');
      active=result.active;
    } catch(err) {
      if(err instanceof IdentityBoundaryError) throw err;
      throw identityProblem('IDENTITY_UNAVAILABLE','Session validation unavailable');
    }
    if (!active) throw identityProblem('UNAUTHENTICATED','Session revoked');

    let member: Awaited<ReturnType<IdentityDirectory['member']>>['membership'];
    try {
      const result = await this.dependencies.directory.member(user.id,tenantId);
      if (result.error) throw identityProblem('IDENTITY_UNAVAILABLE','Membership lookup unavailable');
      member=result.membership;
    } catch(err) {
      if(err instanceof IdentityBoundaryError) throw err;
      throw identityProblem('IDENTITY_UNAVAILABLE','Membership lookup unavailable');
    }
    if(!member || member.status!=='active' || !['owner','admin','staff','customer'].includes(member.role))
      throw identityProblem('FORBIDDEN','Active organization membership required');

    // Claims are inspected only after getUser verified the bearer AND active session RPC.
    const assurance = verifiedClaims.aal;
    // An elevated organization role requires MFA just as privileged Identity routes do.
    if ((member.role==='owner'||member.role==='admin') && assurance !== 'aal2')
      throw identityProblem('FORBIDDEN','Elevated tenant role requires MFA');
    return {
      principal:{subject:user.id,tenantId,assuranceLevel:assurance==='aal2'?2:1},
      organisationRole:member.role
    };
  }
}
/** Real adapter for the same Supabase Auth authority and RPC used by TrillionAI Identity. */
export function makeSupabaseIdentityBoundary(config:{
  supabaseUrl:string; publishableKey:string; serviceRoleKey:string
}):SupabaseIdentityBoundary {
  if (!config.supabaseUrl?.startsWith('https://') ||
      !config.publishableKey?.trim() || !config.serviceRoleKey?.trim() ||
      config.publishableKey===config.serviceRoleKey) throw new Error('Invalid Supabase Identity configuration');
  const options={auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false}} as const;
  const publicClient=createClient(config.supabaseUrl,config.publishableKey,options);
  const adminClient=createClient(config.supabaseUrl,config.serviceRoleKey,options);
  return new SupabaseIdentityBoundary({
    auth:{
      async getUser(token){
        const {data,error}=await publicClient.auth.getUser(token);
        return {user:data.user?{id:data.user.id,email_confirmed_at:data.user.email_confirmed_at}:null,error};
      },
    },
    directory:{
      async sessionActive(userId,sessionId){
        const {data,error}=await adminClient.rpc('identity_session_active',{p_user:userId,p_session:sessionId});
        return {active:typeof data==='boolean'?data:null,error};
      },
      async member(userId,tenantId){
        const {data,error}=await adminClient.from('identity_memberships')
          .select('role,status').eq('organisation_id',tenantId).eq('user_id',userId).maybeSingle();
        return {membership:data as {role:OrganisationRole;status:string}|null,error};
      }
    }
  });
}

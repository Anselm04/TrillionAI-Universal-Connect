import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { Principal } from '../../gateway/src/index.ts';

export type OrganisationRole = 'owner' | 'admin' | 'staff' | 'customer';
export class IdentityBoundaryError extends Error {
  constructor(readonly code: 'UNAUTHENTICATED' | 'FORBIDDEN' | 'IDENTITY_UNAVAILABLE', message: string) {
    super(message);
    this.name = 'IdentityBoundaryError';
  }
}
export interface VerifiedIdentity {
  readonly principal: Principal;
  readonly organisationRole: OrganisationRole;
}
export interface IdentityAuth {
  getUser(token: string): Promise<{ user: {id:string; email_confirmed_at?: string|null}|null; error?: unknown }>;
  getAssuranceLevel(token: string): Promise<{level: string|null; error?:unknown}>;
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
function validatedSessionClaims(token:string, subject:string): string|null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some(p=>!p)) return null;
    const claims: unknown = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return null;
    const payload = claims as Record<string,unknown>;
    // Identity prohibits OAuth client-bound tokens in its account security endpoints.
    if (Object.hasOwn(payload,'client_id') || payload.sub !== subject ||
       typeof payload.session_id !== 'string' || !uuid.test(payload.session_id)) return null;
    return payload.session_id;
  } catch { return null; }
}
const identityProblem = (code: IdentityBoundaryError['code'], msg: string) =>
  new IdentityBoundaryError(code,msg);

export class SupabaseIdentityBoundary {
  constructor(private readonly dependencies:IdentityDependencies) {}
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
    const sessionId = validatedSessionClaims(accessToken,user.id);
    if (!sessionId) throw identityProblem('UNAUTHENTICATED','Invalid session-bound access token');

    let active:boolean|null;
    try {
      const result = await this.dependencies.directory.sessionActive(user.id,sessionId);
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

    let assurance:string|null;
    try {
      const result=await this.dependencies.auth.getAssuranceLevel(accessToken);
      if(result.error || !result.level) throw identityProblem('IDENTITY_UNAVAILABLE','MFA assurance unavailable');
      assurance=result.level;
    } catch(err) {
      if(err instanceof IdentityBoundaryError) throw err;
      throw identityProblem('IDENTITY_UNAVAILABLE','MFA assurance unavailable');
    }
    if (assurance !== 'aal1' && assurance !== 'aal2')
      throw identityProblem('UNAUTHENTICATED','Unsupported authentication assurance level');
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
      async getAssuranceLevel(token){
        const {data,error}=await publicClient.auth.mfa.getAuthenticatorAssuranceLevel(token);
        return {level:data?.currentLevel??null,error};
      }
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

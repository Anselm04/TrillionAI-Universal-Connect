import test from 'node:test';
import assert from 'node:assert/strict';
import { SupabaseIdentityBoundary, IdentityBoundaryError, type IdentityAuth, type IdentityDirectory } from '../src/index.ts';
const uid='11111111-1111-4111-8111-111111111111';
const tenant='22222222-2222-4222-8222-222222222222';
const session='33333333-3333-4333-8333-333333333333';
const token=(claims:Record<string,unknown>={})=>'signed.'+Buffer.from(JSON.stringify({sub:uid,session_id:session,aal:'aal1',...claims})).toString('base64url')+'.signature';
function setup(options:{verified?:boolean; active?:boolean;role?:'owner'|'admin'|'staff'|'customer';status?:string;aal?:string;directoryError?:boolean}={}){
  let authCalls=0; let membershipCalls=0;
  const auth:IdentityAuth={
    getUser:async()=>{authCalls++;return {user:options.verified===false?null:{id:uid,email_confirmed_at:'2026-01-01T00:00:00Z'}}},
  };
  const directory:IdentityDirectory={
    sessionActive:async()=>({active:options.active??true}),
    member:async()=>{membershipCalls++;return options.directoryError?{membership:null,error:new Error('offline')}:{membership:{role:options.role??'customer',status:options.status??'active'}}}
  };
  return {boundary:new SupabaseIdentityBoundary({auth,directory}),calls:()=>({authCalls,membershipCalls})};
}
function rejected(code:IdentityBoundaryError['code']) {
  return (error:unknown)=>error instanceof IdentityBoundaryError&&error.code===code;
}
test('verified user with active session and membership yields tenant principal',async()=>{
  const {boundary}=setup();assert.deepEqual(await boundary.authenticate(token(),tenant),{
    principal:{subject:uid,tenantId:tenant,assuranceLevel:1},organisationRole:'customer'
  });
});
test('admin and owner require MFA',async()=>{
  await assert.rejects(setup({role:'admin'}).boundary.authenticate(token(),tenant),rejected('FORBIDDEN'));
  const result=await setup({role:'owner',aal:'aal2'}).boundary.authenticate(token({aal:'aal2'}),tenant);
  assert.equal(result.organisationRole,'owner');assert.equal(result.principal.assuranceLevel,2);
});
test('invalid bearer never accesses membership',async()=>{
  const s=setup({verified:false});
  await assert.rejects(s.boundary.authenticate(token(),tenant),rejected('UNAUTHENTICATED'));
  assert.equal(s.calls().membershipCalls,0);
});
test('reject OAuth client-bound tokens',async()=>assert.rejects(
  setup().boundary.authenticate(token({client_id:'third-party-app'}),tenant),rejected('UNAUTHENTICATED')));
test('revoked session fails closed',async()=>assert.rejects(
  setup({active:false}).boundary.authenticate(token(),tenant),rejected('UNAUTHENTICATED')));
test('no active membership denies tenant access',async()=>assert.rejects(
  setup({status:'disabled'}).boundary.authenticate(token(),tenant),rejected('FORBIDDEN')));
test('membership data outages fail closed',async()=>assert.rejects(
  setup({directoryError:true}).boundary.authenticate(token(),tenant),rejected('IDENTITY_UNAVAILABLE')));
test('invalid tenant ID rejected before provider call',async()=>{
  const s=setup();await assert.rejects(s.boundary.authenticate(token(),'other-tenant'),rejected('UNAUTHENTICATED'));
  assert.equal(s.calls().authCalls,0);
});
test('spoofed session subject denied after token verification',async()=>assert.rejects(
  setup().boundary.authenticate(token({sub:'55555555-5555-4555-8555-555555555555'}),tenant),rejected('UNAUTHENTICATED')));
test('bad assurance fails closed',async()=>assert.rejects(
  setup({aal:'invalid'}).boundary.authenticate(token({aal:'invalid'}),tenant),rejected('UNAUTHENTICATED')));

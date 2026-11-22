import test from 'node:test';
import assert from 'node:assert/strict';
import {createGuardedNetworkTransport,EgressDenied,isPublicAddress,resolvePublicAddresses} from '../src/index.ts';

test('public IPv4 and IPv6 accepted, private and special-use addresses blocked',()=>{
  for(const addr of ['8.8.8.8','1.1.1.1','2606:4700:4700::1111']) assert.equal(isPublicAddress(addr),true,addr);
  for(const addr of ['127.0.0.1','10.0.0.1','192.168.5.1','172.16.1.1','169.254.169.254','100.64.1.2','0.0.0.0','224.0.0.1','::1','fc00::1','fe80::1','::ffff:127.0.0.1','::ffff:10.0.0.1']) assert.equal(isPublicAddress(addr),false,addr);
});
test('mixed public and private DNS responses fail closed',async()=>{
  await assert.rejects(resolvePublicAddresses('api.example.com',async()=>[
    {address:'8.8.8.8',family:4},{address:'10.3.0.4',family:4}]),EgressDenied);
});
test('unresolvable or invalid hostnames fail closed',async()=>{
  await assert.rejects(resolvePublicAddresses('localhost',async()=>[{address:'8.8.8.8',family:4}]),EgressDenied);
  await assert.rejects(resolvePublicAddresses('api.example.com',async()=>[]),EgressDenied);
  await assert.rejects(resolvePublicAddresses('api.example.com',async()=>{throw Error('DNS fail')}),EgressDenied);
});
test('guarded transport rejects unknown origins before DNS and network access',async()=>{
  let calls=0;
  const transport=createGuardedNetworkTransport({
    allowedOrigins:['https://api.example.com'],
    resolver:async()=>{calls++;return [{address:'8.8.8.8',family:4}]}
  });
  try{
    await assert.rejects(transport.send('https://other.example.com/records',{method:'GET',redirect:'error'}),EgressDenied);
    await assert.rejects(transport.send('http://api.example.com/records',{method:'GET',redirect:'error'}),EgressDenied);
    await assert.rejects(transport.send('https://api.example.com/records?redirect=evil',{method:'GET',redirect:'error'}),EgressDenied);
    await assert.rejects(transport.send('https://api.example.com/records',{method:'GET',redirect:'follow'}),EgressDenied);
    assert.equal(calls,0);
  }finally{await transport.close()}
});
test('constructor denies unapproved origins and local targets',()=>{
  for(const origin of ['http://api.example.com','https://localhost','https://127.0.0.1','https://api.example.com:8443','https://api.example.com/internal']) {
    assert.throws(()=>createGuardedNetworkTransport({allowedOrigins:[origin]}),EgressDenied);
  }
});

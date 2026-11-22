import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {once} from 'node:events';
import {createOrganizationRouter} from '../src/index.ts';
const tenant='11111111-1111-4111-8111-111111111111';
test('organization route demands same origin + bearer and never trusts tenant in headers',async()=>{
  const app=express();let calls=0;
  app.use('/organizations',createOrganizationRouter({
    allowedOrigin:'https://connect.example.com',
    limiter:{acquire:async()=>true},
    identity:{organizations:async(token)=>{calls++;assert.equal(token,'valid-token-12345');return [{id:tenant,role:'customer'}]}}
  }));
  const server=app.listen(0,'127.0.0.1');await once(server,'listening');
  try{
    const addr=server.address();if(!addr||typeof addr==='string')throw Error('server port');
    const url='http://127.0.0.1:'+addr.port+'/organizations';
    const bad=await fetch(url,{headers:{origin:'https://other.example.com',authorization:'Bearer valid-token-12345'}});
    assert.equal(bad.status,403);assert.equal(calls,0);
    const ok=await fetch(url,{headers:{origin:'https://connect.example.com',authorization:'Bearer valid-token-12345','x-organisation-id':'attacker-tenant'}});
    assert.equal(ok.status,200);assert.deepEqual((await ok.json()).organizations,[{id:tenant,role:'customer'}]);
    assert.equal(ok.headers.get('cache-control'),'no-store');
  }finally{await new Promise<void>(resolve=>server.close(()=>resolve()))}
});

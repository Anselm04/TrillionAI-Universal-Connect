import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {PostgresProviderRateLimiter} from '../src/index.ts';

test('policy denies zero, fractional or unbounded limits',()=>{
  const fake={connect:async()=>{throw Error('should not connect')}};
  for(const invalid of [0,-1,1.2,100001]) assert.throws(()=>new PostgresProviderRateLimiter(fake,{maxRequests:invalid,windowSeconds:60}));
  assert.throws(()=>new PostgresProviderRateLimiter(fake,{maxRequests:2,windowSeconds:0}));
});
if(process.env.TEST_ADMIN_DATABASE_URL && process.env.TEST_RUNTIME_DATABASE_URL){
  test('real PostgreSQL: shared tenant/provider quota is atomic under concurrency',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL,max:12});
    const prefix='test-limit-'+process.pid;
    try{
      const limiter=new PostgresProviderRateLimiter(runtime,{maxRequests:3,windowSeconds:3600});
      const attempts=await Promise.all(Array.from({length:12},()=>limiter.acquire(prefix,'crm.example')));
      assert.equal(attempts.filter(Boolean).length,3,'concurrent requests share a single quota');
      assert.equal(await limiter.acquire(prefix,'other.example'),true,'providers are independent');
      assert.equal(await limiter.acquire(prefix+'-other','crm.example'),true,'tenants are independent');
      const cross=await runtime.query('SELECT * FROM universal_connect.provider_rate_limits');
      assert.equal(cross.rows.length,0,'runtime role sees no cross-tenant data without a scoped transaction');
      const values=await admin.query('SELECT request_count FROM universal_connect.provider_rate_limits WHERE tenant_id=$1 AND provider_id=$2',[prefix,'crm.example']);
      assert.equal(values.rows.length,1);assert.equal(values.rows[0].request_count,3);
    }finally{
      await admin.query("DELETE FROM universal_connect.provider_rate_limits WHERE tenant_id LIKE 'test-limit-%'");
      await runtime.end();await admin.end();
    }
  });
}

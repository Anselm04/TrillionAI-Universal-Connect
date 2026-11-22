import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { randomBytes } from 'node:crypto';
import { encryptCredential,decryptCredential,PostgresCredentialVault,VaultError,type VaultKeyProvider } from '../src/index.ts';

const a={tenantId:'test-vault-tenant-a',connectionId:'test-vault-connection-a'};
const b={tenantId:'test-vault-tenant-b',connectionId:'test-vault-connection-b'};
const k1=randomBytes(32),k2=randomBytes(32);
let current='v1';
const keys:VaultKeyProvider={
  currentVersion:async()=>current,
  keyForVersion:async version=>{
    if(version==='v1')return k1;
    if(version==='v2')return k2;
    throw new Error('key unavailable');
  }
};
test('encryption uses authenticated random nonce and tenant AAD',async()=>{
  const raw=Buffer.from('not-a-real-token');
  const first=await encryptCredential(raw,k1,a,'access_token','v1');
  const second=await encryptCredential(raw,k1,a,'access_token','v1');
  assert.notEqual(first.nonce.toString('hex'),second.nonce.toString('hex'));
  assert.notEqual(first.ciphertext.toString('hex'),raw.toString('hex'));
  assert.equal((await decryptCredential(first,k1,a,'access_token')).toString(),'not-a-real-token');
  await assert.rejects(decryptCredential(first,k1,b,'access_token'),(e:unknown)=>e instanceof VaultError&&e.code==='INTEGRITY_FAILED');
  await assert.rejects(decryptCredential(first,k2,a,'access_token'),(e:unknown)=>e instanceof VaultError&&e.code==='INTEGRITY_FAILED');
  await assert.rejects(decryptCredential({...first,tag:Buffer.alloc(16)},k1,a,'access_token'),(e:unknown)=>e instanceof VaultError&&e.code==='INTEGRITY_FAILED');
});
test('rejects invalid names and empty plaintext',async()=>{
  await assert.rejects(encryptCredential(Buffer.from('x'),k1,a,'__proto__','v1'),(e:unknown)=>e instanceof VaultError&&e.code==='INVALID_INPUT');
  await assert.rejects(encryptCredential(Buffer.alloc(0),k1,a,'access_token','v1'),(e:unknown)=>e instanceof VaultError&&e.code==='INVALID_INPUT');
});

if(process.env.TEST_ADMIN_DATABASE_URL && process.env.TEST_RUNTIME_DATABASE_URL){
  test('real PostgreSQL: scoped credential store, use, rotate, revoke',async()=>{
    const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
    const runtime=new pg.Pool({connectionString:process.env.TEST_RUNTIME_DATABASE_URL});
    try {
      await admin.query("DELETE FROM universal_connect.credentials WHERE tenant_id LIKE 'test-vault-%'");
      await admin.query("DELETE FROM universal_connect.connections WHERE tenant_id LIKE 'test-vault-%'");
      await admin.query(`INSERT INTO universal_connect.connections(id,tenant_id,connector_id,enabled,capabilities)
        VALUES ($1,$2,'crm.example',true,'["records.read"]'::jsonb),
               ($3,$4,'crm.example',true,'["records.read"]'::jsonb)`,[a.connectionId,a.tenantId,b.connectionId,b.tenantId]);
      const vault=new PostgresCredentialVault(runtime,keys);
      await vault.put(a,'access_token',Buffer.from('fake-token'));
      await assert.rejects(vault.withCredential(b,'access_token',async secret=>secret.toString()),(e:unknown)=>e instanceof VaultError&&e.code==='NOT_FOUND');
      await assert.rejects(vault.put({tenantId:b.tenantId,connectionId:a.connectionId},'access_token',Buffer.from('bad')),(e:unknown)=>e instanceof VaultError&&e.code==='NOT_FOUND');
      let observedBuffer:Buffer|undefined;
      const secret=await vault.withCredential(a,'access_token',async supplied=>{observedBuffer=supplied;return supplied.toString()});
      assert.equal(secret,'fake-token');
      assert.deepEqual(observedBuffer,Buffer.alloc('fake-token'.length),'plaintext buffer must be wiped');
      const saved=await admin.query("SELECT ciphertext,nonce,tag,key_version FROM universal_connect.credentials WHERE tenant_id=$1",[a.tenantId]);
      assert.equal(saved.rows.length,1);assert.notEqual(saved.rows[0].ciphertext.toString(),'fake-token');
      current='v2';
      assert.equal(await vault.rotate(a,'access_token'),true);
      const rotated=await admin.query("SELECT key_version FROM universal_connect.credentials WHERE tenant_id=$1",[a.tenantId]);
      assert.equal(rotated.rows[0].key_version,'v2');
      assert.equal(await vault.withCredential(a,'access_token',async raw=>raw.toString()),'fake-token');
      assert.equal(await vault.revoke(a,'access_token'),true);
      assert.equal(await vault.revoke(a,'access_token'),false);
      await assert.rejects(vault.withCredential(a,'access_token',async raw=>raw.toString()),(e:unknown)=>e instanceof VaultError&&e.code==='NOT_FOUND');
      const unscoped=await runtime.query('SELECT * FROM universal_connect.credentials');
      assert.equal(unscoped.rows.length,0);
      await assert.rejects(runtime.query("SELECT * FROM universal_connect.credentials WHERE tenant_id=$1",[a.tenantId]).then(r=>{if(r.rows.length)throw new Error('unexpected rows');}),/unexpected rows|./);
    } finally {
      await admin.query("DELETE FROM universal_connect.credentials WHERE tenant_id LIKE 'test-vault-%'");
      await admin.query("DELETE FROM universal_connect.connections WHERE tenant_id LIKE 'test-vault-%'");
      await runtime.end();await admin.end();
      current='v1';
    }
  });
}

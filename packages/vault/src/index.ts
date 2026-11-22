import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { inTenantTransaction, type TenantPool } from '../../persistence/src/index.ts';

/** Obtain keys from an external secret manager/HSM at runtime, not from a public Git repo. */
export interface VaultKeyProvider {
  currentVersion(): Promise<string>;
  keyForVersion(version: string): Promise<Buffer>;
}
export interface VaultScope {
  readonly tenantId: string;
  readonly connectionId: string;
}
export interface EncryptedCredential {
  readonly id: string;
  readonly keyVersion: string;
  readonly nonce: Buffer;
  readonly tag: Buffer;
  readonly ciphertext: Buffer;
}
export class VaultError extends Error {
  readonly code: 'INVALID_INPUT' | 'UNAVAILABLE' | 'NOT_FOUND' | 'INTEGRITY_FAILED';
  constructor(code: VaultError['code']) {
    super(code); this.name='VaultError'; this.code=code;
  }
}
const nameValid = (name: string): boolean => typeof name==='string' && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(name);
function validate(scope: VaultScope, name:string): void {
  if (!scope || !scope.tenantId?.trim() || scope.tenantId.length>128 ||
      !scope.connectionId?.trim() || scope.connectionId.length>128 || !nameValid(name))
    throw new VaultError('INVALID_INPUT');
}
function aad(scope: VaultScope, name:string):Buffer {
  // JSON tuple has unambiguous separators, unlike string concatenation.
  return Buffer.from(JSON.stringify(['uc-vault-v1',scope.tenantId,scope.connectionId,name]));
}
function getKey(key:Buffer):Buffer {
  if (!Buffer.isBuffer(key) || key.byteLength!==32) throw new VaultError('UNAVAILABLE');
  return Buffer.from(key);
}
export async function encryptCredential(
  plaintext: Buffer, key:Buffer, scope:VaultScope, name:string, version:string
):Promise<EncryptedCredential> {
  validate(scope,name);
  if (!Buffer.isBuffer(plaintext) || plaintext.byteLength===0 || plaintext.byteLength>65536 ||
      typeof version!=='string'||!version.trim()||version.length>128) throw new VaultError('INVALID_INPUT');
  const material=getKey(key);
  try {
    const nonce=randomBytes(12);
    const cipher=createCipheriv('aes-256-gcm',material,nonce);
    cipher.setAAD(aad(scope,name));
    const ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]);
    return {id:randomUUID(),keyVersion:version,nonce,tag:cipher.getAuthTag(),ciphertext};
  } finally {material.fill(0)}
}
export async function decryptCredential(
  envelope: EncryptedCredential, key:Buffer, scope:VaultScope, name:string
):Promise<Buffer> {
  validate(scope,name);
  const material=getKey(key);
  try {
    if (!Buffer.isBuffer(envelope.nonce)||envelope.nonce.byteLength!==12||
        !Buffer.isBuffer(envelope.tag)||envelope.tag.byteLength!==16||
        !Buffer.isBuffer(envelope.ciphertext)||envelope.ciphertext.byteLength<1||
        envelope.ciphertext.byteLength>65536) throw new VaultError('INTEGRITY_FAILED');
    const decipher=createDecipheriv('aes-256-gcm',material,envelope.nonce);
    decipher.setAAD(aad(scope,name));
    decipher.setAuthTag(envelope.tag);
    return Buffer.concat([decipher.update(envelope.ciphertext),decipher.final()]);
  } catch {
    throw new VaultError('INTEGRITY_FAILED');
  } finally {material.fill(0)}
}
function fromDb(row:Record<string,unknown>):EncryptedCredential {
  if (typeof row.id!=='string'||typeof row.key_version!=='string') throw new VaultError('UNAVAILABLE');
  return {id:row.id,keyVersion:row.key_version,nonce:row.nonce as Buffer,
    tag:row.tag as Buffer,ciphertext:row.ciphertext as Buffer};
}
/** Only construct/use on a trusted backend, after Identity and capability authorization. */
export class PostgresCredentialVault {
  private readonly pool:TenantPool;
  private readonly keys:VaultKeyProvider;
  constructor(pool:TenantPool, keys:VaultKeyProvider) { this.pool=pool; this.keys=keys; }

  async put(scope:VaultScope,name:string,plaintext:Buffer):Promise<void> {
    validate(scope,name);
    const version=await this.keys.currentVersion();
    const key=await this.keys.keyForVersion(version);
    const encrypted=await encryptCredential(plaintext,key,scope,name,version);
    await inTenantTransaction(this.pool,scope.tenantId,async client=>{
      const result=await client.query(
        `INSERT INTO universal_connect.credentials
          (id,tenant_id,connection_id,name,key_version,nonce,tag,ciphertext)
          SELECT $1,c.tenant_id,c.id,$2,$3,$4,$5,$6
          FROM universal_connect.connections c
          WHERE c.id=$7 AND c.tenant_id=$8
          ON CONFLICT (tenant_id,connection_id,name) DO UPDATE SET
            key_version=EXCLUDED.key_version,nonce=EXCLUDED.nonce,
            tag=EXCLUDED.tag,ciphertext=EXCLUDED.ciphertext,updated_at=now()
          RETURNING id`,
        [encrypted.id,name,encrypted.keyVersion,encrypted.nonce,encrypted.tag,
          encrypted.ciphertext,scope.connectionId,scope.tenantId]);
      if(result.rowCount!==1)throw new VaultError('NOT_FOUND');
    });
  }

  /** Explicit one-off use, not a plaintext-returning HTTP endpoint. Wipe the supplied buffer afterward. */
  async withCredential<T>(scope:VaultScope,name:string,use:(secret:Buffer)=>Promise<T>):Promise<T> {
    validate(scope,name);
    const row=await inTenantTransaction(this.pool,scope.tenantId,async client=>{
      const result=await client.query(
        `SELECT v.id,v.key_version,v.nonce,v.tag,v.ciphertext
          FROM universal_connect.credentials v
          JOIN universal_connect.connections c ON c.id=v.connection_id AND c.tenant_id=v.tenant_id
          WHERE v.tenant_id=$1 AND v.connection_id=$2 AND v.name=$3 AND c.enabled=true
          LIMIT 1`,[scope.tenantId,scope.connectionId,name]);
      return result.rows[0] as Record<string,unknown>|undefined;
    });
    if(!row)throw new VaultError('NOT_FOUND');
    const envelope=fromDb(row);
    const key=await this.keys.keyForVersion(envelope.keyVersion);
    const plaintext=await decryptCredential(envelope,key,scope,name);
    try {return await use(plaintext)} finally {plaintext.fill(0)}
  }

  async revoke(scope:VaultScope,name:string):Promise<boolean> {
    validate(scope,name);
    return inTenantTransaction(this.pool,scope.tenantId,async client=>{
      const result=await client.query(
        `DELETE FROM universal_connect.credentials
          WHERE tenant_id=$1 AND connection_id=$2 AND name=$3`,
        [scope.tenantId,scope.connectionId,name]);
      return result.rowCount===1;
    });
  }

  /** Re-encrypt in place under the currently active key, guarded against concurrent updates. */
  async rotate(scope:VaultScope,name:string):Promise<boolean> {
    validate(scope,name);
    return inTenantTransaction(this.pool,scope.tenantId,async client=>{
      const selected=await client.query(
        `SELECT id,key_version,nonce,tag,ciphertext FROM universal_connect.credentials
          WHERE tenant_id=$1 AND connection_id=$2 AND name=$3 FOR UPDATE`,
        [scope.tenantId,scope.connectionId,name]);
      const row=selected.rows[0] as Record<string,unknown>|undefined;
      if(!row)return false;
      const existing=fromDb(row);
      const current=await this.keys.currentVersion();
      if(existing.keyVersion===current)return true;
      const oldKey=await this.keys.keyForVersion(existing.keyVersion);
      const plaintext=await decryptCredential(existing,oldKey,scope,name);
      let updated:EncryptedCredential;
      try {
        const currentKey=await this.keys.keyForVersion(current);
        updated=await encryptCredential(plaintext,currentKey,scope,name,current);
      } finally {plaintext.fill(0)}
      const result=await client.query(
        `UPDATE universal_connect.credentials SET key_version=$1,nonce=$2,tag=$3,
          ciphertext=$4,updated_at=now()
          WHERE id=$5 AND tenant_id=$6 AND connection_id=$7`,
        [updated.keyVersion,updated.nonce,updated.tag,updated.ciphertext,
          existing.id,scope.tenantId,scope.connectionId]);
      return result.rowCount===1;
    });
  }
}

import {inTenantTransaction,type TenantPool} from '../../persistence/src/index.ts';

export interface ProviderRateLimiter {
  /** Reserve before each outbound HTTP attempt. Denials must fail closed. */
  acquire(tenantId:string,providerId:string):Promise<boolean>;
}
export interface ProviderLimitPolicy {
  readonly maxRequests:number;
  readonly windowSeconds:number;
}
const validId=(s:string):boolean=>typeof s==='string'&&/^[a-z][a-z0-9._-]{1,127}$/.test(s);
export class PostgresProviderRateLimiter implements ProviderRateLimiter {
  private readonly pool:TenantPool;
  private readonly policy:ProviderLimitPolicy;
  constructor(pool:TenantPool,policy:ProviderLimitPolicy) {
    if (!Number.isInteger(policy.maxRequests)||policy.maxRequests<1||policy.maxRequests>100000||
        !Number.isInteger(policy.windowSeconds)||policy.windowSeconds<1||policy.windowSeconds>86400)
      throw new Error('Invalid provider rate limit');
    this.pool=pool;this.policy=policy;
  }
  async acquire(tenantId:string,providerId:string):Promise<boolean> {
    if (!validId(providerId)) throw new Error('Invalid provider identifier');
    return inTenantTransaction(this.pool,tenantId,async client=>{
      // Fixed-window ID is computed using the DATABASE clock (not customer clocks).
      // ON CONFLICT updates atomically and enforces a global limit across workers.
      // The WHERE condition denies when full and returns zero rows.
      const result=await client.query(
        `WITH window_clock AS (
           SELECT floor(extract(epoch from clock_timestamp()) / $4)::bigint AS window_id
         )
         INSERT INTO universal_connect.provider_rate_limits
           (tenant_id,provider_id,window_id,request_count)
         SELECT $1,$2,window_id,1 FROM window_clock
         ON CONFLICT (tenant_id,provider_id,window_id)
         DO UPDATE SET request_count=universal_connect.provider_rate_limits.request_count+1
         WHERE universal_connect.provider_rate_limits.request_count < $3
         RETURNING request_count`,
        [tenantId,providerId,this.policy.maxRequests,this.policy.windowSeconds]);
      return result.rowCount===1;
    });
  }
}

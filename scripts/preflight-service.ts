import {parseServiceConfig} from '../packages/service/src/index.ts';
import {createPostgresPool} from '../packages/persistence/src/index.ts';
import {assertRuntimeDatabaseReady} from '../packages/service/src/preflight.ts';

/** Operator-only deployment gate: validates runtime configuration and database schema/RLS.
 * Does not listen on a port, run migrations, touch customer data, or call external providers. */
async function main():Promise<void>{
  const config=parseServiceConfig(process.env);
  const pool=createPostgresPool(config.databaseUrl);
  try{
    await assertRuntimeDatabaseReady(pool);
    process.stdout.write('Runtime preflight passed: database role, tenant RLS and required schema verified\n');
  }finally{await pool.end()}
}
main().catch(()=>{
  process.stderr.write('Runtime preflight failed: verify protected configuration, role and migrations\n');
  process.exitCode=1;
});

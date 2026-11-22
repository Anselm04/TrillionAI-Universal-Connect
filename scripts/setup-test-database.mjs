import pg from 'pg';
import { readFile } from 'node:fs/promises';
const url = process.env.TEST_ADMIN_DATABASE_URL;
if (!url) throw new Error('TEST_ADMIN_DATABASE_URL is required');
const client = new pg.Client({connectionString:url});
await client.connect();
try {
  await client.query("CREATE ROLE uc_runtime LOGIN PASSWORD 'ci-only-runtime' NOSUPERUSER NOBYPASSRLS");
  for (const path of [
    'infrastructure/database/001_tenant_persistence.sql',
    'infrastructure/database/002_runtime_grants.sql',
    'infrastructure/database/003_credential_vault.sql',
    'infrastructure/database/004_provider_rate_limits.sql',
    'infrastructure/database/005_durable_workflows.sql',
  ]) {
    await client.query(await readFile(path, 'utf8'));
  }
  console.log('PostgreSQL integration-test schema and isolated application role ready');
} finally {
  await client.end();
}

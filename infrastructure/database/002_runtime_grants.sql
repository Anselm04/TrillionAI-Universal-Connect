-- Run after provisioning a dedicated NON-OWNER, NON-BYPASSRLS uc_runtime role.
-- Avoid using postgres/superuser as an application database login.
BEGIN;
GRANT USAGE ON SCHEMA universal_connect TO uc_runtime;
GRANT SELECT ON universal_connect.connections TO uc_runtime;
GRANT SELECT, UPDATE(consumed_at) ON universal_connect.approvals TO uc_runtime;
GRANT INSERT, SELECT ON universal_connect.audit_events TO uc_runtime;
GRANT USAGE, SELECT ON SEQUENCE universal_connect.audit_events_id_seq TO uc_runtime;
COMMIT;

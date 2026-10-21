CREATE TABLE IF NOT EXISTS phishguard_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phishguard_scans(id TEXT PRIMARY KEY,owner TEXT NOT NULL,created_at TEXT NOT NULL,result_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS phishguard_scans_owner_date ON phishguard_scans(owner,created_at);
CREATE TABLE IF NOT EXISTS phishguard_rate_limits(bucket TEXT PRIMARY KEY,window_id BIGINT NOT NULL,hits INTEGER NOT NULL);

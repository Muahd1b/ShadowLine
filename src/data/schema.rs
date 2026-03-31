use anyhow::Result;
use rusqlite::Connection;

pub fn initialize_database(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS vendors (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            vendor_type TEXT NOT NULL,
            risk_score REAL NOT NULL DEFAULT 0.0,
            last_scanned TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS connections (
            id TEXT PRIMARY KEY,
            vendor_id TEXT NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
            platform TEXT NOT NULL,
            connection_type TEXT NOT NULL,
            permissions TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'active',
            discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_used TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            current_stage TEXT NOT NULL DEFAULT 'initial-access',
            ttps TEXT NOT NULL DEFAULT '[]',
            velocity_estimate TEXT,
            blast_radius TEXT
        );

        CREATE TABLE IF NOT EXISTS velocity_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER REFERENCES incidents(id),
            minutes_remaining REAL NOT NULL,
            confidence REAL NOT NULL,
            archetype TEXT NOT NULL,
            recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            reasoning TEXT,
            prev_hash BLOB NOT NULL,
            hash BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
            total_packages INTEGER NOT NULL,
            clean_count INTEGER NOT NULL,
            malicious_count INTEGER NOT NULL,
            risky_count INTEGER NOT NULL,
            details TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_connections_vendor ON connections(vendor_id);
        CREATE INDEX IF NOT EXISTS idx_connections_status ON connections(status);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        ",
    )?;
    Ok(())
}

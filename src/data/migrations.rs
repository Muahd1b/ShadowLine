use anyhow::Result;
use rusqlite::Connection;

pub fn run_migrations(_conn: &Connection) -> Result<()> {
    Ok(())
}

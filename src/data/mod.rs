mod schema;
mod queries;
mod migrations;

pub use schema::initialize_database;
pub use queries::Database;

use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

pub fn open_database(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    Ok(conn)
}

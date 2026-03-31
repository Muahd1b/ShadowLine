pub mod core;
pub mod data;
pub mod security;
pub mod connectors;
pub mod scanner;
pub mod ai;
pub mod plugins;
pub mod tui;
pub mod splash;

pub use core::{Incident, Vendor, Connection, VelocityEstimate, BlastRadius};
pub use data::Database;
pub use security::{AuditLog, CredentialVault, PromptFirewall};

use anyhow::Result;
use std::path::PathBuf;

pub const APP_NAME: &str = "shadowline";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn data_dir() -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
        .join(".shadowline");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn db_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("data.db"))
}

use crate::core::{Platform, Vendor};
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Connector: Send + Sync {
    async fn discover_connections(&self) -> Result<Vec<Vendor>>;
    async fn revoke_connection(&self, connection_id: &str) -> Result<()>;
    fn platform(&self) -> &Platform;
    fn name(&self) -> &str;
}

pub struct ConnectorConfig {
    pub platform: Platform,
    pub api_key_env: Option<String>,
    pub oauth_token_env: Option<String>,
    pub base_url: Option<String>,
}

impl ConnectorConfig {
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            api_key_env: None,
            oauth_token_env: None,
            base_url: None,
        }
    }

    pub fn with_api_key_env(mut self, env_var: &str) -> Self {
        self.api_key_env = Some(env_var.to_string());
        self
    }

    pub fn with_oauth_env(mut self, env_var: &str) -> Self {
        self.oauth_token_env = Some(env_var.to_string());
        self
    }
}

#[derive(Debug)]
pub struct ConnectorResult {
    pub vendor: Vendor,
    pub connections_found: usize,
    pub errors: Vec<String>,
}

use super::common::Connector;
use crate::core::*;
use anyhow::Result;
use async_trait::async_trait;

pub struct GitHubConnector {
    api_token: Option<String>,
}

impl GitHubConnector {
    pub fn new(config: &super::ConnectorConfig) -> Result<Self> {
        let api_token = config
            .api_key_env
            .as_ref()
            .and_then(|env| std::env::var(env).ok());

        Ok(Self { api_token })
    }
}

#[async_trait]
impl Connector for GitHubConnector {
    async fn discover_connections(&self) -> Result<Vec<Vendor>> {
        if self.api_token.is_none() {
            tracing::warn!("GitHub: no API token configured");
            return Ok(vec![]);
        }

        let vendor = Vendor {
            id: "github".to_string(),
            name: "GitHub".to_string(),
            vendor_type: VendorType::Saas,
            risk_score: 0.3,
            connections: vec![],
            last_scanned: Some(chrono::Utc::now()),
        };

        Ok(vec![vendor])
    }

    async fn revoke_connection(&self, connection_id: &str) -> Result<()> {
        tracing::info!("GitHub: revoking connection {}", connection_id);
        Ok(())
    }

    fn platform(&self) -> &Platform {
        &Platform::GitHub
    }

    fn name(&self) -> &str {
        "GitHub"
    }
}

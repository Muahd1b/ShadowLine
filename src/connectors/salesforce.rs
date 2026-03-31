use super::common::Connector;
use crate::core::*;
use anyhow::Result;
use async_trait::async_trait;

pub struct SalesforceConnector {
    api_token: Option<String>,
}

impl SalesforceConnector {
    pub fn new(config: &super::ConnectorConfig) -> Result<Self> {
        let api_token = config
            .oauth_token_env
            .as_ref()
            .and_then(|env| std::env::var(env).ok());

        Ok(Self { api_token })
    }
}

#[async_trait]
impl Connector for SalesforceConnector {
    async fn discover_connections(&self) -> Result<Vec<Vendor>> {
        if self.api_token.is_none() {
            tracing::warn!("Salesforce: no API token configured");
            return Ok(vec![]);
        }

        let vendor = Vendor {
            id: "salesforce".to_string(),
            name: "Salesforce".to_string(),
            vendor_type: VendorType::Saas,
            risk_score: 0.4,
            connections: vec![],
            last_scanned: Some(chrono::Utc::now()),
        };

        Ok(vec![vendor])
    }

    async fn revoke_connection(&self, connection_id: &str) -> Result<()> {
        tracing::info!("Salesforce: revoking connection {}", connection_id);
        Ok(())
    }

    fn platform(&self) -> &Platform {
        &Platform::Salesforce
    }

    fn name(&self) -> &str {
        "Salesforce"
    }
}

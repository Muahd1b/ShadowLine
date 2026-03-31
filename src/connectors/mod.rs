mod common;
mod github;
mod salesforce;
mod slack;

pub use common::{Connector, ConnectorConfig, ConnectorResult};
pub use github::GitHubConnector;
pub use salesforce::SalesforceConnector;
pub use slack::SlackConnector;



use anyhow::Result;

pub fn create_connector(config: &ConnectorConfig) -> Result<Box<dyn Connector>> {
    match config.platform {
        crate::core::Platform::GitHub => Ok(Box::new(GitHubConnector::new(config)?)),
        crate::core::Platform::Salesforce => Ok(Box::new(SalesforceConnector::new(config)?)),
        crate::core::Platform::Slack => Ok(Box::new(SlackConnector::new(config)?)),
        _ => anyhow::bail!("Unsupported platform: {:?}", config.platform),
    }
}

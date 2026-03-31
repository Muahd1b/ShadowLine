use super::models::*;
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub struct KillSwitch;

impl KillSwitch {
    pub fn new() -> Self {
        Self
    }

    pub fn build_kill_plan(&self, vendor: &Vendor) -> Result<KillPlan> {
        let steps: Vec<KillStep> = vendor
            .connections
            .iter()
            .filter(|c| c.status != ConnectionStatus::Revoked)
            .map(|conn| KillStep {
                platform: conn.platform.clone(),
                connection_id: conn.id.clone(),
                connection_type: format!("{:?}", conn.connection_type),
                operation: KillOperation::Revoke,
            })
            .collect();

        let total_connections = steps.len();

        Ok(KillPlan {
            vendor_id: vendor.id.clone(),
            vendor_name: vendor.name.clone(),
            steps,
            estimated_seconds: total_connections as f64 * 0.5,
            teams_affected: vec![],
        })
    }

    pub fn execute_dry_run(&self, plan: &KillPlan) -> Result<KillResult> {
        let results: Vec<StepResult> = plan
            .steps
            .iter()
            .map(|step| StepResult {
                platform: step.platform.display_name().to_string(),
                connection_id: step.connection_id.clone(),
                success: true,
                message: "DRY RUN: would revoke".to_string(),
            })
            .collect();

        Ok(KillResult {
            vendor_name: plan.vendor_name.clone(),
            total_actions: results.len(),
            successful: results.len(),
            failed: 0,
            step_results: results,
            execution_seconds: 0.0,
        })
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillPlan {
    pub vendor_id: String,
    pub vendor_name: String,
    pub steps: Vec<KillStep>,
    pub estimated_seconds: f64,
    pub teams_affected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillStep {
    pub platform: Platform,
    pub connection_id: String,
    pub connection_type: String,
    pub operation: KillOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KillOperation {
    Revoke,
    Disable,
    Delete,
    Quarantine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillResult {
    pub vendor_name: String,
    pub total_actions: usize,
    pub successful: usize,
    pub failed: usize,
    pub step_results: Vec<StepResult>,
    pub execution_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub platform: String,
    pub connection_id: String,
    pub success: bool,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_vendor() -> Vendor {
        Vendor {
            id: "vendor-1".to_string(),
            name: "Drift".to_string(),
            vendor_type: VendorType::Saas,
            risk_score: 0.8,
            connections: vec![
                Connection {
                    id: "conn-1".to_string(),
                    platform: Platform::Salesforce,
                    connection_type: ConnectionType::OAuth {
                        token_ref: Uuid::new_v4(),
                        scopes: vec!["read".to_string(), "write".to_string()],
                    },
                    permissions: vec![Permission {
                        resource: "contacts".to_string(),
                        access: AccessLevel::Write,
                    }],
                    status: ConnectionStatus::Active,
                    discovered_at: Utc::now(),
                    last_used: Some(Utc::now()),
                },
                Connection {
                    id: "conn-2".to_string(),
                    platform: Platform::Slack,
                    connection_type: ConnectionType::Webhook {
                        url: "https://hooks.slack.com/test".to_string(),
                        events: vec!["message".to_string()],
                    },
                    permissions: vec![],
                    status: ConnectionStatus::Active,
                    discovered_at: Utc::now(),
                    last_used: None,
                },
            ],
            last_scanned: None,
        }
    }

    #[test]
    fn test_kill_plan_generation() {
        let ks = KillSwitch::new();
        let vendor = make_vendor();
        let plan = ks.build_kill_plan(&vendor).unwrap();
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.vendor_name, "Drift");
    }

    #[test]
    fn test_dry_run_execution() {
        let ks = KillSwitch::new();
        let vendor = make_vendor();
        let plan = ks.build_kill_plan(&vendor).unwrap();
        let result = ks.execute_dry_run(&plan).unwrap();
        assert_eq!(result.total_actions, 2);
        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 0);
    }
}

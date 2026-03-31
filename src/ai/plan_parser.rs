use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPlan {
    pub action: String,
    pub reasoning: Option<String>,
    pub steps: Vec<PlanStep>,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub platform: String,
    pub operation: String,
    pub target: String,
    pub priority: Option<u32>,
}

pub fn parse_action_plan(json: &str) -> Result<ActionPlan> {
    let plan: ActionPlan = serde_json::from_str(json)?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_plan() {
        let json = r#"{
            "action": "kill_chain",
            "reasoning": "Drift confirmed compromised",
            "steps": [
                {"platform": "salesforce", "operation": "revoke", "target": "token-1", "priority": 1},
                {"platform": "slack", "operation": "disable", "target": "webhook-1", "priority": 2}
            ],
            "confidence": 0.85
        }"#;

        let plan = parse_action_plan(json).unwrap();
        assert_eq!(plan.action, "kill_chain");
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.confidence, Some(0.85));
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_action_plan("not json");
        assert!(result.is_err());
    }
}

use super::kill_switch::KillPlan;
use super::models::*;
use anyhow::Result;

pub struct ActionValidator {
    max_single_kill_radius: u32,
    max_kills_per_hour: u32,
    kills_this_hour: u32,
    auto_confirm: bool,
}

impl ActionValidator {
    pub fn new(max_single_kill_radius: u32, max_kills_per_hour: u32, auto_confirm: bool) -> Self {
        Self {
            max_single_kill_radius,
            max_kills_per_hour,
            kills_this_hour: 0,
            auto_confirm,
        }
    }

    pub fn validate_kill_plan(
        &self,
        plan: &KillPlan,
        blast_radius: &BlastRadius,
    ) -> Result<ValidationResult> {
        let mut warnings = vec![];
        let mut blocked = false;

        if blast_radius.systems_affected > self.max_single_kill_radius {
            blocked = true;
            warnings.push(format!(
                "Blast radius ({}) exceeds max single kill radius ({})",
                blast_radius.systems_affected, self.max_single_kill_radius
            ));
        }

        if self.kills_this_hour >= self.max_kills_per_hour {
            blocked = true;
            warnings.push(format!(
                "Kill rate limit reached: {}/{} this hour",
                self.kills_this_hour, self.max_kills_per_hour
            ));
        }

        if plan.steps.is_empty() {
            blocked = true;
            warnings.push("No connections to kill".to_string());
        }

        if blast_radius.systems_affected > 10 {
            warnings.push(format!(
                "High blast radius: {} systems affected. Consider dry-run first.",
                blast_radius.systems_affected
            ));
        }

        if !self.auto_confirm && !blocked {
            warnings.push("Human confirmation required".to_string());
        }

        Ok(ValidationResult {
            approved: !blocked,
            warnings,
            requires_human: !self.auto_confirm,
        })
    }

    pub fn increment_kill_count(&mut self) {
        self.kills_this_hour += 1;
    }

    pub fn reset_hourly_count(&mut self) {
        self.kills_this_hour = 0;
    }
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub approved: bool,
    pub warnings: Vec<String>,
    pub requires_human: bool,
}

#[cfg(test)]
mod tests {
    use super::super::kill_switch::{KillOperation, KillPlan, KillStep};
    use super::super::models::Platform;
    use super::*;

    fn make_plan(steps: usize) -> KillPlan {
        KillPlan {
            vendor_id: "v1".to_string(),
            vendor_name: "Test".to_string(),
            steps: (0..steps)
                .map(|i| KillStep {
                    platform: Platform::Salesforce,
                    connection_id: format!("c{}", i),
                    connection_type: "OAuth".to_string(),
                    operation: KillOperation::Revoke,
                })
                .collect(),
            estimated_seconds: steps as f64 * 0.5,
            teams_affected: vec![],
        }
    }

    fn make_radius(systems: u32) -> BlastRadius {
        BlastRadius {
            systems_affected: systems,
            data_records_at_risk: 0,
            teams_affected: vec![],
            downstream_vendors: vec![],
        }
    }

    #[test]
    fn test_valid_kill_plan() {
        let validator = ActionValidator::new(20, 10, true);
        let plan = make_plan(3);
        let radius = make_radius(5);
        let result = validator.validate_kill_plan(&plan, &radius).unwrap();
        assert!(result.approved);
    }

    #[test]
    fn test_blast_radius_blocks_kill() {
        let validator = ActionValidator::new(5, 10, true);
        let plan = make_plan(3);
        let radius = make_radius(10);
        let result = validator.validate_kill_plan(&plan, &radius).unwrap();
        assert!(!result.approved);
    }

    #[test]
    fn test_human_confirmation_required() {
        let validator = ActionValidator::new(20, 10, false);
        let plan = make_plan(3);
        let radius = make_radius(5);
        let result = validator.validate_kill_plan(&plan, &radius).unwrap();
        assert!(result.approved);
        assert!(result.requires_human);
    }
}

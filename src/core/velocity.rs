use super::models::*;

pub struct VelocityClock {
    baseline_blitz: (f64, f64),
    baseline_standard: (f64, f64),
    baseline_atp: (f64, f64),
    baseline_opportunistic: (f64, f64),
}

impl VelocityClock {
    pub fn new() -> Self {
        Self {
            baseline_blitz: (30.0, 90.0),
            baseline_standard: (1440.0, 4320.0),
            baseline_atp: (10080.0, 43200.0),
            baseline_opportunistic: (60.0, 2880.0),
        }
    }

    pub fn estimate(&self, incident: &Incident) -> VelocityEstimate {
        let archetype = self.classify_archetype(&incident.ttps_observed);
        let (min_range, max_range) = archetype.typical_minutes();

        let stage_factor = incident.current_stage.progress();
        let elapsed_factor = 1.0 - stage_factor;

        let remaining_low = min_range * elapsed_factor;
        let remaining_high = max_range * elapsed_factor;
        let remaining_mid = (remaining_low + remaining_high) / 2.0;

        let confidence = self.calculate_confidence(&incident.ttps_observed, stage_factor);

        VelocityEstimate {
            minutes_remaining: remaining_mid,
            confidence,
            range_low: remaining_low,
            range_high: remaining_high,
            archetype,
            similar_incidents: vec![],
        }
    }

    fn classify_archetype(&self, ttps: &[Technique]) -> VelocityArchetype {
        let ai_indicators = ttps.iter().any(|t| {
            t.mitre_id.starts_with("T1059") || t.mitre_id == "T1053" || t.mitre_id == "T1204"
        });

        let automated_indicators = ttps.len() > 5
            && ttps.windows(2).all(|w| {
                let delta = w[1].observed_at.signed_duration_since(w[0].observed_at);
                delta.num_seconds() < 300
            });

        if ai_indicators && automated_indicators {
            VelocityArchetype::Blitz
        } else if ttps
            .iter()
            .any(|t| t.tactic == "persistence" || t.tactic == "defense-evasion")
        {
            VelocityArchetype::AtpSlow
        } else if ttps.len() <= 2 {
            VelocityArchetype::Opportunistic
        } else {
            VelocityArchetype::Standard
        }
    }

    fn calculate_confidence(&self, ttps: &[Technique], stage_progress: f64) -> f64 {
        let base = 0.4;
        let ttp_bonus = (ttps.len() as f64 * 0.05).min(0.3);
        let stage_bonus = stage_progress * 0.2;
        (base + ttp_bonus + stage_bonus).min(0.95)
    }
}

impl Default for VelocityClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_incident(stage: AttackStage, ttps: Vec<Technique>) -> Incident {
        Incident {
            id: 1,
            status: IncidentStatus::Active,
            created_at: Utc::now(),
            ttps_observed: ttps,
            current_stage: stage,
            velocity_estimate: None,
            blast_radius: None,
        }
    }

    fn make_technique(id: &str, tactic: &str) -> Technique {
        Technique {
            mitre_id: id.to_string(),
            name: "test".to_string(),
            tactic: tactic.to_string(),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn test_blitz_classification() {
        let clock = VelocityClock::new();
        let now = Utc::now();
        let ttps: Vec<Technique> = (0..6)
            .map(|i| Technique {
                mitre_id: "T1059.001".to_string(),
                name: "PowerShell".to_string(),
                tactic: "execution".to_string(),
                observed_at: now + chrono::Duration::seconds(i * 60),
            })
            .collect();
        let incident = make_incident(AttackStage::LateralMovement, ttps);
        let estimate = clock.estimate(&incident);
        assert!(matches!(estimate.archetype, VelocityArchetype::Blitz));
        assert!(estimate.minutes_remaining > 0.0);
    }

    #[test]
    fn test_early_stage_higher_remaining() {
        let clock = VelocityClock::new();
        let early = make_incident(
            AttackStage::InitialAccess,
            vec![make_technique("T1078", "initial-access")],
        );
        let late = make_incident(
            AttackStage::Collection,
            vec![make_technique("T1078", "initial-access")],
        );
        let early_est = clock.estimate(&early);
        let late_est = clock.estimate(&late);
        assert!(early_est.minutes_remaining > late_est.minutes_remaining);
    }
}

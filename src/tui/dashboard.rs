use crate::core::*;
use chrono::Utc;

pub struct Dashboard {
    pub incidents: Vec<Incident>,
    pub vendors: Vec<Vendor>,
    pub log_entries: Vec<String>,
    pub selected_pane: usize,
    pub command_input: String,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            incidents: vec![],
            vendors: vec![],
            log_entries: vec![],
            selected_pane: 0,
            command_input: String::new(),
        }
    }

    pub fn add_log(&mut self, entry: String) {
        let timestamp = Utc::now().format("%H:%M:%S");
        self.log_entries.push(format!("[{}] {}", timestamp, entry));
        if self.log_entries.len() > 200 {
            self.log_entries.remove(0);
        }
    }

    pub fn active_incidents(&self) -> Vec<&Incident> {
        self.incidents
            .iter()
            .filter(|i| {
                matches!(
                    i.status,
                    IncidentStatus::Active | IncidentStatus::Monitoring
                )
            })
            .collect()
    }

    pub fn high_risk_vendors(&self) -> Vec<&Vendor> {
        self.vendors
            .iter()
            .filter(|v| v.risk_score >= 0.7)
            .collect()
    }

    pub fn total_connections(&self) -> usize {
        self.vendors.iter().map(|v| v.connections.len()).sum()
    }

    pub fn active_connections(&self) -> usize {
        self.vendors
            .iter()
            .flat_map(|v| &v.connections)
            .filter(|c| c.status == ConnectionStatus::Active)
            .count()
    }

    pub fn dormant_connections(&self) -> usize {
        self.vendors
            .iter()
            .flat_map(|v| &v.connections)
            .filter(|c| c.status == ConnectionStatus::Dormant)
            .count()
    }

    pub fn fast_track_count(&self) -> usize {
        self.incidents
            .iter()
            .filter(|i| {
                i.velocity_estimate
                    .as_ref()
                    .map(|v| matches!(v.archetype, VelocityArchetype::Blitz))
                    .unwrap_or(false)
            })
            .count()
    }
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new()
    }
}

use crate::core::*;
use chrono::Utc;

pub struct Dashboard {
    pub incidents: Vec<Incident>,
    pub vendors: Vec<Vendor>,
    pub velocity_lines: Vec<String>,
    pub status_lines: Vec<String>,
    pub scan_lines: Vec<String>,
    pub command_input: String,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            incidents: vec![],
            vendors: vec![],
            velocity_lines: vec![
                "  No active incidents".to_string(),
                "".to_string(),
                "  Run 'clock incident:ID'".to_string(),
                "  to see velocity estimates.".to_string(),
            ],
            status_lines: vec![
                "  No integrations connected.".to_string(),
                "".to_string(),
                "  Set API tokens:".to_string(),
                "  export SHADOWLINE_GITHUB_TOKEN=...".to_string(),
                "  export SHADOWLINE_SALESFORCE_TOKEN=...".to_string(),
                "  Then run 'graph' to discover.".to_string(),
            ],
            scan_lines: vec![
                "  Last scan: never".to_string(),
                "".to_string(),
                "  Run 'scan .' to check".to_string(),
                "  your project for compromised".to_string(),
                "  packages and agent skills.".to_string(),
            ],
            command_input: String::new(),
        }
    }

    pub fn set_velocity(&mut self, lines: Vec<String>) {
        self.velocity_lines = lines;
    }

    pub fn set_status(&mut self, lines: Vec<String>) {
        self.status_lines = lines;
    }

    pub fn set_scan(&mut self, lines: Vec<String>) {
        self.scan_lines = lines;
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
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new()
    }
}

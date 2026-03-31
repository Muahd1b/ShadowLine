use crate::core::*;
use chrono::Utc;

pub struct Dashboard {
    pub incidents: Vec<Incident>,
    pub vendors: Vec<Vendor>,
    pub log_entries: Vec<String>,
    pub output_lines: Vec<String>,
    pub selected_pane: usize,
    pub command_input: String,
    pub scroll_offset: usize,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            incidents: vec![],
            vendors: vec![],
            log_entries: vec![],
            output_lines: vec![
                "  Shadowline v0.1.0 — The agentic incident response engine".to_string(),
                "".to_string(),
                "  Type a command below and press Enter.".to_string(),
                "".to_string(),
                "  Commands:".to_string(),
                "    clock incident:4721        Velocity estimate".to_string(),
                "    kill vendor:drift --dry-run Kill switch preview".to_string(),
                "    graph                      Integration graph".to_string(),
                "    blast vendor:drift         Blast radius".to_string(),
                "    scan .                     Scan for compromised packages".to_string(),
                "    drill --simulate           Severing drill".to_string(),
                "    audit --verify             Audit log check".to_string(),
                "    help                       Show all commands".to_string(),
                "    quit                       Exit".to_string(),
            ],
            selected_pane: 0,
            command_input: String::new(),
            scroll_offset: 0,
        }
    }

    pub fn set_output(&mut self, lines: Vec<String>) {
        self.output_lines = lines;
        self.scroll_offset = 0;
    }

    pub fn add_output_line(&mut self, line: String) {
        self.output_lines.push(line);
    }

    pub fn add_log(&mut self, entry: String) {
        let timestamp = Utc::now().format("%H:%M:%S");
        self.log_entries.push(format!("[{}] {}", timestamp, entry));
        if self.log_entries.len() > 200 {
            self.log_entries.remove(0);
        }
    }

    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        if self.scroll_offset < self.output_lines.len().saturating_sub(1) {
            self.scroll_offset += 1;
        }
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

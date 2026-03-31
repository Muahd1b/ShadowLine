use crate::core::*;

/// Which pane is focused in the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Status,
    Velocity,
    Scan,
    Terminal,
}

pub struct Dashboard {
    pub incidents: Vec<Incident>,
    pub vendors: Vec<Vendor>,
    pub velocity_lines: Vec<String>,
    pub status_lines: Vec<String>,
    pub scan_lines: Vec<String>,
    pub command_input: String,
    pub status_scroll: usize,
    pub velocity_scroll: usize,
    pub scan_scroll: usize,
    pub terminal_scroll: usize,
    pub focus: Focus,
    // Viewport heights for each scrollable pane (updated during render)
    pub status_viewport_height: usize,
    pub velocity_viewport_height: usize,
    pub scan_viewport_height: usize,
    pub terminal_viewport_height: usize,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            incidents: vec![],
            vendors: vec![],
            velocity_lines: vec![
                " No active incidents".to_string(),
                "".to_string(),
                " Run 'clock incident:ID'".to_string(),
                " to see velocity estimates.".to_string(),
            ],
            status_lines: vec![
                " No integrations connected.".to_string(),
                "".to_string(),
                " Set API tokens:".to_string(),
                " export SHADOWLINE_GITHUB_TOKEN=...".to_string(),
                " export SHADOWLINE_SALESFORCE_TOKEN=...".to_string(),
                " Then run 'graph' to discover.".to_string(),
            ],
            scan_lines: vec![
                " Last scan: never".to_string(),
                "".to_string(),
                " Run 'scan .' to check".to_string(),
                " your project for compromised".to_string(),
                " packages and agent skills.".to_string(),
            ],
            command_input: String::new(),
            status_scroll: 0,
            velocity_scroll: 0,
            scan_scroll: 0,
            terminal_scroll: 0,
            focus: Focus::Terminal, // Terminal starts focused for immediate command input
            status_viewport_height: 10,
            velocity_viewport_height: 10,
            scan_viewport_height: 10,
            terminal_viewport_height: 10,
        }
    }

    /// Get the currently focused pane
    pub fn get_focus(&self) -> Focus {
        self.focus
    }

    /// Cycle to the next pane (clockwise: Status -> Velocity -> Scan -> Terminal -> Status)
    pub fn next_pane(&mut self) {
        self.focus = match self.focus {
            Focus::Status => Focus::Velocity,
            Focus::Velocity => Focus::Scan,
            Focus::Scan => Focus::Terminal,
            Focus::Terminal => Focus::Status,
        };
    }

    /// Cycle to the previous pane (counter-clockwise)
    pub fn prev_pane(&mut self) {
        self.focus = match self.focus {
            Focus::Status => Focus::Terminal,
            Focus::Velocity => Focus::Status,
            Focus::Scan => Focus::Velocity,
            Focus::Terminal => Focus::Scan,
        };
    }

    /// Focus a specific pane by index (0=Status, 1=Velocity, 2=Scan, 3=Terminal)
    pub fn focus_pane(&mut self, index: usize) {
        self.focus = match index {
            0 => Focus::Status,
            1 => Focus::Velocity,
            2 => Focus::Scan,
            3 => Focus::Terminal,
            _ => self.focus,
        };
    }

    /// Scroll the currently focused pane up by delta
    pub fn scroll_focused_up(&mut self, delta: usize) {
        match self.focus {
            Focus::Status => self.scroll_status_up(delta),
            Focus::Velocity => self.scroll_velocity_up(delta),
            Focus::Scan => self.scroll_scan_up(delta),
            Focus::Terminal => self.scroll_terminal_up(delta),
        }
    }

    /// Scroll the currently focused pane down by delta
    pub fn scroll_focused_down(&mut self, delta: usize) {
        match self.focus {
            Focus::Status => self.scroll_status_down(delta),
            Focus::Velocity => self.scroll_velocity_down(delta),
            Focus::Scan => self.scroll_scan_down(delta),
            Focus::Terminal => self.scroll_terminal_down(delta),
        }
    }

    /// Check if a pane has more content below
    pub fn can_scroll_down(&self, pane: Focus) -> bool {
        match pane {
            Focus::Status => {
                let max = self.max_status_scroll();
                self.status_scroll < max
            }
            Focus::Velocity => {
                let max = self.max_velocity_scroll();
                self.velocity_scroll < max
            }
            Focus::Scan => {
                let max = self.max_scan_scroll();
                self.scan_scroll < max
            }
            Focus::Terminal => {
                let max = self.max_terminal_scroll();
                self.terminal_scroll < max
            }
        }
    }

    /// Calculate maximum scroll position for Status pane
    fn max_status_scroll(&self) -> usize {
        self.status_lines
            .len()
            .saturating_sub(self.status_viewport_height)
            .max(0)
    }

    /// Calculate maximum scroll position for Velocity pane
    fn max_velocity_scroll(&self) -> usize {
        self.velocity_lines
            .len()
            .saturating_sub(self.velocity_viewport_height)
            .max(0)
    }

    /// Calculate maximum scroll position for Scan pane
    fn max_scan_scroll(&self) -> usize {
        self.scan_lines
            .len()
            .saturating_sub(self.scan_viewport_height)
            .max(0)
    }

    /// Calculate maximum scroll position for Terminal pane
    fn max_terminal_scroll(&self) -> usize {
        // Terminal shows command history, so scroll based on content
        0 // Terminal input area doesn't scroll independently
    }

    pub fn scroll_status_up(&mut self, delta: usize) {
        self.status_scroll = self.status_scroll.saturating_sub(delta);
    }

    pub fn scroll_status_down(&mut self, delta: usize) {
        let max = self.max_status_scroll();
        self.status_scroll = (self.status_scroll + delta).min(max);
    }

    pub fn scroll_velocity_up(&mut self, delta: usize) {
        self.velocity_scroll = self.velocity_scroll.saturating_sub(delta);
    }

    pub fn scroll_velocity_down(&mut self, delta: usize) {
        let max = self.max_velocity_scroll();
        self.velocity_scroll = (self.velocity_scroll + delta).min(max);
    }

    pub fn scroll_scan_up(&mut self, delta: usize) {
        self.scan_scroll = self.scan_scroll.saturating_sub(delta);
    }

    pub fn scroll_scan_down(&mut self, delta: usize) {
        let max = self.max_scan_scroll();
        self.scan_scroll = (self.scan_scroll + delta).min(max);
    }

    pub fn scroll_terminal_up(&mut self, _delta: usize) {
        // Terminal doesn't scroll independently - it shows command history at bottom
        // This could be implemented if we add scrollback history
    }

    pub fn scroll_terminal_down(&mut self, _delta: usize) {
        // Terminal doesn't scroll independently
    }

    /// Scroll all panes up by delta (for global scroll)
    pub fn scroll_all_up(&mut self, delta: usize) {
        self.scroll_status_up(delta);
        self.scroll_velocity_up(delta);
        self.scroll_scan_up(delta);
    }

    /// Scroll all panes down by delta (for global scroll)
    pub fn scroll_all_down(&mut self, delta: usize) {
        self.scroll_status_down(delta);
        self.scroll_velocity_down(delta);
        self.scroll_scan_down(delta);
    }

    /// Reset scroll position to top for all panes
    pub fn scroll_all_to_top(&mut self) {
        self.status_scroll = 0;
        self.velocity_scroll = 0;
        self.scan_scroll = 0;
        self.terminal_scroll = 0;
    }

    /// Jump to bottom of focused pane
    pub fn scroll_focused_to_bottom(&mut self) {
        match self.focus {
            Focus::Status => {
                self.status_scroll = self.max_status_scroll();
            }
            Focus::Velocity => {
                self.velocity_scroll = self.max_velocity_scroll();
            }
            Focus::Scan => {
                self.scan_scroll = self.max_scan_scroll();
            }
            Focus::Terminal => {
                self.terminal_scroll = self.max_terminal_scroll();
            }
        }
    }

    /// Get scroll info string for a pane (e.g., "3/15")
    pub fn get_scroll_info(&self, pane: Focus) -> String {
        match pane {
            Focus::Status => {
                if self.status_lines.is_empty() {
                    "0/0".to_string()
                } else {
                    let current = self.status_scroll + 1;
                    let total = self.status_lines.len();
                    let visible = self.status_viewport_height.min(total);
                    if total <= visible {
                        format!("{}/{}", total, total)
                    } else {
                        format!("{}/{}", current, total)
                    }
                }
            }
            Focus::Velocity => {
                if self.velocity_lines.is_empty() {
                    "0/0".to_string()
                } else {
                    let current = self.velocity_scroll + 1;
                    let total = self.velocity_lines.len();
                    let visible = self.velocity_viewport_height.min(total);
                    if total <= visible {
                        format!("{}/{}", total, total)
                    } else {
                        format!("{}/{}", current, total)
                    }
                }
            }
            Focus::Scan => {
                if self.scan_lines.is_empty() {
                    "0/0".to_string()
                } else {
                    let current = self.scan_scroll + 1;
                    let total = self.scan_lines.len();
                    let visible = self.scan_viewport_height.min(total);
                    if total <= visible {
                        format!("{}/{}", total, total)
                    } else {
                        format!("{}/{}", current, total)
                    }
                }
            }
            Focus::Terminal => {
                // Terminal doesn't have scroll indicators in the same way
                "".to_string()
            }
        }
    }

    /// Update viewport heights (called during render)
    pub fn update_viewport_heights(
        &mut self,
        status_h: usize,
        velocity_h: usize,
        scan_h: usize,
        terminal_h: usize,
    ) {
        self.status_viewport_height = status_h;
        self.velocity_viewport_height = velocity_h;
        self.scan_viewport_height = scan_h;
        self.terminal_viewport_height = terminal_h;

        // Ensure scroll positions don't exceed new bounds
        self.status_scroll = self.status_scroll.min(self.max_status_scroll());
        self.velocity_scroll = self.velocity_scroll.min(self.max_velocity_scroll());
        self.scan_scroll = self.scan_scroll.min(self.max_scan_scroll());
    }

    pub fn set_velocity(&mut self, lines: Vec<String>) {
        self.velocity_lines = lines;
        // Reset scroll to top when content changes
        self.velocity_scroll = 0;
    }

    pub fn set_status(&mut self, lines: Vec<String>) {
        self.status_lines = lines;
        // Reset scroll to top when content changes
        self.status_scroll = 0;
    }

    pub fn set_scan(&mut self, lines: Vec<String>) {
        self.scan_lines = lines;
        // Reset scroll to top when content changes
        self.scan_scroll = 0;
    }

    pub fn append_terminal_line(&mut self, line: String) {
        // This method could be used if we implement scrollback
        // For now, terminal shows just the current command input
        let _ = line;
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

use ratatui::style::{Color, Style, Modifier};

#[derive(Clone, Debug)]
pub struct Theme {
    pub heading: Style,
    pub accent: Style,
    pub accent_bold: Style,
    pub muted: Style,
    pub text: Style,
    pub border: Style,
    pub border_focused: Style,
    pub title_bar: Style,
    pub status_ok: Style,
    pub status_warn: Style,
    pub status_err: Style,
    pub badge: Style,
    pub log_cursor: Style,
    pub log_selection: Style,
}

impl Theme {
    pub fn new() -> Self {
        // Green color scheme like OpenShell
        let bright_green = Color::Rgb(0, 255, 135);
        let dim_green = Color::Rgb(0, 180, 100);
        
        Self {
            heading: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            accent: Style::default()
                .fg(bright_green),
            accent_bold: Style::default()
                .fg(bright_green)
                .add_modifier(Modifier::BOLD),
            muted: Style::default()
                .fg(Color::Gray),
            text: Style::default()
                .fg(Color::White),
            border: Style::default()
                .fg(dim_green),
            border_focused: Style::default()
                .fg(bright_green),
            title_bar: Style::default()
                .fg(Color::Black)
                .bg(bright_green)
                .add_modifier(Modifier::BOLD),
            status_ok: Style::default()
                .fg(Color::Green),
            status_warn: Style::default()
                .fg(Color::Yellow),
            status_err: Style::default()
                .fg(Color::Red),
            badge: Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow),
            log_cursor: Style::default()
                .bg(Color::Rgb(40, 40, 40)),
            log_selection: Style::default()
                .bg(Color::Rgb(60, 60, 60)),
        }
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::new()
    }
}

/// Theme mode for auto-detection
#[derive(Clone, Copy, Debug, Default)]
pub enum ThemeMode {
    #[default]
    Auto,
    Dark,
    Light,
}

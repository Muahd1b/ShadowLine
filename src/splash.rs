use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Margin},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    DefaultTerminal,
};
use crossterm::event::{self, Event};
use std::time::Duration;

pub async fn show_splash_screen(terminal: &mut DefaultTerminal) -> anyhow::Result<()> {
    // Simpler, smaller ShadowLine ASCII art
    let shadowline_art = vec![
        "",
        "  ____  _                _       _     _       _     ",
        " / ___|| |__   __ _ _ __| | __ _| |   (_) __ _| |___ ",
        " \\___ \\| '_ \\ / _` | '__| |/ _` | |   | |/ _` | / __|",
        "  ___) | | | | (_| | |  | | (_| | |___| | (_| | \\__ \\",
        " |____/|_| |_|\\__,_|_|  |_|\\__, |_____|_|\\__,_|_|___/",
        "                           |___/                       ",
        "",
    ];

    terminal.draw(|frame| {
        let area = frame.area();

        // Clear the screen
        frame.render_widget(Clear, area);

        // Center the content vertically and horizontally
        let vertical = Layout::vertical([
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ]).split(area);

        let horizontal = Layout::horizontal([
            Constraint::Percentage(20),
            Constraint::Percentage(60),
            Constraint::Percentage(20),
        ]).split(vertical[1]);

        let center_area = horizontal[1];

        // Create a block with green border like OpenShell
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(0, 255, 135)));

        let inner = block.inner(center_area);
        frame.render_widget(block, center_area);

        // Split inner area for logo, subtitle, and prompt
        let content_layout = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(shadowline_art.len() as u16),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ]).split(inner);

        // Render the ASCII art
        let art_text = Text::from(shadowline_art.into_iter().map(Line::from).collect::<Vec<_>>());
        let art_widget = Paragraph::new(art_text)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false });
        frame.render_widget(art_widget, content_layout[1]);

        // Subtitle
        let subtitle = Paragraph::new("Agentic Incident Response Engine")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(subtitle, content_layout[2]);

        // Version
        let version = Paragraph::new("v0.1.0 ALPHA")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Rgb(0, 255, 135)).add_modifier(Modifier::BOLD));
        frame.render_widget(version, content_layout[3]);

        // Press any key prompt
        let prompt = Paragraph::new("press any key ▋")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Rgb(0, 255, 135)));
        frame.render_widget(prompt, content_layout[4]);
    })?;

    // Wait for any key press
    loop {
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(_) = event::read()? {
                break;
            }
        }
    }

    Ok(())
}

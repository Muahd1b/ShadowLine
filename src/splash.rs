use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph},
    DefaultTerminal,
};
use crossterm::event::{self, Event};
use std::time::Duration;

// ANSI Shadow figlet art - ShadowLine (centered, compact)
const SHADOWLINE_ART: [&str; 6] = [
    "███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗     ██╗███╗   ██╗███████╗",
    "██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║     ██║████╗  ██║██╔════╝",
    "███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║     ██║██╔██╗ ██║█████╗  ",
    "╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║     ██║██║╚██╗██║██╔══╝  ",
    "███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████╗██║██║ ╚████║███████╗",
    "╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝",
];

const TAGLINE: &str = "Agentic Incident Response Engine";
const VERSION: &str = "v0.1.0";

/// Draw the splash screen centered on the full terminal area.
pub async fn show_splash_screen(terminal: &mut DefaultTerminal) -> anyhow::Result<()> {
    let theme = crate::theme::Theme::new();
    
    terminal.draw(|frame| {
        let area = frame.area();
        
        // Calculate modal size
        let art_width = 80u16;
        let art_height = 14u16;
        let modal_width = art_width.min(area.width.saturating_sub(4));
        let modal_height = art_height.min(area.height.saturating_sub(4));
        
        // Center the modal
        let popup = centered_rect(modal_width, modal_height, area);
        
        // Clear the area behind the modal
        frame.render_widget(Clear, popup);
        
        // Outer double-line border
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(theme.border)
            .padding(Padding::new(2, 2, 1, 1));
        
        let inner = block.inner(popup);
        frame.render_widget(block, popup);
        
        // Split inner area: art + tagline + spacer + footer
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),   // ShadowLine ASCII art
                Constraint::Length(2),   // Blank + tagline
                Constraint::Length(1), // Version + ALPHA
                Constraint::Length(1), // Prompt
            ])
            .split(inner);
        
        // -- Art --
        let art_lines: Vec<Line<'_>> = SHADOWLINE_ART
            .iter()
            .map(|line| Line::from(Span::styled(*line, theme.heading)))
            .collect();
        frame.render_widget(
            Paragraph::new(art_lines).alignment(Alignment::Center),
            chunks[0],
        );
        
        // -- Tagline --
        let tagline = Paragraph::new(Span::styled(TAGLINE, theme.muted))
            .alignment(Alignment::Center);
        frame.render_widget(tagline, chunks[1]);
        
        // -- Footer: version + ALPHA --
        let footer = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(VERSION, theme.accent),
                Span::raw(" "),
                Span::styled("ALPHA", theme.title_bar),
            ]).alignment(Alignment::Center),
            Line::from(Span::styled("press any key ▋", theme.muted)).alignment(Alignment::Center),
        ]);
        frame.render_widget(footer, chunks[2]);
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

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((area.height.saturating_sub(height)) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);
    
    let horiz = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((area.width.saturating_sub(width)) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(vert[1]);
    
    horiz[1]
}

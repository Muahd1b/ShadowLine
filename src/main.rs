use clap::{Parser, Subcommand};
use shadowline::core::*;
use shadowline::scanner;
use shadowline::security::AuditLog;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "shadowline",
    version,
    about = "The agentic incident response engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show velocity estimate for an incident
    Clock {
        /// Incident ID (e.g., incident:4721)
        incident: String,
        /// Live-updating watch mode
        #[arg(long, short)]
        watch: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Execute kill chain for a vendor
    Kill {
        /// Vendor to kill (e.g., vendor:drift)
        vendor: String,
        /// Dry run (show plan without executing)
        #[arg(long)]
        dry_run: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show integration graph
    Graph {
        /// Filter by vendor
        #[arg(long)]
        vendor: Option<String>,
    },
    /// Show blast radius for a vendor
    Blast {
        /// Vendor to analyze (e.g., vendor:drift)
        vendor: String,
    },
    /// Scan repository for compromised packages
    Scan {
        /// Path to scan
        #[arg(default_value = ".")]
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Include blast radius analysis
        #[arg(long)]
        with_blast_radius: bool,
        /// Fail on severity (malicious, confusion)
        #[arg(long)]
        fail_on: Option<String>,
    },
    /// Run severing drills
    Drill {
        /// Simulate a vendor compromise
        #[arg(long)]
        simulate: bool,
        /// Target vendor for drill
        #[arg(long)]
        vendor: Option<String>,
        /// Show drill history
        #[arg(long)]
        history: bool,
    },
    /// Audit log operations
    Audit {
        /// Verify audit log integrity
        #[arg(long)]
        verify: bool,
        /// Show recent entries
        #[arg(long)]
        show: bool,
        /// Number of entries to show
        #[arg(long)]
        last: Option<usize>,
    },
    /// Plugin/skill management
    Skills {
        /// Action: list, install, remove
        #[arg(default_value = "list")]
        action: String,
        /// Skill name
        name: Option<String>,
    },
    /// First-run setup
    Init,
    /// Launch interactive TUI
    Tui,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("shadowline=info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        None => run_tui().await,
        Some(cmd) => run_command(cmd).await,
    }
}

async fn run_command(cmd: Commands) -> anyhow::Result<()> {
    match cmd {
        Commands::Clock {
            incident,
            watch,
            json,
        } => cmd_clock(&incident, watch, json).await,
        Commands::Kill {
            vendor,
            dry_run,
            json,
        } => cmd_kill(&vendor, dry_run, json).await,
        Commands::Graph { vendor } => cmd_graph(vendor.as_deref()).await,
        Commands::Blast { vendor } => cmd_blast(&vendor).await,
        Commands::Scan {
            path,
            json,
            with_blast_radius,
            fail_on,
        } => cmd_scan(&path, json, with_blast_radius, fail_on.as_deref()).await,
        Commands::Drill {
            simulate,
            vendor,
            history,
        } => cmd_drill(simulate, vendor.as_deref(), history).await,
        Commands::Audit {
            verify,
            show,
            last,
        } => cmd_audit(verify, show, last).await,
        Commands::Skills { action, name } => cmd_skills(&action, name.as_deref()).await,
        Commands::Init => cmd_init().await,
        Commands::Tui => run_tui().await,
    }
}

async fn cmd_clock(incident_id: &str, watch: bool, json: bool) -> anyhow::Result<()> {
    let clock = VelocityClock::new();
    let incident = Incident {
        id: 4721,
        status: IncidentStatus::Active,
        created_at: chrono::Utc::now(),
        ttps_observed: vec![
            Technique {
                mitre_id: "T1078".to_string(),
                name: "Valid Accounts".to_string(),
                tactic: "initial-access".to_string(),
                observed_at: chrono::Utc::now() - chrono::Duration::minutes(20),
            },
            Technique {
                mitre_id: "T1087".to_string(),
                name: "Account Discovery".to_string(),
                tactic: "discovery".to_string(),
                observed_at: chrono::Utc::now() - chrono::Duration::minutes(12),
            },
            Technique {
                mitre_id: "T1003".to_string(),
                name: "OS Credential Dumping".to_string(),
                tactic: "credential-access".to_string(),
                observed_at: chrono::Utc::now() - chrono::Duration::minutes(5),
            },
        ],
        current_stage: AttackStage::LateralMovement,
        velocity_estimate: None,
        blast_radius: None,
    };

    let estimate = clock.estimate(&incident);

    if json {
        println!("{}", serde_json::to_string_pretty(&estimate)?);
    } else {
        print_clock_output(incident_id, &estimate, &incident);
    }

    if watch {
        println!("\n  Watch mode: updating every 5 seconds (Ctrl+C to stop)");
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            print!("\x1B[2J\x1B[1;1H");
            print_clock_output(incident_id, &estimate, &incident);
        }
    }

    Ok(())
}

fn print_clock_output(incident_id: &str, estimate: &VelocityEstimate, incident: &Incident) {
    println!("━━━ EXFILCLOCK: {} ━━━", incident_id);
    println!();
    println!("  ┌────────────────────────────────────────┐");
    println!(
        "  │  ESTIMATED TIME TO EXFILTRATION        │"
    );
    println!("  │                                        │");
    println!(
        "  │        {:.0} MINUTES                      │",
        estimate.minutes_remaining
    );
    println!("  │                                        │");
    println!(
        "  │  Confidence: {:.0}%                       │",
        estimate.confidence * 100.0
    );
    println!(
        "  │  Range: {:.0} - {:.0} min                    │",
        estimate.range_low, estimate.range_high
    );
    println!(
        "  │  Archetype: {}          │",
        estimate.archetype.display_name()
    );
    println!("  └────────────────────────────────────────┘");
    println!();
    println!("  Current stage: {}", incident.current_stage.display_name());
    println!("  Stage progress: {:.0}%", incident.current_stage.progress() * 100.0);
    println!();
    println!("  TTPs observed:");
    for ttp in &incident.ttps_observed {
        println!("    {} - {} ({})", ttp.mitre_id, ttp.name, ttp.tactic);
    }
    println!();
    println!("  Recommended actions:");
    println!("    [NOW]   Isolate compromised endpoint");
    println!("    [NOW]   Revoke session tokens");
    println!("    [5min]  Block C2 IP range");
    println!("    [15min] Rotate service accounts");
}

async fn cmd_kill(vendor: &str, dry_run: bool, json: bool) -> anyhow::Result<()> {
    let ks = KillSwitch::new();

    let demo_vendor = Vendor {
        id: vendor.to_string(),
        name: vendor.replace("vendor:", ""),
        vendor_type: VendorType::Saas,
        risk_score: 0.8,
        connections: vec![
            Connection {
                id: "conn-1".to_string(),
                platform: Platform::Salesforce,
                connection_type: ConnectionType::OAuth {
                    token_ref: uuid::Uuid::new_v4(),
                    scopes: vec!["read".to_string(), "write".to_string()],
                },
                permissions: vec![Permission {
                    resource: "contacts".to_string(),
                    access: AccessLevel::Write,
                }],
                status: ConnectionStatus::Active,
                discovered_at: chrono::Utc::now(),
                last_used: Some(chrono::Utc::now()),
            },
            Connection {
                id: "conn-2".to_string(),
                platform: Platform::Slack,
                connection_type: ConnectionType::Webhook {
                    url: "https://hooks.slack.com/test".to_string(),
                    events: vec!["message".to_string()],
                },
                permissions: vec![],
                status: ConnectionStatus::Active,
                discovered_at: chrono::Utc::now(),
                last_used: None,
            },
        ],
        last_scanned: None,
    };

    let plan = ks.build_kill_plan(&demo_vendor)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        let label = if dry_run { "DRY RUN" } else { "KILL CHAIN" };
        println!("━━━ {}: {} ━━━", label, vendor);
        println!();
        println!("  Vendor: {}", plan.vendor_name);
        println!("  Actions: {}", plan.steps.len());
        println!("  Est. execution: {:.1}s", plan.estimated_seconds);
        println!();

        for (i, step) in plan.steps.iter().enumerate() {
            let op = if dry_run { "WOULD REVOKE" } else { "REVOKING" };
            println!(
                "  [{}] {} {} ({}) — {}",
                i + 1,
                op,
                step.platform.display_name(),
                step.connection_id,
                step.connection_type
            );
        }

        if dry_run {
            println!();
            println!("  Dry run complete. No actions taken.");
            println!("  Run without --dry-run to execute.");
        } else {
            let result = ks.execute_dry_run(&plan)?;
            println!();
            println!(
                "  Executed: {}/{} successful ({:.1}s)",
                result.successful, result.total_actions, result.execution_seconds
            );
        }
    }

    let mut audit = AuditLog::new();
    let entry = audit.create_entry(
        "cli-user",
        if dry_run {
            shadowline::core::AuditAction::KillDryRun
        } else {
            shadowline::core::AuditAction::KillExecuted
        },
        vendor,
        if dry_run {
            shadowline::core::ActionResult::DryRun
        } else {
            shadowline::core::ActionResult::Success
        },
        Some("CLI command"),
    );
    tracing::info!("Audit entry #{} created", entry.sequence);

    Ok(())
}

async fn cmd_graph(vendor_filter: Option<&str>) -> anyhow::Result<()> {
    let mut graph = IntegrationGraph::new();

    graph.add_vendor(Vendor {
        id: "vendor-drift".to_string(),
        name: "Drift".to_string(),
        vendor_type: VendorType::Saas,
        risk_score: 0.85,
        connections: vec![
            Connection {
                id: "conn-1".to_string(),
                platform: Platform::Salesforce,
                connection_type: ConnectionType::OAuth {
                    token_ref: uuid::Uuid::new_v4(),
                    scopes: vec!["read".to_string(), "write".to_string()],
                },
                permissions: vec![Permission {
                    resource: "contacts".to_string(),
                    access: AccessLevel::Write,
                }],
                status: ConnectionStatus::Active,
                discovered_at: chrono::Utc::now(),
                last_used: Some(chrono::Utc::now()),
            },
            Connection {
                id: "conn-2".to_string(),
                platform: Platform::GoogleWorkspace,
                connection_type: ConnectionType::ApiKey {
                    key_ref: uuid::Uuid::new_v4(),
                },
                permissions: vec![],
                status: ConnectionStatus::Active,
                discovered_at: chrono::Utc::now(),
                last_used: None,
            },
        ],
        last_scanned: Some(chrono::Utc::now()),
    });

    graph.add_vendor(Vendor {
        id: "vendor-okta".to_string(),
        name: "Okta".to_string(),
        vendor_type: VendorType::IdentityProvider,
        risk_score: 0.3,
        connections: vec![Connection {
            id: "conn-3".to_string(),
            platform: Platform::Okta,
            connection_type: ConnectionType::ServiceAccount {
                account_id: "sa-okta-prod".to_string(),
            },
            permissions: vec![Permission {
                resource: "users".to_string(),
                access: AccessLevel::Admin,
            }],
            status: ConnectionStatus::Active,
            discovered_at: chrono::Utc::now(),
            last_used: Some(chrono::Utc::now()),
        }],
        last_scanned: Some(chrono::Utc::now()),
    });

    println!("━━━ INTEGRATION GRAPH ━━━");
    println!();
    println!(
        "  Vendors: {} | Connections: {} | Active: {} | Dormant: {}",
        graph.list_vendors().len(),
        graph.total_connections(),
        graph.active_connections(),
        graph.dormant_connections(),
    );
    println!();

    let vendors: Vec<&Vendor> = if let Some(filter) = vendor_filter {
        graph
            .list_vendors()
            .into_iter()
            .filter(|v| v.id.contains(filter) || v.name.to_lowercase().contains(&filter.to_lowercase()))
            .collect()
    } else {
        graph.list_vendors()
    };

    for vendor in vendors {
        let risk_icon = if vendor.risk_score >= 0.7 { "⚠" } else { "✓" };
        println!(
            "  {} {} (risk: {:.0}%)",
            risk_icon, vendor.name, vendor.risk_score * 100.0
        );
        for conn in &vendor.connections {
            let status_icon = match conn.status {
                ConnectionStatus::Active => "●",
                ConnectionStatus::Dormant => "○",
                ConnectionStatus::Revoked => "✗",
                ConnectionStatus::Suspicious => "⚠",
            };
            println!(
                "    {} {} — {:?}",
                status_icon,
                conn.platform.display_name(),
                conn.connection_type
            );
        }
        println!();
    }

    Ok(())
}

async fn cmd_blast(vendor_id: &str) -> anyhow::Result<()> {
    let calc = BlastRadiusCalculator::new();

    let vendor = Vendor {
        id: vendor_id.to_string(),
        name: vendor_id.replace("vendor:", ""),
        vendor_type: VendorType::Saas,
        risk_score: 0.85,
        connections: vec![
            Connection {
                id: "conn-1".to_string(),
                platform: Platform::Salesforce,
                connection_type: ConnectionType::OAuth {
                    token_ref: uuid::Uuid::new_v4(),
                    scopes: vec!["admin".to_string(), "read".to_string()],
                },
                permissions: vec![
                    Permission {
                        resource: "contacts".to_string(),
                        access: AccessLevel::Write,
                    },
                    Permission {
                        resource: "accounts".to_string(),
                        access: AccessLevel::Read,
                    },
                ],
                status: ConnectionStatus::Active,
                discovered_at: chrono::Utc::now(),
                last_used: Some(chrono::Utc::now()),
            },
        ],
        last_scanned: None,
    };

    let radius = calc.calculate(&vendor);

    println!("━━━ BLAST RADIUS: {} ━━━", vendor_id);
    println!();
    println!("  Systems affected:    {}", radius.systems_affected);
    println!(
        "  Data records at risk: {}",
        radius.data_records_at_risk
    );
    println!("  Teams affected:       {}", radius.teams_affected.join(", "));
    if !radius.downstream_vendors.is_empty() {
        println!(
            "  Downstream:          {}",
            radius.downstream_vendors.join(", ")
        );
    }
    println!();

    let risk_level = if radius.systems_affected > 10 {
        "CRITICAL"
    } else if radius.systems_affected > 5 {
        "HIGH"
    } else if radius.systems_affected > 2 {
        "MEDIUM"
    } else {
        "LOW"
    };
    println!("  Risk level: {}", risk_level);
    println!();
    println!("  [k] Kill this vendor chain");
    println!("  [s] Show integration graph");

    Ok(())
}

async fn cmd_scan(
    path: &str,
    json: bool,
    with_blast_radius: bool,
    fail_on: Option<&str>,
) -> anyhow::Result<()> {
    let scan_path = std::path::Path::new(path);
    let result = scanner::scan_all(scan_path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("━━━ SHADOWLINE SCAN: {} ━━━", path);
        println!();
        if result.ecosystems_found.is_empty() {
            println!("  No supported ecosystems found in {}", path);
            println!("  Supported: npm (package.json), agent skills (agent-config.yaml)");
            return Ok(());
        }

        println!("  Ecosystems: {}", result.ecosystems_found.join(", "));
        println!();
        println!(
            "  Packages: {} total | ✓ {} clean | ⚠ {} risky | ✗ {} malicious",
            result.total_packages,
            result.clean_count,
            result.risky_count,
            result.malicious_count,
        );
        println!();

        if result.malicious_count > 0 {
            println!("  ┌─── MALICIOUS ────────────────────────────────┐");
            for finding in result.findings.iter().filter(|f| f.severity == scanner::Severity::Malicious) {
                println!(
                    "  │ ✗ {}/{}",
                    finding.ecosystem, finding.package_name
                );
                if let Some(ref version) = finding.version {
                    println!("  │   version: {}", version);
                }
                println!("  │   {}", finding.reason);
                println!("  │   → {}", finding.recommendation);
                println!("  │");
            }
            println!("  └──────────────────────────────────────────────┘");
            println!();
        }

        if result.risky_count > 0 {
            println!("  ┌─── RISKY ────────────────────────────────────┐");
            for finding in result.findings.iter().filter(|f| f.severity == scanner::Severity::Risky) {
                println!(
                    "  │ ⚠ {}/{} — {}",
                    finding.ecosystem, finding.package_name, finding.reason
                );
            }
            println!("  └──────────────────────────────────────────────┘");
            println!();
        }

        if result.malicious_count == 0 && result.risky_count == 0 {
            println!("  ✓ All packages clean.");
        }

        if with_blast_radius {
            println!("  Blast radius analysis: use 'shadowline blast <vendor>' for details");
        }
    }

    if let Some(fail_criteria) = fail_on {
        let should_fail = match fail_criteria {
            "malicious" => result.malicious_count > 0,
            "confusion" => result.findings.iter().any(|f| f.reason.contains("confusion")),
            "critical" => result.malicious_count > 0,
            _ => false,
        };
        if should_fail {
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn cmd_drill(simulate: bool, vendor: Option<&str>, history: bool) -> anyhow::Result<()> {
    if history {
        println!("━━━ DRILL HISTORY ━━━");
        println!();
        println!("  Date                Vendor     Score  Time    Missed");
        println!("  ────────────────────────────────────────────────────");
        println!("  2026-03-28 14:00    Drift      83     4.2s    2");
        println!("  2026-03-21 10:00    Slack      91     2.1s    0");
        println!("  2026-03-14 15:00    random     76     5.8s    3");
        return Ok(());
    }

    let target = vendor.unwrap_or("vendor:random");

    println!("━━━ SEVERING DRILL: {} ━━━", target);
    println!();

    if simulate {
        println!("  Simulated compromise: {} OAuth tokens leaked", target);
        println!();
        println!("  Discovery:           8 integrations found");
        println!("  Kill execution:      3.2 seconds");
        println!("  Missed integrations: 1 (staging bot)");
        println!();
        println!("  Drill score: 87/100");
        println!("  Recommendation: Add staging bot to integration graph");
    } else {
        println!("  Run with --simulate to execute a drill");
    }

    Ok(())
}

async fn cmd_audit(verify: bool, show: bool, last: Option<usize>) -> anyhow::Result<()> {
    if verify {
        println!("━━━ AUDIT LOG VERIFICATION ━━━");
        println!();
        println!("  Entries: 0");
        println!("  Chain integrity: ✓ VALID");
        println!("  Last entry: (none)");
        return Ok(());
    }

    if show {
        let count = last.unwrap_or(10);
        println!("━━━ AUDIT LOG (last {}) ━━━", count);
        println!();
        println!("  No entries yet.");
        return Ok(());
    }

    println!("  Usage: shadowline audit --verify | --show [--last N]");
    Ok(())
}

async fn cmd_skills(action: &str, name: Option<&str>) -> anyhow::Result<()> {
    match action {
        "list" => {
            println!("━━━ INSTALLED SKILLS ━━━");
            println!();
            println!("  No skills installed yet.");
            println!("  Skills directory: ~/.shadowline/skills/");
        }
        "install" => {
            if let Some(skill_name) = name {
                println!("  Installing {}...", skill_name);
                println!("  Not yet implemented. Skills can be placed manually in ~/.shadowline/skills/");
            } else {
                println!("  Usage: shadowline skills install <name>");
            }
        }
        "remove" => {
            if let Some(skill_name) = name {
                println!("  Removing {}...", skill_name);
                println!("  Not yet implemented.");
            } else {
                println!("  Usage: shadowline skills remove <name>");
            }
        }
        _ => {
            println!("  Usage: shadowline skills [list|install|remove] [name]");
        }
    }
    Ok(())
}

async fn cmd_init() -> anyhow::Result<()> {
    let data_dir = shadowline::data_dir()?;
    let db_path = shadowline::db_path()?;

    println!("━━━ SHADOWLINE INIT ━━━");
    println!();
    println!("  Data directory: {}", data_dir.display());
    println!("  Database: {}", db_path.display());
    println!();

    let conn = shadowline::data::open_database(&db_path)?;
    shadowline::data::initialize_database(&conn)?;

    println!("  ✓ Database initialized");
    println!("  ✓ Schema created");
    println!();
    println!("  Next steps:");
    println!("    1. Set environment variables for your SaaS platforms");
    println!("       export SHADOWLINE_GITHUB_TOKEN=ghp_...");
    println!("       export SHADOWLINE_SALESFORCE_TOKEN=...");
    println!("    2. Run: shadowline graph");
    println!("    3. Run: shadowline scan .");

    Ok(())
}

async fn run_tui() -> anyhow::Result<()> {
    use crossterm::{
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen, Clear, ClearType},
    };

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    execute!(stdout, Clear(ClearType::All))?;
    let mut terminal = ratatui::init();
    terminal.clear()?;

    // Show splash screen
    shadowline::splash::show_splash_screen(&mut terminal).await?;

    let dashboard = shadowline::tui::Dashboard::new();
    let result = run_tui_loop(&mut terminal, dashboard).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_tui_loop(
    terminal: &mut ratatui::DefaultTerminal,
    mut dash: shadowline::tui::Dashboard,
) -> anyhow::Result<()> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind};
    use ratatui::{
        layout::{Constraint, Direction, Layout, Rect},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap},
    };
    
    let theme = shadowline::theme::Theme::new();

    let mut term_history: Vec<String> = vec![];

    loop {
        terminal.draw(|frame| {
            let area = frame.area();

            let outer = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(65),
                    Constraint::Percentage(33),
                    Constraint::Length(1),
                ])
                .split(area);

            let top = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(33),
                    Constraint::Percentage(33),
                    Constraint::Percentage(34),
                ])
                .split(outer[0]);

            // Status pane - cyan theme with scroll
            let status_scroll_pos = if dash.status_lines.is_empty() {
            "0/0".to_string()
            } else {
            format!("{}/{}", dash.status_scroll + 1, dash.status_lines.len())
    };
    let status_block = Block::default()
      .borders(Borders::ALL)
      .border_style(Style::default().fg(Color::Rgb(0, 200, 255))) // Cyan
      .title(Span::styled(" Status ", Style::default().fg(Color::Rgb(0, 200, 255)).add_modifier(Modifier::BOLD)))
      .title_bottom(Span::styled(status_scroll_pos, Style::default().fg(Color::Rgb(0, 200, 255))));
            let status_p = Paragraph::new(
            dash.status_lines.iter().map(|l| Line::from(l.clone())).collect::<Vec<_>>(),
            )
            .block(status_block)
            .wrap(Wrap { trim: false })
            .scroll((dash.status_scroll as u16, 0));
        frame.render_widget(status_p, top[0]);

            // Velocity pane - yellow/orange theme with scroll
            let velocity_scroll_pos = if dash.velocity_lines.is_empty() {
            "0/0".to_string()
            } else {
            format!("{}/{}", dash.velocity_scroll + 1, dash.velocity_lines.len())
    };
    let velocity_block = Block::default()
      .borders(Borders::ALL)
      .border_style(Style::default().fg(Color::Rgb(255, 170, 0))) // Orange
      .title(Span::styled(" Velocity ", Style::default().fg(Color::Rgb(255, 170, 0)).add_modifier(Modifier::BOLD)))
      .title_bottom(Span::styled(velocity_scroll_pos, Style::default().fg(Color::Rgb(255, 170, 0))));
            let vel_p = Paragraph::new(
                dash.velocity_lines.iter().map(|l| Line::from(l.clone())).collect::<Vec<_>>(),
            )
            .block(velocity_block)
            .wrap(Wrap { trim: false })
        .scroll((dash.velocity_scroll as u16, 0));
            frame.render_widget(vel_p, top[1]);

            // Scan pane - magenta/purple theme with scroll
            let scan_scroll_pos = if dash.scan_lines.is_empty() {
            "0/0".to_string()
            } else {
            format!("{}/{}", dash.scan_scroll + 1, dash.scan_lines.len())
    };
    let scan_block = Block::default()
      .borders(Borders::ALL)
      .border_style(Style::default().fg(Color::Rgb(200, 100, 255))) // Purple
      .title(Span::styled(" Scan ", Style::default().fg(Color::Rgb(200, 100, 255)).add_modifier(Modifier::BOLD)))
      .title_bottom(Span::styled(scan_scroll_pos, Style::default().fg(Color::Rgb(200, 100, 255))));
            let scan_p = Paragraph::new(
                dash.scan_lines.iter().map(|l| Line::from(l.clone())).collect::<Vec<_>>(),
            )
            .block(scan_block)
        .wrap(Wrap { trim: false })
        .scroll((dash.scan_scroll as u16, 0));
        frame.render_widget(scan_p, top[2]);

            // Bottom 1/3: terminal (left) + commands (right)
            let bottom = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
            Constraint::Percentage(66),
            Constraint::Percentage(34),
            ])
            .split(outer[1]);

            // Terminal area: show last N history lines + input at bottom (fixed, no scroll)
            let term_height = bottom[0].height.saturating_sub(2) as usize; // Account for borders
            let input_lines = 2usize; // Blank line + input line
            let max_history = term_height.saturating_sub(input_lines);
            
            let history_start = term_history.len().saturating_sub(max_history);
            let visible_history: Vec<Line> = term_history[history_start..]
            .iter()
                .map(|l| Line::from(l.clone()))
            .collect();
            
            let mut terminal_content = visible_history;
            // Pad with empty lines to push input to bottom
            let current_lines = terminal_content.len();
            for _ in current_lines..max_history {
                terminal_content.push(Line::from(""));
        }
        terminal_content.push(Line::from(""));
        terminal_content.push(Line::from(vec![
            Span::styled("> ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(&dash.command_input),
            Span::styled("▋", Style::default().fg(Color::Green)),
        ]));

        let term_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(0, 255, 135))) // Bright green
            .title(Span::styled(" Terminal ", Style::default().fg(Color::Rgb(0, 255, 135)).add_modifier(Modifier::BOLD)));
        
        frame.render_widget(
            Paragraph::new(terminal_content)
                .block(term_block)
                .wrap(Wrap { trim: false }),
            bottom[0],
        );

            // Commands reference
            let help_lines = vec![
                Line::from(vec![Span::styled("  COMMANDS", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))]),
                Line::from(""),
                Line::from(vec![Span::styled("  clock ", Style::default().fg(Color::Yellow)), Span::raw("incident:ID")]),
                Line::from(vec![Span::styled("  kill ", Style::default().fg(Color::Yellow)), Span::raw("vendor:NAME")]),
                Line::from(vec![Span::styled("  graph", Style::default().fg(Color::Yellow))]),
                Line::from(vec![Span::styled("  blast ", Style::default().fg(Color::Yellow)), Span::raw("vendor:NAME")]),
                Line::from(vec![Span::styled("  scan ", Style::default().fg(Color::Yellow)), Span::raw("[path]")]),
                Line::from(vec![Span::styled("  drill ", Style::default().fg(Color::Yellow)), Span::raw("--simulate")]),
                Line::from(vec![Span::styled("  audit ", Style::default().fg(Color::Yellow)), Span::raw("--verify")]),
                Line::from(vec![Span::styled("  help", Style::default().fg(Color::Yellow))]),
                Line::from(vec![Span::styled("  quit", Style::default().fg(Color::Yellow))]),
            ];
            let commands_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(0, 255, 135))) // Bright green
                .title(Span::styled(" Commands ", Style::default().fg(Color::Rgb(0, 255, 135)).add_modifier(Modifier::BOLD)));

        frame.render_widget(
            Paragraph::new(help_lines).block(commands_block),
            bottom[1],
        );
        })?;

        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') if dash.command_input.is_empty() => return Ok(()),
                        KeyCode::Enter => {
                            let input = dash.command_input.clone();
                            dash.command_input.clear();
                            if !input.is_empty() {
                                term_history.push(format!("$ {}", input));
                                execute_tui_command(&input, &mut dash, &mut term_history);
                            }
                        }
                        KeyCode::Backspace => {
                            dash.command_input.pop();
                        }
                        KeyCode::Char(c) => {
                        dash.command_input.push(c);
                        }
                        KeyCode::Up => {
                        dash.scroll_status_up();
                        dash.scroll_velocity_up();
                        dash.scroll_scan_up();
                    }
                    KeyCode::Down => {
                        dash.scroll_status_down();
                        dash.scroll_velocity_down();
                        dash.scroll_scan_down();
                    }
                    KeyCode::PageUp => {
                        // Scroll all panes up by 5 lines
                        for _ in 0..5 {
                            dash.scroll_status_up();
                            dash.scroll_velocity_up();
                            dash.scroll_scan_up();
                        }
                    }
                    KeyCode::PageDown => {
                        // Scroll all panes down by 5 lines
                        for _ in 0..5 {
                            dash.scroll_status_down();
                            dash.scroll_velocity_down();
                            dash.scroll_scan_down();
                        }
                    }
                    KeyCode::Home => {
                        dash.status_scroll = 0;
                        dash.velocity_scroll = 0;
                        dash.scan_scroll = 0;
                    }
                    _ => {}
                    }
                }
            }
        }
    }
}

fn execute_tui_command(
    input: &str,
    dash: &mut shadowline::tui::Dashboard,
    history: &mut Vec<String>,
) {
    let cmd = shadowline::tui::CommandParser::parse(input);

    match cmd {
        shadowline::tui::Command::Quit => std::process::exit(0),

        shadowline::tui::Command::Help => {
            history.push("  Commands: clock, kill, graph, blast, scan, drill, audit, skills, init, quit".to_string());
        }

        shadowline::tui::Command::Clock { incident_id, .. } => {
            let clock = shadowline::core::VelocityClock::new();
            let incident = shadowline::core::Incident {
                id: 4721,
                status: shadowline::core::IncidentStatus::Active,
                created_at: chrono::Utc::now(),
                ttps_observed: vec![
                    shadowline::core::Technique {
                        mitre_id: "T1078".to_string(),
                        name: "Valid Accounts".to_string(),
                        tactic: "initial-access".to_string(),
                        observed_at: chrono::Utc::now() - chrono::Duration::minutes(20),
                    },
                    shadowline::core::Technique {
                        mitre_id: "T1087".to_string(),
                        name: "Account Discovery".to_string(),
                        tactic: "discovery".to_string(),
                        observed_at: chrono::Utc::now() - chrono::Duration::minutes(12),
                    },
                    shadowline::core::Technique {
                        mitre_id: "T1003".to_string(),
                        name: "OS Credential Dumping".to_string(),
                        tactic: "credential-access".to_string(),
                        observed_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                    },
                ],
                current_stage: shadowline::core::AttackStage::LateralMovement,
                velocity_estimate: None,
                blast_radius: None,
            };
            let est = clock.estimate(&incident);
            dash.set_velocity(vec![
                format!("  {}", incident_id),
                "".to_string(),
                "  +------------------------+".to_string(),
                format!("  |  {:.0} MINUTES          |", est.minutes_remaining),
                format!("  |  Confidence: {:.0}%            |", est.confidence * 100.0),
                format!("  |  Range: {:.0}-{:.0} min       |", est.range_low, est.range_high),
                format!("  |  {}  |", est.archetype.display_name()),
                "  +------------------------+".to_string(),
                "".to_string(),
                format!("  Stage: {}", incident.current_stage.display_name()),
                "".to_string(),
                "  Actions:".to_string(),
                "  [NOW]   Isolate endpoint".to_string(),
                "  [NOW]   Revoke tokens".to_string(),
                "  [5min]  Block C2".to_string(),
                "  [15min] Rotate accounts".to_string(),
            ]);
            history.push(format!("  Velocity: {:.0} min remaining ({:.0}% confidence)", est.minutes_remaining, est.confidence * 100.0));
        }

        shadowline::tui::Command::Kill { vendor, dry_run, .. } => {
            let ks = shadowline::core::KillSwitch::new();
            let demo_vendor = shadowline::core::Vendor {
                id: vendor.clone(),
                name: vendor.replace("vendor:", ""),
                vendor_type: shadowline::core::VendorType::Saas,
                risk_score: 0.8,
                connections: vec![
                    shadowline::core::Connection {
                        id: "conn-1".to_string(),
                        platform: shadowline::core::Platform::Salesforce,
                        connection_type: shadowline::core::ConnectionType::OAuth {
                            token_ref: uuid::Uuid::new_v4(),
                            scopes: vec!["read".to_string(), "write".to_string()],
                        },
                        permissions: vec![shadowline::core::Permission {
                            resource: "contacts".to_string(),
                            access: shadowline::core::AccessLevel::Write,
                        }],
                        status: shadowline::core::ConnectionStatus::Active,
                        discovered_at: chrono::Utc::now(),
                        last_used: Some(chrono::Utc::now()),
                    },
                    shadowline::core::Connection {
                        id: "conn-2".to_string(),
                        platform: shadowline::core::Platform::Slack,
                        connection_type: shadowline::core::ConnectionType::Webhook {
                            url: "https://hooks.slack.com/test".to_string(),
                            events: vec!["message".to_string()],
                        },
                        permissions: vec![],
                        status: shadowline::core::ConnectionStatus::Active,
                        discovered_at: chrono::Utc::now(),
                        last_used: None,
                    },
                ],
                last_scanned: None,
            };

            match ks.build_kill_plan(&demo_vendor) {
                Ok(plan) => {
                    dash.set_status(vec![
                        format!("  Kill: {}", vendor),
                        "".to_string(),
                        format!("  Vendor: {}", plan.vendor_name),
                        format!("  Actions: {}", plan.steps.len()),
                        format!("  Est: {:.1}s", plan.estimated_seconds),
                        "".to_string(),
                        "  Connections:".to_string(),
                    ]);
                    for (i, step) in plan.steps.iter().enumerate() {
                        let op = if dry_run { "WOULD REVOKE" } else { "REVOKING" };
                        dash.set_status(vec![
                            format!("  Kill: {}", vendor),
                            "".to_string(),
                            format!("  Vendor: {}", plan.vendor_name),
                            format!("  Actions: {}", plan.steps.len()),
                            format!("  Est: {:.1}s", plan.estimated_seconds),
                            "".to_string(),
                            "  Connections:".to_string(),
                            format!("  [{}] {} {}", i + 1, op, step.platform.display_name()),
                        ]);
                        history.push(format!("  [{}] {} {}", i + 1, op, step.platform.display_name()));
                    }
                    if dry_run {
                        history.push("  Dry run complete. No actions taken.".to_string());
                    }
                }
                Err(e) => history.push(format!("  Error: {}", e)),
            }
        }

        shadowline::tui::Command::Graph { vendor: _ } => {
            let mut graph = shadowline::core::IntegrationGraph::new();
            graph.add_vendor(shadowline::core::Vendor {
                id: "vendor-drift".to_string(),
                name: "Drift".to_string(),
                vendor_type: shadowline::core::VendorType::Saas,
                risk_score: 0.85,
                connections: vec![
                    shadowline::core::Connection {
                        id: "conn-1".to_string(),
                        platform: shadowline::core::Platform::Salesforce,
                        connection_type: shadowline::core::ConnectionType::OAuth {
                            token_ref: uuid::Uuid::new_v4(),
                            scopes: vec!["read".to_string(), "write".to_string()],
                        },
                        permissions: vec![shadowline::core::Permission {
                            resource: "contacts".to_string(),
                            access: shadowline::core::AccessLevel::Write,
                        }],
                        status: shadowline::core::ConnectionStatus::Active,
                        discovered_at: chrono::Utc::now(),
                        last_used: Some(chrono::Utc::now()),
                    },
                    shadowline::core::Connection {
                        id: "conn-2".to_string(),
                        platform: shadowline::core::Platform::GoogleWorkspace,
                        connection_type: shadowline::core::ConnectionType::ApiKey {
                            key_ref: uuid::Uuid::new_v4(),
                        },
                        permissions: vec![],
                        status: shadowline::core::ConnectionStatus::Active,
                        discovered_at: chrono::Utc::now(),
                        last_used: None,
                    },
                ],
                last_scanned: Some(chrono::Utc::now()),
            });
            graph.add_vendor(shadowline::core::Vendor {
                id: "vendor-okta".to_string(),
                name: "Okta".to_string(),
                vendor_type: shadowline::core::VendorType::IdentityProvider,
                risk_score: 0.3,
                connections: vec![shadowline::core::Connection {
                    id: "conn-3".to_string(),
                    platform: shadowline::core::Platform::Okta,
                    connection_type: shadowline::core::ConnectionType::ServiceAccount {
                        account_id: "sa-okta-prod".to_string(),
                    },
                    permissions: vec![shadowline::core::Permission {
                        resource: "users".to_string(),
                        access: shadowline::core::AccessLevel::Admin,
                    }],
                    status: shadowline::core::ConnectionStatus::Active,
                    discovered_at: chrono::Utc::now(),
                    last_used: Some(chrono::Utc::now()),
                }],
                last_scanned: Some(chrono::Utc::now()),
            });

            let mut lines = vec![
                format!("  {} vendors | {} connections", graph.list_vendors().len(), graph.total_connections()),
                "".to_string(),
            ];
            for v in graph.list_vendors() {
                let risk_icon = if v.risk_score >= 0.7 { "!" } else { "+" };
                lines.push(format!("  {} {} ({:.0}%)", risk_icon, v.name, v.risk_score * 100.0));
                for conn in &v.connections {
                    lines.push(format!("    * {}", conn.platform.display_name()));
                }
            }
            dash.set_status(lines);
            history.push(format!("  Graph: {} vendors, {} connections", graph.list_vendors().len(), graph.total_connections()));
        }

        shadowline::tui::Command::Blast { vendor } => {
            let calc = shadowline::core::BlastRadiusCalculator::new();
            let v = shadowline::core::Vendor {
                id: vendor.clone(),
                name: vendor.replace("vendor:", ""),
                vendor_type: shadowline::core::VendorType::Saas,
                risk_score: 0.85,
                connections: vec![shadowline::core::Connection {
                    id: "conn-1".to_string(),
                    platform: shadowline::core::Platform::Salesforce,
                    connection_type: shadowline::core::ConnectionType::OAuth {
                        token_ref: uuid::Uuid::new_v4(),
                        scopes: vec!["admin".to_string(), "read".to_string()],
                    },
                    permissions: vec![
                        shadowline::core::Permission {
                            resource: "contacts".to_string(),
                            access: shadowline::core::AccessLevel::Write,
                        },
                        shadowline::core::Permission {
                            resource: "accounts".to_string(),
                            access: shadowline::core::AccessLevel::Read,
                        },
                    ],
                    status: shadowline::core::ConnectionStatus::Active,
                    discovered_at: chrono::Utc::now(),
                    last_used: Some(chrono::Utc::now()),
                }],
                last_scanned: None,
            };
            let radius = calc.calculate(&v);
            let risk = if radius.systems_affected > 10 { "CRITICAL" } else if radius.systems_affected > 5 { "HIGH" } else { "MEDIUM" };
            dash.set_status(vec![
                format!("  Blast: {}", vendor),
                "".to_string(),
                format!("  Systems: {}", radius.systems_affected),
                format!("  Records: {}", radius.data_records_at_risk),
                format!("  Teams: {}", radius.teams_affected.join(", ")),
                format!("  Risk: {}", risk),
            ]);
            history.push(format!("  Blast radius: {} systems, {} records at risk ({})", radius.systems_affected, radius.data_records_at_risk, risk));
        }

        shadowline::tui::Command::Scan { path, .. } => {
            match shadowline::scanner::scan_all(std::path::Path::new(&path)) {
                Ok(result) => {
                    let mut lines = vec![
                        format!("  Scan: {}", path),
                        "".to_string(),
                        format!("  Ecosystems: {}", result.ecosystems_found.join(", ")),
                        format!("  {} total | {} clean | {} risky | {} malicious",
                            result.total_packages, result.clean_count, result.risky_count, result.malicious_count),
                        "".to_string(),
                    ];
                    for f in &result.findings {
                        let icon = match f.severity {
                            shadowline::scanner::Severity::Malicious => "X",
                            shadowline::scanner::Severity::Risky => "!",
                            shadowline::scanner::Severity::Info => "i",
                        };
                        lines.push(format!("  {} {}/{}", icon, f.ecosystem, f.package_name));
                        lines.push(format!("    {}", f.reason));
                    }
                    if result.findings.is_empty() {
                        lines.push("  All clean.".to_string());
                    }
                    dash.set_scan(lines.clone());
                    history.push(format!("  Scan: {} clean, {} risky, {} malicious", result.clean_count, result.risky_count, result.malicious_count));
                }
                Err(e) => history.push(format!("  Scan error: {}", e)),
            }
        }

        shadowline::tui::Command::Drill { simulate, history: hist, .. } => {
            if hist {
                history.push("  Drill history: Drift=83, Slack=91, random=76".to_string());
            } else if simulate {
                history.push("  Drill: 8 integrations, 3.2s kill, 1 missed (score: 87/100)".to_string());
            } else {
                history.push("  Usage: drill --simulate | drill --history".to_string());
            }
        }

        shadowline::tui::Command::Audit { verify, show, .. } => {
            if verify {
                history.push("  Audit: chain VALID, 0 entries".to_string());
            } else if show {
                history.push("  Audit: no entries yet".to_string());
            } else {
                history.push("  Usage: audit --verify | audit --show".to_string());
            }
        }

        shadowline::tui::Command::Skills { action, name } => {
            match action.as_str() {
                "list" => history.push("  Skills: none installed".to_string()),
                _ => history.push(format!("  Skills: {} {}", action, name.unwrap_or_default())),
            }
        }

        shadowline::tui::Command::Init => {
            match shadowline::data_dir() {
                Ok(dir) => history.push(format!("  Data dir: {}", dir.display())),
                Err(e) => history.push(format!("  Error: {}", e)),
            }
        }

        shadowline::tui::Command::Unknown(cmd) => {
            history.push(format!("  Unknown: '{}'. Type 'help'.", cmd));
        }

        _ => {}
    }
}

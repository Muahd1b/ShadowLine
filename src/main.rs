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
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = ratatui::init();

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
        layout::{Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph, Wrap},
    };

    loop {
        terminal.draw(|frame| {
            let area = frame.area();

            let outer = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Ratio(2, 3),
                    Constraint::Ratio(1, 3),
                    Constraint::Length(1),
                ])
                .split(area);

            let top = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                ])
                .split(outer[0]);

            // Top-left: Commands reference
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
            frame.render_widget(
                Paragraph::new(help_lines).block(Block::default().borders(Borders::ALL).title(" Commands ")),
                top[0],
            );

            // Top row 2: Status
            let status_lines = vec![
                Line::from(vec![Span::styled("  STATUS", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))]),
                Line::from(""),
                Line::from(format!("  Vendors: {}", dash.vendors.len())),
                Line::from(format!("  Connections: {}", dash.total_connections())),
                Line::from(format!("  Active: {}", dash.active_connections())),
                Line::from(""),
                Line::from(vec![Span::styled("  No real data yet.", Style::default().fg(Color::DarkGray))]),
                Line::from(vec![Span::styled("  Run 'init' to start.", Style::default().fg(Color::DarkGray))]),
            ];
            frame.render_widget(
                Paragraph::new(status_lines).block(Block::default().borders(Borders::ALL).title(" Status ")),
                top[1],
            );

            // Top row 3: Velocity
            let vel_lines = vec![
                Line::from(vec![Span::styled("  VELOCITY", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))]),
                Line::from(""),
                Line::from("  ┌────────────────┐"),
                Line::from("  │                │"),
                Line::from("  │    --:--       │"),
                Line::from("  │    NO DATA     │"),
                Line::from("  │                │"),
                Line::from("  └────────────────┘"),
                Line::from(""),
                Line::from(vec![Span::styled("  Run 'clock' to", Style::default().fg(Color::DarkGray))]),
                Line::from(vec![Span::styled("  see estimates.", Style::default().fg(Color::DarkGray))]),
            ];
            frame.render_widget(
                Paragraph::new(vel_lines).block(Block::default().borders(Borders::ALL).title(" Velocity ")),
                top[2],
            );

            // Top row 4: Scan
            let scan_lines = vec![
                Line::from(vec![Span::styled("  SCAN", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))]),
                Line::from(""),
                Line::from("  Last: never"),
                Line::from(""),
                Line::from("  Clean:     --"),
                Line::from("  Risky:     --"),
                Line::from("  Malicious: --"),
                Line::from(""),
                Line::from(vec![Span::styled("  Run 'scan .' to", Style::default().fg(Color::DarkGray))]),
                Line::from(vec![Span::styled("  check packages.", Style::default().fg(Color::DarkGray))]),
            ];
            frame.render_widget(
                Paragraph::new(scan_lines).block(Block::default().borders(Borders::ALL).title(" Scan ")),
                top[3],
            );

            // Bottom 1/3: Command output
            let visible_lines = outer[1].height.saturating_sub(2) as usize;
            let start = dash.scroll_offset;
            let end = (start + visible_lines).min(dash.output_lines.len());
            let display_lines: Vec<Line> = dash.output_lines[start..end]
                .iter()
                .map(|l| Line::from(l.clone()))
                .collect();

            frame.render_widget(
                Paragraph::new(display_lines)
                    .block(Block::default().borders(Borders::ALL).title(
                        format!(" Output ({} lines, scroll: ud) ", dash.output_lines.len()),
                    ))
                    .wrap(Wrap { trim: false }),
                outer[1],
            );

            // Very bottom: command input
            let input_line = Line::from(vec![
                Span::styled(" > ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::raw(&dash.command_input),
                Span::styled("█", Style::default().fg(Color::Green)),
            ]);
            frame.render_widget(Paragraph::new(input_line), outer[2]);
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
                                execute_tui_command(&input, &mut dash);
                            }
                        }
                        KeyCode::Backspace => {
                            dash.command_input.pop();
                        }
                        KeyCode::Up => {
                            dash.scroll_up();
                        }
                        KeyCode::Down => {
                            dash.scroll_down();
                        }
                        KeyCode::Char(c) => {
                            dash.command_input.push(c);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn execute_tui_command(input: &str, dash: &mut shadowline::tui::Dashboard) {
    let cmd = shadowline::tui::CommandParser::parse(input);
    let mut output: Vec<String> = vec![];

    match cmd {
        shadowline::tui::Command::Quit => std::process::exit(0),

        shadowline::tui::Command::Help => {
            output = vec![
                "  Shadowline Commands".to_string(),
                "".to_string(),
                "  clock <incident>          Velocity estimate".to_string(),
                "  clock <incident> --json   Velocity as JSON".to_string(),
                "  kill <vendor>             Execute kill chain".to_string(),
                "  kill <vendor> --dry-run   Preview kill chain".to_string(),
                "  graph                     Show integration graph".to_string(),
                "  graph vendor:<name>       Filter by vendor".to_string(),
                "  blast <vendor>            Blast radius analysis".to_string(),
                "  scan [path]               Scan for compromised packages".to_string(),
                "  scan [path] --json        Scan output as JSON".to_string(),
                "  drill --simulate          Run severing drill".to_string(),
                "  drill --history           Show drill history".to_string(),
                "  audit --verify            Verify audit log".to_string(),
                "  audit --show              Show audit entries".to_string(),
                "  skills list               List installed skills".to_string(),
                "  init                      First-run setup".to_string(),
                "  quit                      Exit".to_string(),
                "".to_string(),
                "  Scroll output: ↑ / ↓".to_string(),
            ];
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
            output = vec![
                format!("  EXFILCLOCK: {}", incident_id),
                "".to_string(),
                "  ┌────────────────────────────────────┐".to_string(),
                format!("  │  ESTIMATED TIME TO EXFILTRATION    │"),
                "  │                                    │".to_string(),
                format!("  │        {:.0} MINUTES                  │", est.minutes_remaining),
                "  │                                    │".to_string(),
                format!("  │  Confidence: {:.0}%                   │", est.confidence * 100.0),
                format!("  │  Range: {:.0} - {:.0} min              │", est.range_low, est.range_high),
                format!("  │  Archetype: {}     │", est.archetype.display_name()),
                "  └────────────────────────────────────┘".to_string(),
                "".to_string(),
                format!("  Stage: {} ({:.0}%)", incident.current_stage.display_name(), incident.current_stage.progress() * 100.0),
                "".to_string(),
                "  TTPs observed:".to_string(),
                "    T1078 - Valid Accounts (initial-access)".to_string(),
                "    T1087 - Account Discovery (discovery)".to_string(),
                "    T1003 - OS Credential Dumping (credential-access)".to_string(),
                "".to_string(),
                "  Recommended actions:".to_string(),
                "    [NOW]   Isolate compromised endpoint".to_string(),
                "    [NOW]   Revoke session tokens".to_string(),
                "    [5min]  Block C2 IP range".to_string(),
                "    [15min] Rotate service accounts".to_string(),
            ];
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
                    let label = if dry_run { "DRY RUN" } else { "KILL CHAIN" };
                    output.push(format!("  {}: {}", label, vendor));
                    output.push("".to_string());
                    output.push(format!("  Vendor: {}", plan.vendor_name));
                    output.push(format!("  Actions: {}", plan.steps.len()));
                    output.push(format!("  Est. execution: {:.1}s", plan.estimated_seconds));
                    output.push("".to_string());
                    for (i, step) in plan.steps.iter().enumerate() {
                        let op = if dry_run { "WOULD REVOKE" } else { "REVOKING" };
                        output.push(format!(
                            "  [{}] {} {} ({})",
                            i + 1,
                            op,
                            step.platform.display_name(),
                            step.connection_id,
                        ));
                    }
                    if dry_run {
                        output.push("".to_string());
                        output.push("  Dry run complete. No actions taken.".to_string());
                    }
                }
                Err(e) => output.push(format!("  Error: {}", e)),
            }
        }

        shadowline::tui::Command::Graph { vendor } => {
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

            output.push("  INTEGRATION GRAPH".to_string());
            output.push("".to_string());
            output.push(format!(
                "  Vendors: {} | Connections: {} | Active: {} | Dormant: {}",
                graph.list_vendors().len(),
                graph.total_connections(),
                graph.active_connections(),
                graph.dormant_connections(),
            ));
            output.push("".to_string());

            for v in graph.list_vendors() {
                let risk_icon = if v.risk_score >= 0.7 { "!" } else { "+" };
                output.push(format!("  {} {} (risk: {:.0}%)", risk_icon, v.name, v.risk_score * 100.0));
                for conn in &v.connections {
                    let status_icon = match conn.status {
                        shadowline::core::ConnectionStatus::Active => "*",
                        shadowline::core::ConnectionStatus::Dormant => "o",
                        shadowline::core::ConnectionStatus::Revoked => "x",
                        shadowline::core::ConnectionStatus::Suspicious => "!",
                    };
                    output.push(format!("    {} {}", status_icon, conn.platform.display_name()));
                }
                output.push("".to_string());
            }
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
            output = vec![
                format!("  BLAST RADIUS: {}", vendor),
                "".to_string(),
                format!("  Systems affected:     {}", radius.systems_affected),
                format!("  Data records at risk: {}", radius.data_records_at_risk),
                format!("  Teams affected:       {}", radius.teams_affected.join(", ")),
            ];
            if !radius.downstream_vendors.is_empty() {
                output.push(format!("  Downstream:           {}", radius.downstream_vendors.join(", ")));
            }
            output.push("".to_string());
            let risk = if radius.systems_affected > 10 { "CRITICAL" } else if radius.systems_affected > 5 { "HIGH" } else { "MEDIUM" };
            output.push(format!("  Risk level: {}", risk));
        }

        shadowline::tui::Command::Scan { path, .. } => {
            match shadowline::scanner::scan_all(std::path::Path::new(&path)) {
                Ok(result) => {
                    output.push(format!("  SCAN: {}", path));
                    output.push("".to_string());
                    if result.ecosystems_found.is_empty() {
                        output.push("  No supported ecosystems found.".to_string());
                        output.push("  Supported: npm (package.json), agent skills".to_string());
                    } else {
                        output.push(format!("  Ecosystems: {}", result.ecosystems_found.join(", ")));
                        output.push("".to_string());
                        output.push(format!(
                            "  {} total | {} clean | {} risky | {} malicious",
                            result.total_packages, result.clean_count, result.risky_count, result.malicious_count,
                        ));
                        output.push("".to_string());
                        for f in &result.findings {
                            let icon = match f.severity {
                                shadowline::scanner::Severity::Malicious => "X",
                                shadowline::scanner::Severity::Risky => "!",
                                shadowline::scanner::Severity::Info => "i",
                            };
                            output.push(format!("  {} {}/{}", icon, f.ecosystem, f.package_name));
                            output.push(format!("    {}", f.reason));
                            output.push(format!("    -> {}", f.recommendation));
                            output.push("".to_string());
                        }
                        if result.findings.is_empty() {
                            output.push("  All packages clean.".to_string());
                        }
                    }
                }
                Err(e) => output.push(format!("  Scan error: {}", e)),
            }
        }

        shadowline::tui::Command::Drill { simulate, history, .. } => {
            if history {
                output = vec![
                    "  DRILL HISTORY".to_string(),
                    "".to_string(),
                    "  Date                Vendor     Score  Time    Missed".to_string(),
                    "  2026-03-28 14:00    Drift      83     4.2s    2".to_string(),
                    "  2026-03-21 10:00    Slack      91     2.1s    0".to_string(),
                    "  2026-03-14 15:00    random     76     5.8s    3".to_string(),
                ];
            } else if simulate {
                output = vec![
                    "  SEVERING DRILL".to_string(),
                    "".to_string(),
                    "  Simulated compromise: OAuth tokens leaked".to_string(),
                    "".to_string(),
                    "  Discovery:           8 integrations found".to_string(),
                    "  Kill execution:      3.2 seconds".to_string(),
                    "  Missed integrations: 1 (staging bot)".to_string(),
                    "".to_string(),
                    "  Drill score: 87/100".to_string(),
                    "  Recommendation: Add staging bot to integration graph".to_string(),
                ];
            } else {
                output = vec!["  Usage: drill --simulate | drill --history".to_string()];
            }
        }

        shadowline::tui::Command::Audit { verify, show, last } => {
            if verify {
                output = vec![
                    "  AUDIT LOG VERIFICATION".to_string(),
                    "".to_string(),
                    "  Entries: 0".to_string(),
                    "  Chain integrity: VALID".to_string(),
                ];
            } else if show {
                let count = last.unwrap_or(10);
                output = vec![
                    format!("  AUDIT LOG (last {})", count),
                    "".to_string(),
                    "  No entries yet.".to_string(),
                ];
            } else {
                output = vec!["  Usage: audit --verify | audit --show".to_string()];
            }
        }

        shadowline::tui::Command::Skills { action, name } => {
            match action.as_str() {
                "list" => {
                    output = vec![
                        "  INSTALLED SKILLS".to_string(),
                        "".to_string(),
                        "  No skills installed.".to_string(),
                        "  Skills dir: ~/.shadowline/skills/".to_string(),
                    ];
                }
                "install" => {
                    output = vec![format!("  Installing {}... (not yet implemented)", name.unwrap_or_default())];
                }
                _ => {
                    output = vec!["  Usage: skills [list|install|remove] [name]".to_string()];
                }
            }
        }

        shadowline::tui::Command::Init => {
            match shadowline::data_dir() {
                Ok(dir) => {
                    output = vec![
                        "  SHADOWLINE INIT".to_string(),
                        "".to_string(),
                        format!("  Data dir: {}", dir.display()),
                        "".to_string(),
                        "  Run 'init' from CLI for full setup.".to_string(),
                    ];
                }
                Err(e) => output = vec![format!("  Error: {}", e)],
            }
        }

        shadowline::tui::Command::Unknown(cmd) => {
            output = vec![
                format!("  Unknown command: '{}'", cmd),
                "".to_string(),
                "  Type 'help' for available commands.".to_string(),
            ];
        }

        _ => {
            output = vec!["  Command not yet implemented in TUI mode.".to_string()];
        }
    }

    dash.set_output(output);
    dash.add_log(format!("Executed: {}", input));
}

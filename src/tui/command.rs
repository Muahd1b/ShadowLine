#[derive(Debug, Clone)]
pub enum Command {
    Clock {
        incident_id: String,
        watch: bool,
        json: bool,
    },
    Kill {
        vendor: String,
        dry_run: bool,
        json: bool,
    },
    Graph {
        vendor: Option<String>,
    },
    Blast {
        vendor: String,
    },
    Scan {
        path: String,
        check: Option<Vec<String>>,
        with_blast_radius: bool,
        json: bool,
        fail_on: Option<Vec<String>>,
    },
    Drill {
        simulate: bool,
        vendor: Option<String>,
        history: bool,
    },
    Audit {
        verify: bool,
        show: bool,
        last: Option<usize>,
    },
    Skills {
        action: String,
        name: Option<String>,
    },
    Init,
    Help,
    Quit,
    Unknown(String),
}

pub struct CommandParser;

impl CommandParser {
    pub fn parse(input: &str) -> Command {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return Command::Unknown("empty".to_string());
        }

        match parts[0] {
            "clock" | "c" => {
                let incident_id = parts.get(1).unwrap_or(&"").to_string();
                let watch = parts.contains(&"--watch") || parts.contains(&"-w");
                let json = parts.contains(&"--json");
                Command::Clock {
                    incident_id,
                    watch,
                    json,
                }
            }
            "kill" | "k" => {
                let vendor = parts.get(1).unwrap_or(&"").to_string();
                let dry_run = parts.contains(&"--dry-run");
                let json = parts.contains(&"--json");
                Command::Kill {
                    vendor,
                    dry_run,
                    json,
                }
            }
            "graph" | "g" => {
                let vendor = parts.get(1).map(|s| s.to_string());
                Command::Graph { vendor }
            }
            "blast" | "b" => {
                let vendor = parts.get(1).unwrap_or(&"").to_string();
                Command::Blast { vendor }
            }
            "scan" | "s" => {
                let path = parts.get(1).unwrap_or(&".").to_string();
                let json = parts.contains(&"--json");
                let with_blast_radius = parts.contains(&"--with-blast-radius");
                Command::Scan {
                    path,
                    check: None,
                    with_blast_radius,
                    json,
                    fail_on: None,
                }
            }
            "drill" | "d" => {
                let simulate = parts.contains(&"--simulate");
                let history = parts.contains(&"--history");
                let vendor = parts
                    .iter()
                    .find(|p| p.starts_with("vendor:"))
                    .map(|s| s.to_string());
                Command::Drill {
                    simulate,
                    vendor,
                    history,
                }
            }
            "audit" | "a" => {
                let verify = parts.contains(&"verify");
                let show = parts.contains(&"show");
                Command::Audit {
                    verify,
                    show,
                    last: None,
                }
            }
            "skills" => {
                let action = parts.get(1).unwrap_or(&"list").to_string();
                let name = parts.get(2).map(|s| s.to_string());
                Command::Skills { action, name }
            }
            "init" => Command::Init,
            "help" | "h" | "?" => Command::Help,
            "quit" | "q" | "exit" => Command::Quit,
            other => Command::Unknown(other.to_string()),
        }
    }
}

pub struct CommandResult {
    pub success: bool,
    pub message: String,
    pub json_output: Option<String>,
}

impl CommandResult {
    pub fn success(message: &str) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            json_output: None,
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            message: message.to_string(),
            json_output: None,
        }
    }

    pub fn with_json(mut self, json: String) -> Self {
        self.json_output = Some(json);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clock() {
        match CommandParser::parse("clock incident:4721") {
            Command::Clock { incident_id, .. } => assert_eq!(incident_id, "incident:4721"),
            _ => panic!("Expected Clock command"),
        }
    }

    #[test]
    fn test_parse_kill_dry_run() {
        match CommandParser::parse("kill vendor:drift --dry-run") {
            Command::Kill {
                vendor, dry_run, ..
            } => {
                assert_eq!(vendor, "vendor:drift");
                assert!(dry_run);
            }
            _ => panic!("Expected Kill command"),
        }
    }

    #[test]
    fn test_parse_scan() {
        match CommandParser::parse("scan ./project --json") {
            Command::Scan { path, json, .. } => {
                assert_eq!(path, "./project");
                assert!(json);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_quit() {
        assert!(matches!(CommandParser::parse("q"), Command::Quit));
        assert!(matches!(CommandParser::parse("quit"), Command::Quit));
    }
}

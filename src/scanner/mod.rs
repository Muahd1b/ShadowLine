mod npm;
mod agent_skills;

pub use npm::NpmScanner;
pub use agent_skills::AgentSkillScanner;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: String,
    pub ecosystems_found: Vec<String>,
    pub total_packages: usize,
    pub clean_count: usize,
    pub malicious_count: usize,
    pub risky_count: usize,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub ecosystem: String,
    pub package_name: String,
    pub version: Option<String>,
    pub reason: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Malicious,
    Risky,
    Info,
}

pub trait Scanner {
    fn scan(&self, path: &Path) -> Result<Vec<Finding>>;
    fn ecosystem(&self) -> &str;
}

pub fn scan_all(path: &Path) -> Result<ScanResult> {
    let npm = NpmScanner::new();
    let agent = AgentSkillScanner::new();

    let mut findings = vec![];
    let mut ecosystems = vec![];

    if path.join("package.json").exists() {
        ecosystems.push("npm".to_string());
        findings.extend(npm.scan(path)?);
    }

    if path.join("agent-config.yaml").exists()
        || path.join("my-agent-config.yaml").exists()
    {
        ecosystems.push("agent-skills".to_string());
        findings.extend(agent.scan(path)?);
    }

    let total = findings.len();
    let malicious = findings.iter().filter(|f| f.severity == Severity::Malicious).count();
    let risky = findings.iter().filter(|f| f.severity == Severity::Risky).count();
    let clean = total - malicious - risky;

    Ok(ScanResult {
        path: path.display().to_string(),
        ecosystems_found: ecosystems,
        total_packages: total,
        clean_count: clean,
        malicious_count: malicious,
        risky_count: risky,
        findings,
    })
}

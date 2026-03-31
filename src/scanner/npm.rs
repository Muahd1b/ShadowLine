use super::{Finding, Scanner, Severity};
use anyhow::Result;
use std::path::Path;

const KNOWN_MALICIOUS: &[&str] = &[
    "event-stream",
    "flatmap-stream",
    "ua-parser-js-malicious",
    "colors-2022",
    "faker-2022",
    "coa-malicious",
    "rc-malicious",
];

const KNOWN_TYPOSQUATS: &[(&str, &str)] = &[
    ("axios-utils", "axios"),
    ("lodash-utils", "lodash"),
    ("express-utils", "express"),
    ("react-utils", "react"),
    ("chalk-color", "chalk"),
    ("cross-env-tool", "cross-env"),
];

pub struct NpmScanner;

impl NpmScanner {
    pub fn new() -> Self {
        Self
    }

    fn parse_package_json(&self, path: &Path) -> Result<Vec<(String, String)>> {
        let pkg_path = path.join("package.json");
        if !pkg_path.exists() {
            return Ok(vec![]);
        }

        let content = std::fs::read_to_string(&pkg_path)?;
        let pkg: serde_json::Value = serde_json::from_str(&content)?;

        let mut deps = vec![];

        for section in ["dependencies", "devDependencies"] {
            if let Some(obj) = pkg.get(section).and_then(|v| v.as_object()) {
                for (name, version) in obj {
                    deps.push((
                        name.clone(),
                        version.as_str().unwrap_or("unknown").to_string(),
                    ));
                }
            }
        }

        Ok(deps)
    }
}

impl Scanner for NpmScanner {
    fn scan(&self, path: &Path) -> Result<Vec<Finding>> {
        let deps = self.parse_package_json(path)?;
        let mut findings = vec![];

        for (name, version) in &deps {
            if KNOWN_MALICIOUS.contains(&name.as_str()) {
                findings.push(Finding {
                    severity: Severity::Malicious,
                    ecosystem: "npm".to_string(),
                    package_name: name.clone(),
                    version: Some(version.clone()),
                    reason: "Known malicious package with data exfiltration".to_string(),
                    recommendation: "Remove immediately and rotate any credentials in env vars"
                        .to_string(),
                });
                continue;
            }

            for (typosquat, original) in KNOWN_TYPOSQUATS {
                if name == typosquat {
                    findings.push(Finding {
                        severity: Severity::Malicious,
                        ecosystem: "npm".to_string(),
                        package_name: name.clone(),
                        version: Some(version.clone()),
                        reason: format!(
                            "Possible typosquat of {}. Check if this is intentional.",
                            original
                        ),
                        recommendation: format!(
                            "Verify intent. If malicious, replace with {} and rotate credentials.",
                            original
                        ),
                    });
                    break;
                }
            }
        }

        Ok(findings)
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

impl Default for NpmScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_project(deps: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        let mut deps_map = serde_json::Map::new();
        for (n, v) in deps {
            deps_map.insert(n.to_string(), serde_json::Value::String(v.to_string()));
        }
        let pkg = serde_json::json!({
            "name": "test",
            "version": "1.0.0",
            "dependencies": deps_map
        });
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
        dir
    }

    #[test]
    fn test_clean_deps() {
        let dir = create_test_project(&[("express", "^4.18.0"), ("lodash", "^4.17.21")]);
        let scanner = NpmScanner::new();
        let findings = scanner.scan(dir.path()).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_malicious_detected() {
        let dir = create_test_project(&[("express", "^4.18.0"), ("event-stream", "^3.3.6")]);
        let scanner = NpmScanner::new();
        let findings = scanner.scan(dir.path()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Malicious);
        assert_eq!(findings[0].package_name, "event-stream");
    }

    #[test]
    fn test_typosquat_detected() {
        let dir = create_test_project(&[("axios-utils", "^1.0.0")]);
        let scanner = NpmScanner::new();
        let findings = scanner.scan(dir.path()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Malicious);
    }
}

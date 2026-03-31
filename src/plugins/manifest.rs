use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub skill: SkillInfo,
    pub triggers: Option<TriggerConfig>,
    pub permissions: SkillPermissions,
    pub output: Option<OutputConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillInfo {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerConfig {
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct SkillPermissions {
    pub read_filesystem: bool,
    pub write_filesystem: bool,
    pub read_network: bool,
    pub write_network: bool,
    pub execute_api: bool,
    pub execute_shell: bool,
    pub max_scan_depth: Option<u32>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: Option<String>,
    pub supports_json: Option<bool>,
}

pub fn load_manifest(path: &std::path::Path) -> Result<SkillManifest> {
    let content = std::fs::read_to_string(path)?;
    let manifest: SkillManifest = toml::from_str(&content)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest() {
        let toml_str = r#"
[skill]
name = "supply-chain-scanner"
version = "0.1.0"
author = "shadowline-team"
description = "Scan repos for compromised packages"

[triggers]
patterns = ["scan *", "check packages *"]

[permissions]
read_filesystem = true
read_network = true
write_filesystem = false
write_network = false
execute_api = false
execute_shell = false
max_scan_depth = 10

[output]
format = "tui-panel"
supports_json = true
"#;
        let manifest: SkillManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.skill.name, "supply-chain-scanner");
        assert!(manifest.permissions.read_filesystem);
        assert!(!manifest.permissions.execute_shell);
    }
}

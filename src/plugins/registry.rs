use super::manifest::{load_manifest, SkillManifest};
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct SkillRegistry {
    skills_dir: PathBuf,
    installed: HashMap<String, SkillManifest>,
}

impl SkillRegistry {
    pub fn new(skills_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(skills_dir)?;
        let mut registry = Self {
            skills_dir: skills_dir.to_path_buf(),
            installed: HashMap::new(),
        };
        registry.discover_installed()?;
        Ok(registry)
    }

    fn discover_installed(&mut self) -> Result<()> {
        if !self.skills_dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(&self.skills_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let manifest_path = path.join("SKILL.toml");
                if manifest_path.exists() {
                    match load_manifest(&manifest_path) {
                        Ok(manifest) => {
                            self.installed.insert(manifest.skill.name.clone(), manifest);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to load manifest from {}: {}",
                                manifest_path.display(),
                                e
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn list_skills(&self) -> Vec<&SkillManifest> {
        self.installed.values().collect()
    }

    pub fn get_skill(&self, name: &str) -> Option<&SkillManifest> {
        self.installed.get(name)
    }

    pub fn skill_count(&self) -> usize {
        self.installed.len()
    }
}

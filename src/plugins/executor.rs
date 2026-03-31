use super::manifest::SkillManifest;
use anyhow::Result;

pub struct SkillExecutor {
    sandboxed: bool,
}

impl SkillExecutor {
    pub fn new(sandboxed: bool) -> Self {
        Self { sandboxed }
    }

    pub fn execute(&self, manifest: &SkillManifest, args: &[String]) -> Result<String> {
        if manifest.permissions.execute_shell {
            anyhow::bail!(
                "Skill '{}' requests shell execution, which is denied",
                manifest.skill.name
            );
        }

        if self.sandboxed {
            tracing::info!("Executing skill '{}' in sandbox mode", manifest.skill.name);
        }

        let output = serde_json::json!({
            "skill": manifest.skill.name,
            "version": manifest.skill.version,
            "args": args,
            "result": "Skill execution not yet implemented",
            "status": "stub"
        });

        Ok(serde_json::to_string_pretty(&output)?)
    }
}

impl Default for SkillExecutor {
    fn default() -> Self {
        Self::new(true)
    }
}

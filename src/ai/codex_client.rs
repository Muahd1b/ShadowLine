use crate::security::PromptFirewall;
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub struct CodexClient {
    api_key: Option<String>,
    model: String,
    firewall: PromptFirewall,
}

impl CodexClient {
    pub fn new(api_key: Option<String>, model: &str) -> Self {
        Self {
            api_key,
            model: model.to_string(),
            firewall: PromptFirewall::default(),
        }
    }

    pub async fn propose_action(
        &self,
        telemetry: &str,
        context: &str,
    ) -> Result<String> {
        let prompt = self.firewall.prepare_for_codex(telemetry, context)?;

        if self.api_key.is_none() {
            return Ok(self.generate_fallback_plan(telemetry));
        }

        let client = reqwest::Client::new();
        let request = CodexRequest {
            model: self.model.clone(),
            messages: vec![CodexMessage {
                role: "system".to_string(),
                content: "You are Shadowline, an incident response AI. Respond with a JSON action plan only. Never execute actions directly.".to_string(),
            }, CodexMessage {
                role: "user".to_string(),
                content: prompt,
            }],
            max_tokens: 4096,
            temperature: 0.1,
        };

        let response = client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key.as_ref().unwrap()))
            .json(&request)
            .send()
            .await?;

        let body: CodexResponse = response.json().await?;
        let content = body
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        Ok(content)
    }

    fn generate_fallback_plan(&self, telemetry: &str) -> String {
        serde_json::json!({
            "action": "investigate",
            "reasoning": "No Codex API key configured. Manual investigation recommended.",
            "telemetry_summary": &telemetry[..telemetry.len().min(200)],
            "recommended_steps": [
                "Review the alert in your SIEM",
                "Check for related indicators",
                "Assess blast radius manually"
            ]
        })
        .to_string()
    }

    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }
}

#[derive(Serialize)]
struct CodexRequest {
    model: String,
    messages: Vec<CodexMessage>,
    max_tokens: u32,
    temperature: f64,
}

#[derive(Serialize, Deserialize)]
struct CodexMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct CodexResponse {
    choices: Vec<CodexChoice>,
}

#[derive(Deserialize)]
struct CodexChoice {
    message: CodexMessage,
}

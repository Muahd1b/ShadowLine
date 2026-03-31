use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vendor {
    pub id: String,
    pub name: String,
    pub vendor_type: VendorType,
    pub risk_score: f64,
    pub connections: Vec<Connection>,
    pub last_scanned: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VendorType {
    Saas,
    Rmm,
    Mdm,
    AiAgent,
    CloudProvider,
    IdentityProvider,
    MonitoringTool,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub platform: Platform,
    pub connection_type: ConnectionType,
    pub permissions: Vec<Permission>,
    pub status: ConnectionStatus,
    pub discovered_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Platform {
    Salesforce,
    GitHub,
    Slack,
    GoogleWorkspace,
    Microsoft365,
    Okta,
    Aws,
    Azure,
    Gcp,
    Jira,
    Zendesk,
    HubSpot,
    Datadog,
    PagerDuty,
    Other(String),
}

impl Platform {
    pub fn api_host(&self) -> &str {
        match self {
            Self::Salesforce => "api.salesforce.com",
            Self::GitHub => "api.github.com",
            Self::Slack => "slack.com",
            Self::GoogleWorkspace => "accounts.google.com",
            Self::Microsoft365 => "graph.microsoft.com",
            Self::Okta => "your-org.okta.com",
            Self::Aws => "iam.amazonaws.com",
            Self::Azure => "graph.microsoft.com",
            Self::Gcp => "iam.googleapis.com",
            Self::Jira => "your-domain.atlassian.net",
            Self::Zendesk => "your-subdomain.zendesk.com",
            Self::HubSpot => "api.hubapi.com",
            Self::Datadog => "api.datadoghq.com",
            Self::PagerDuty => "api.pagerduty.com",
            Self::Other(h) => h,
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            Self::Salesforce => "Salesforce",
            Self::GitHub => "GitHub",
            Self::Slack => "Slack",
            Self::GoogleWorkspace => "Google Workspace",
            Self::Microsoft365 => "Microsoft 365",
            Self::Okta => "Okta",
            Self::Aws => "AWS IAM",
            Self::Azure => "Azure AD",
            Self::Gcp => "GCP IAM",
            Self::Jira => "Jira",
            Self::Zendesk => "Zendesk",
            Self::HubSpot => "HubSpot",
            Self::Datadog => "Datadog",
            Self::PagerDuty => "PagerDuty",
            Self::Other(n) => n,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionType {
    OAuth {
        token_ref: Uuid,
        scopes: Vec<String>,
    },
    ApiKey {
        key_ref: Uuid,
    },
    Webhook {
        url: String,
        events: Vec<String>,
    },
    ServiceAccount {
        account_id: String,
    },
    Agent {
        agent_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub resource: String,
    pub access: AccessLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessLevel {
    Read,
    Write,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionStatus {
    Active,
    Dormant,
    Revoked,
    Suspicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: u64,
    pub status: IncidentStatus,
    pub created_at: DateTime<Utc>,
    pub ttps_observed: Vec<Technique>,
    pub current_stage: AttackStage,
    pub velocity_estimate: Option<VelocityEstimate>,
    pub blast_radius: Option<BlastRadius>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentStatus {
    Active,
    Monitoring,
    Contained,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub mitre_id: String,
    pub name: String,
    pub tactic: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackStage {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
}

impl AttackStage {
    pub fn display_name(&self) -> &str {
        match self {
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }

    pub fn progress(&self) -> f64 {
        match self {
            Self::InitialAccess => 0.05,
            Self::Execution => 0.15,
            Self::Persistence => 0.25,
            Self::PrivilegeEscalation => 0.35,
            Self::DefenseEvasion => 0.40,
            Self::CredentialAccess => 0.50,
            Self::Discovery => 0.60,
            Self::LateralMovement => 0.70,
            Self::Collection => 0.80,
            Self::Exfiltration => 0.95,
            Self::Impact => 1.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VelocityEstimate {
    pub minutes_remaining: f64,
    pub confidence: f64,
    pub range_low: f64,
    pub range_high: f64,
    pub archetype: VelocityArchetype,
    pub similar_incidents: Vec<IncidentRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VelocityArchetype {
    Blitz,
    Standard,
    AtpSlow,
    Opportunistic,
}

impl VelocityArchetype {
    pub fn display_name(&self) -> &str {
        match self {
            Self::Blitz => "Blitz (AI-accelerated)",
            Self::Standard => "Standard (human-operated)",
            Self::AtpSlow => "APT Slow (nation-state)",
            Self::Opportunistic => "Opportunistic",
        }
    }

    pub fn typical_minutes(&self) -> (f64, f64) {
        match self {
            Self::Blitz => (30.0, 90.0),
            Self::Standard => (1440.0, 4320.0),
            Self::AtpSlow => (10080.0, 43200.0),
            Self::Opportunistic => (60.0, 2880.0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRef {
    pub id: String,
    pub description: String,
    pub actual_exfil_minutes: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    pub systems_affected: u32,
    pub data_records_at_risk: u64,
    pub teams_affected: Vec<String>,
    pub downstream_vendors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: AuditAction,
    pub target: String,
    pub result: ActionResult,
    pub reasoning: Option<String>,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    KillExecuted,
    KillDryRun,
    ScanCompleted,
    DrillExecuted,
    ConnectionDiscovered,
    ConnectionRevoked,
    VelocityCalculated,
    ConfigChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionResult {
    Success,
    PartialSuccess,
    Failed(String),
    DryRun,
}

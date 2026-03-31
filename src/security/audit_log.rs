use crate::core::models::{ActionResult, AuditAction, AuditEntry};
use chrono::Utc;
use ring::digest::{self, SHA256};

const ZERO_HASH: [u8; 32] = [0u8; 32];

pub struct AuditLog {
    sequence: u64,
    last_hash: [u8; 32],
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            sequence: 0,
            last_hash: ZERO_HASH,
        }
    }

    pub fn create_entry(
        &mut self,
        actor: &str,
        action: AuditAction,
        target: &str,
        result: ActionResult,
        reasoning: Option<&str>,
    ) -> AuditEntry {
        self.sequence += 1;

        let prev_hash = self.last_hash;
        let hash = self.compute_hash(self.sequence, actor, &action, target, &result, prev_hash);
        self.last_hash = hash;

        AuditEntry {
            sequence: self.sequence,
            timestamp: Utc::now(),
            actor: actor.to_string(),
            action,
            target: target.to_string(),
            result,
            reasoning: reasoning.map(|s| s.to_string()),
            prev_hash,
            hash,
        }
    }

    fn compute_hash(
        &self,
        sequence: u64,
        actor: &str,
        action: &AuditAction,
        target: &str,
        result: &ActionResult,
        prev_hash: [u8; 32],
    ) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&sequence.to_le_bytes());
        data.extend_from_slice(actor.as_bytes());
        data.extend_from_slice(format!("{action:?}").as_bytes());
        data.extend_from_slice(target.as_bytes());
        data.extend_from_slice(format!("{result:?}").as_bytes());
        data.extend_from_slice(&prev_hash);

        let digest = digest::digest(&SHA256, &data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest.as_ref());
        hash
    }

    pub fn verify_chain(entries: &[AuditEntry]) -> bool {
        if entries.is_empty() {
            return true;
        }

        for i in 1..entries.len() {
            if entries[i].prev_hash != entries[i - 1].hash {
                return false;
            }
        }

        entries[0].prev_hash == ZERO_HASH
    }

    pub fn current_sequence(&self) -> u64 {
        self.sequence
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::{ActionResult, AuditAction};

    #[test]
    fn test_audit_chain_integrity() {
        let mut log = AuditLog::new();
        let e1 = log.create_entry(
            "analyst-1",
            AuditAction::KillExecuted,
            "vendor:drift",
            ActionResult::Success,
            Some("Drift confirmed compromised"),
        );
        let e2 = log.create_entry(
            "analyst-1",
            AuditAction::ScanCompleted,
            "./my-project",
            ActionResult::Success,
            None,
        );
        let e3 = log.create_entry(
            "analyst-1",
            AuditAction::DrillExecuted,
            "vendor:random",
            ActionResult::DryRun,
            None,
        );

        let entries = vec![e1, e2, e3];
        assert!(AuditLog::verify_chain(&entries));
    }

    #[test]
    fn test_tampered_chain_detected() {
        let mut log = AuditLog::new();
        let mut e1 = log.create_entry(
            "analyst-1",
            AuditAction::KillExecuted,
            "vendor:drift",
            ActionResult::Success,
            None,
        );
        let e2 = log.create_entry(
            "analyst-1",
            AuditAction::ScanCompleted,
            "./project",
            ActionResult::Success,
            None,
        );

        // Tamper with e1
        e1.hash[0] ^= 0xFF;
        let entries = vec![e1, e2];
        assert!(!AuditLog::verify_chain(&entries));
    }
}

use super::models::*;

pub struct BlastRadiusCalculator;

impl BlastRadiusCalculator {
    pub fn new() -> Self {
        Self
    }

    pub fn calculate(&self, vendor: &Vendor) -> BlastRadius {
        let systems_affected = self.count_downstream_systems(vendor);
        let data_records = self.estimate_data_exposure(vendor);
        let teams = self.identify_affected_teams(vendor);
        let downstream = self.trace_downstream_vendors(vendor);

        BlastRadius {
            systems_affected,
            data_records_at_risk: data_records,
            teams_affected: teams,
            downstream_vendors: downstream,
        }
    }

    fn count_downstream_systems(&self, vendor: &Vendor) -> u32 {
        vendor
            .connections
            .iter()
            .filter(|c| c.status != ConnectionStatus::Revoked)
            .map(|c| match &c.connection_type {
                ConnectionType::OAuth { scopes, .. } => {
                    if scopes
                        .iter()
                        .any(|s| s.contains("admin") || s.contains("write"))
                    {
                        2
                    } else {
                        1
                    }
                }
                ConnectionType::Webhook { .. } => 1,
                ConnectionType::Agent { .. } => 3,
                _ => 1,
            })
            .sum::<u32>()
    }

    fn estimate_data_exposure(&self, vendor: &Vendor) -> u64 {
        vendor
            .connections
            .iter()
            .filter(|c| c.status != ConnectionStatus::Revoked)
            .flat_map(|c| &c.permissions)
            .map(|p| match p.resource.as_str() {
                "contacts" => 50_000,
                "accounts" => 10_000,
                "emails" => 100_000,
                "files" | "documents" => 25_000,
                _ => 1_000,
            })
            .sum()
    }

    fn identify_affected_teams(&self, vendor: &Vendor) -> Vec<String> {
        let mut teams = vec![];
        for conn in &vendor.connections {
            match conn.platform {
                Platform::Salesforce => {
                    teams.push("Sales".to_string());
                    teams.push("Marketing".to_string());
                }
                Platform::Slack => teams.push("Engineering".to_string()),
                Platform::GitHub => teams.push("Engineering".to_string()),
                Platform::GoogleWorkspace => {
                    teams.push("All".to_string());
                }
                Platform::Microsoft365 => {
                    teams.push("All".to_string());
                }
                Platform::Okta => teams.push("IT".to_string()),
                _ => teams.push("Unknown".to_string()),
            }
        }
        teams.sort();
        teams.dedup();
        teams
    }

    fn trace_downstream_vendors(&self, vendor: &Vendor) -> Vec<String> {
        vendor
            .connections
            .iter()
            .filter_map(|c| {
                if let ConnectionType::Webhook { url, .. } = &c.connection_type {
                    Some(url.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for BlastRadiusCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_vendor_with_permissions() -> Vendor {
        Vendor {
            id: "v1".to_string(),
            name: "TestVendor".to_string(),
            vendor_type: VendorType::Saas,
            risk_score: 0.7,
            connections: vec![Connection {
                id: "c1".to_string(),
                platform: Platform::Salesforce,
                connection_type: ConnectionType::OAuth {
                    token_ref: Uuid::new_v4(),
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
                discovered_at: Utc::now(),
                last_used: Some(Utc::now()),
            }],
            last_scanned: None,
        }
    }

    #[test]
    fn test_blast_radius_calculation() {
        let calc = BlastRadiusCalculator::new();
        let vendor = make_vendor_with_permissions();
        let radius = calc.calculate(&vendor);
        assert!(radius.systems_affected > 0);
        assert!(radius.data_records_at_risk > 0);
        assert!(radius.teams_affected.contains(&"Sales".to_string()));
    }
}

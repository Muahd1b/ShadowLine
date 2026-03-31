use super::models::*;
use anyhow::Result;
use std::collections::HashMap;

pub struct IntegrationGraph {
    vendors: HashMap<String, Vendor>,
}

impl IntegrationGraph {
    pub fn new() -> Self {
        Self {
            vendors: HashMap::new(),
        }
    }

    pub fn add_vendor(&mut self, vendor: Vendor) {
        self.vendors.insert(vendor.id.clone(), vendor);
    }

    pub fn get_vendor(&self, id: &str) -> Option<&Vendor> {
        self.vendors.get(id)
    }

    pub fn list_vendors(&self) -> Vec<&Vendor> {
        self.vendors.values().collect()
    }

    pub fn active_vendors(&self) -> Vec<&Vendor> {
        self.vendors
            .values()
            .filter(|v| {
                v.connections
                    .iter()
                    .any(|c| c.status == ConnectionStatus::Active)
            })
            .collect()
    }

    pub fn high_risk_vendors(&self, threshold: f64) -> Vec<&Vendor> {
        self.vendors
            .values()
            .filter(|v| v.risk_score >= threshold)
            .collect()
    }

    pub fn connections_for_platform(&self, platform: &Platform) -> Vec<(&Vendor, &Connection)> {
        let mut result = vec![];
        for vendor in self.vendors.values() {
            for conn in &vendor.connections {
                if &conn.platform == platform {
                    result.push((vendor, conn));
                }
            }
        }
        result
    }

    pub fn total_connections(&self) -> usize {
        self.vendors.values().map(|v| v.connections.len()).sum()
    }

    pub fn active_connections(&self) -> usize {
        self.vendors
            .values()
            .flat_map(|v| &v.connections)
            .filter(|c| c.status == ConnectionStatus::Active)
            .count()
    }

    pub fn dormant_connections(&self) -> usize {
        self.vendors
            .values()
            .flat_map(|v| &v.connections)
            .filter(|c| c.status == ConnectionStatus::Dormant)
            .count()
    }

    pub fn remove_vendor(&mut self, id: &str) -> Option<Vendor> {
        self.vendors.remove(id)
    }

    pub fn update_vendor(&mut self, vendor: Vendor) -> Result<()> {
        if !self.vendors.contains_key(&vendor.id) {
            anyhow::bail!("Vendor {} not found", vendor.id);
        }
        self.vendors.insert(vendor.id.clone(), vendor);
        Ok(())
    }
}

impl Default for IntegrationGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_test_vendor(name: &str) -> Vendor {
        Vendor {
            id: format!("vendor-{}", name.to_lowercase()),
            name: name.to_string(),
            vendor_type: VendorType::Saas,
            risk_score: 0.5,
            connections: vec![Connection {
                id: "conn-1".to_string(),
                platform: Platform::GitHub,
                connection_type: ConnectionType::OAuth {
                    token_ref: Uuid::new_v4(),
                    scopes: vec!["repo".to_string()],
                },
                permissions: vec![],
                status: ConnectionStatus::Active,
                discovered_at: Utc::now(),
                last_used: Some(Utc::now()),
            }],
            last_scanned: None,
        }
    }

    #[test]
    fn test_add_and_get_vendor() {
        let mut graph = IntegrationGraph::new();
        graph.add_vendor(make_test_vendor("TestVendor"));
        assert!(graph.get_vendor("vendor-testvendor").is_some());
        assert_eq!(graph.total_connections(), 1);
    }

    #[test]
    fn test_high_risk_filter() {
        let mut graph = IntegrationGraph::new();
        let mut risky = make_test_vendor("Risky");
        risky.risk_score = 0.9;
        let mut safe = make_test_vendor("Safe");
        safe.risk_score = 0.2;
        safe.id = "vendor-safe".to_string();
        graph.add_vendor(risky);
        graph.add_vendor(safe);
        assert_eq!(graph.high_risk_vendors(0.7).len(), 1);
    }
}

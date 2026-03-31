use anyhow::Result;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct SecretValue(Vec<u8>);

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct CredentialVault {
    service_name: String,
}

impl CredentialVault {
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }

    pub fn store_credential(&self, key: &str, value: &str) -> Result<Uuid> {
        let ref_id = Uuid::new_v4();
        let entry_name = format!("{}-{}", self.service_name, ref_id);

        let entry = keyring::Entry::new(&self.service_name, &entry_name)
            .map_err(|e| anyhow::anyhow!("Keychain error: {e}"))?;

        entry
            .set_password(value)
            .map_err(|e| anyhow::anyhow!("Failed to store credential: {e}"))?;

        tracing::info!("Stored credential {} (ref: {})", key, ref_id);
        Ok(ref_id)
    }

    pub fn get_credential(&self, ref_id: &Uuid) -> Result<String> {
        let entry_name = format!("{}-{}", self.service_name, ref_id);
        let entry = keyring::Entry::new(&self.service_name, &entry_name)
            .map_err(|e| anyhow::anyhow!("Keychain error: {e}"))?;

        let password = entry
            .get_password()
            .map_err(|e| anyhow::anyhow!("Failed to retrieve credential: {e}"))?;

        Ok(password)
    }

    pub fn delete_credential(&self, ref_id: &Uuid) -> Result<()> {
        let entry_name = format!("{}-{}", self.service_name, ref_id);
        let entry = keyring::Entry::new(&self.service_name, &entry_name)
            .map_err(|e| anyhow::anyhow!("Keychain error: {e}"))?;

        entry
            .delete_credential()
            .map_err(|e| anyhow::anyhow!("Failed to delete credential: {e}"))?;

        tracing::info!("Deleted credential ref: {}", ref_id);
        Ok(())
    }

    pub fn with_credential<F, T>(&self, ref_id: &Uuid, f: F) -> Result<T>
    where
        F: FnOnce(&str) -> T,
    {
        let mut value = SecretValue(self.get_credential(ref_id)?.into_bytes());
        let result = unsafe { f(std::str::from_utf8_unchecked(&value.0)) };
        value.0.zeroize();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_creation() {
        let vault = CredentialVault::new("shadowline-test");
        assert_eq!(vault.service_name, "shadowline-test");
    }
}

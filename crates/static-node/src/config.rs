//! Node configuration persistence
//!
//! Saves and loads the node's identity (Node ID, Mix private key, and
//! Ed25519 identity keypair) and known peers to a JSON file in the data
//! directory.
//!
//! The config file holds long-term secrets: it is written with Unix
//! permissions `0o600` (owner read/write only).

use anyhow::Result;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use static_sphinx::{MixNode, NodeId};
use std::path::PathBuf;

/// Default for [`PersistentConfig::identity_private_key`].
///
/// Returns zeros; [`PersistentConfig::load_or_create`] treats an all-zero
/// (or mismatched) identity as a legacy config and migrates it by
/// generating a fresh keypair and re-saving.
fn default_identity_private_key() -> [u8; 32] {
    [0u8; 32]
}

/// Default for [`PersistentConfig::identity_public_key`].
fn default_identity_public_key() -> [u8; 32] {
    [0u8; 32]
}

/// Persistent node configuration
#[derive(Serialize, Deserialize, Clone)]
pub struct PersistentConfig {
    /// The node's ID
    pub node_id: NodeId,
    /// The node's mix private key (32 bytes)
    pub mix_private_key: [u8; 32],
    /// The node's long-term Ed25519 identity private key (32 bytes).
    ///
    /// Used to sign handshakes/gossip. Never logged or printed.
    #[serde(default = "default_identity_private_key")]
    pub identity_private_key: [u8; 32],
    /// The node's long-term Ed25519 identity public key (32 bytes).
    ///
    /// Always derived from [`PersistentConfig::identity_private_key`].
    #[serde(default = "default_identity_public_key")]
    pub identity_public_key: [u8; 32],
    /// Known peer addresses
    pub known_peers: Vec<String>,
}

impl PersistentConfig {
    /// Create a new random configuration
    pub fn new() -> Self {
        let mut node_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut node_id);

        let mut mix_private_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut mix_private_key);

        let mut identity_private_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut identity_private_key);
        let signing_key = SigningKey::from_bytes(&identity_private_key);
        let identity_public_key = signing_key.verifying_key().to_bytes();

        Self {
            node_id,
            mix_private_key,
            identity_private_key,
            identity_public_key,
            known_peers: vec![],
        }
    }

    /// Return the Ed25519 signing key for this node's identity.
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.identity_private_key)
    }

    /// Whether the stored identity keypair looks like a legacy default
    /// (missing fields deserialized as zeros, or a public key that does
    /// not match the private key).
    fn identity_needs_migration(&self) -> bool {
        if self.identity_private_key == [0u8; 32] {
            return true;
        }
        let derived = self.signing_key().verifying_key().to_bytes();
        derived != self.identity_public_key
    }

    /// Generate a fresh identity keypair in place.
    fn regenerate_identity(&mut self) {
        rand::rngs::OsRng.fill_bytes(&mut self.identity_private_key);
        let signing_key = SigningKey::from_bytes(&self.identity_private_key);
        self.identity_public_key = signing_key.verifying_key().to_bytes();
    }

    /// Load configuration from the data directory, or create a new one if it doesn't exist.
    ///
    /// Older `config.json` files without the `identity_*` fields
    /// deserialize with zeroed keys (via serde defaults); they are
    /// migrated by generating a fresh Ed25519 identity and re-saving.
    pub fn load_or_create(data_dir: &PathBuf) -> Result<Self> {
        let config_path = data_dir.join("config.json");
        if config_path.exists() {
            tracing::info!("Loading existing node configuration from {:?}", config_path);
            let data = std::fs::read_to_string(&config_path)?;
            let mut config: PersistentConfig = serde_json::from_str(&data)?;
            if config.identity_needs_migration() {
                tracing::info!("Migrating legacy config: generating Ed25519 identity keypair");
                config.regenerate_identity();
                config.save(data_dir)?;
            }
            Ok(config)
        } else {
            tracing::info!("No existing configuration found, generating new node identity");
            let config = Self::new();
            config.save(data_dir)?;
            Ok(config)
        }
    }

    /// Save configuration to the data directory.
    ///
    /// The file is written first, then its permissions are restricted to
    /// `0o600` on Unix (no-op on non-Unix) since it contains secrets.
    pub fn save(&self, data_dir: &PathBuf) -> Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let config_path = data_dir.join("config.json");
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(&config_path, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&config_path, perms)?;
        }
        tracing::info!(
            "Saved node configuration to {:?}",
            data_dir.join("config.json")
        );
        Ok(())
    }

    /// Convert the config into a MixNode instance
    pub fn to_mix_node(&self) -> MixNode {
        MixNode::from_private_key(self.mix_private_key, self.node_id)
    }
}

impl Default for PersistentConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_generates_identity_keypair() {
        let a = PersistentConfig::new();
        let b = PersistentConfig::new();
        // Fresh configs must not share identity secrets.
        assert_ne!(a.identity_private_key, b.identity_private_key);
        assert_ne!(a.identity_public_key, b.identity_public_key);
        assert_ne!(a.node_id, b.node_id);
        // Public key must match the private key.
        let sk = a.signing_key();
        assert_eq!(sk.verifying_key().to_bytes(), a.identity_public_key);
        assert_eq!(a.signing_key().to_bytes(), a.identity_private_key);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "static-test-persist-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config = PersistentConfig::new();
        config.save(&dir).unwrap();
        let loaded = PersistentConfig::load_or_create(&dir).unwrap();
        assert_eq!(loaded.node_id, config.node_id);
        assert_eq!(loaded.mix_private_key, config.mix_private_key);
        assert_eq!(loaded.identity_private_key, config.identity_private_key);
        assert_eq!(loaded.identity_public_key, config.identity_public_key);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_save_sets_0600_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "static-test-perms-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config = PersistentConfig::new();
        config.save(&dir).unwrap();
        let mode = std::fs::metadata(dir.join("config.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_migrates_legacy_config_missing_identity() {
        let dir = std::env::temp_dir().join(format!(
            "static-test-migrate-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Legacy file: only the pre-identity fields.
        let legacy = serde_json::json!({
            "node_id": vec![1u8; 16],
            "mix_private_key": vec![2u8; 32],
            "known_peers": []
        });
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let migrated = PersistentConfig::load_or_create(&dir).unwrap();
        assert_eq!(migrated.node_id, [1u8; 16]);
        assert_eq!(migrated.mix_private_key, [2u8; 32]);
        assert_ne!(migrated.identity_private_key, [0u8; 32]);
        // Keypair must be self-consistent.
        assert_eq!(
            migrated.signing_key().verifying_key().to_bytes(),
            migrated.identity_public_key
        );
        // Migration must have been persisted.
        let reloaded = PersistentConfig::load_or_create(&dir).unwrap();
        assert_eq!(reloaded.identity_private_key, migrated.identity_private_key);
        assert_eq!(reloaded.identity_public_key, migrated.identity_public_key);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_migrates_mismatched_identity_pubkey() {
        let mut config = PersistentConfig::new();
        config.identity_public_key = [0xAAu8; 32];
        assert!(config.identity_needs_migration());
    }
}

//! Node configuration persistence
//!
//! Saves and loads the node's identity (Node ID and Mix private key)
//! and known peers to a JSON file in the data directory.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use static_sphinx::{NodeId, MixNode};
use rand::RngCore;

/// Persistent node configuration
#[derive(Serialize, Deserialize, Clone)]
pub struct PersistentConfig {
    /// The node's ID
    pub node_id: NodeId,
    /// The node's mix private key (32 bytes)
    pub mix_private_key: [u8; 32],
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
        
        Self {
            node_id,
            mix_private_key,
            known_peers: vec![],
        }
    }

    /// Load configuration from the data directory, or create a new one if it doesn't exist
    pub fn load_or_create(data_dir: &PathBuf) -> Result<Self> {
        let config_path = data_dir.join("config.json");
        if config_path.exists() {
            tracing::info!("Loading existing node configuration from {:?}", config_path);
            let data = std::fs::read_to_string(config_path)?;
            let config: PersistentConfig = serde_json::from_str(&data)?;
            Ok(config)
        } else {
            tracing::info!("No existing configuration found, generating new node identity");
            let config = Self::new();
            config.save(data_dir)?;
            Ok(config)
        }
    }

    /// Save configuration to the data directory
    pub fn save(&self, data_dir: &PathBuf) -> Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let config_path = data_dir.join("config.json");
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(config_path, data)?;
        tracing::info!("Saved node configuration to {:?}", data_dir.join("config.json"));
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

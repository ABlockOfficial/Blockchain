use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AssetType {
    Item,
    // other asset types...
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub id: String, // Transaction hash
    pub genesis_hash: String,
    pub asset_type: AssetType,
    pub metadata: Option<String>,
    // other existing fields...
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("Invalid genesis hash for metadata update.")]
    InvalidGenesisHash,
    #[error("Asset type is not Item.")]
    InvalidAssetType,
    // other error variants...
}

impl Transaction {
    /// Creates a new Transaction.
    pub fn new(id: String, genesis_hash: String, asset_type: AssetType, metadata: Option<String>) -> Self {
        Transaction {
            id,
            genesis_hash,
            asset_type,
            metadata,
        }
    }

    /// Updates the metadata of the transaction.
    /// For item asset types, updates the genesis hash to the transaction's own hash.
    pub fn update_metadata(&mut self, new_metadata: String) {
        if let AssetType::Item = self.asset_type {
            self.genesis_hash = self.id.clone();
        }
        self.metadata = Some(new_metadata);
    }

    /// Validates the transaction.
    pub fn validate(&self, input_transaction: Option<&Transaction>) -> Result<(), TransactionError> {
        match self.asset_type {
            AssetType::Item => {
                if let Some(input_tx) = input_transaction {
                    if self.genesis_hash != input_tx.id {
                        return Err(TransactionError::InvalidGenesisHash);
                    }
                } else {
                    // For genesis transactions, the genesis_hash should be the same as id
                    if self.genesis_hash != self.id {
                        return Err(TransactionError::InvalidGenesisHash);
                    }
                }
            }
            // Validate other asset types if needed
            _ => {}
        }
        Ok(())
    }

    /// Computes the hash of the transaction.
    pub fn compute_hash(&self) -> String {
        let serialized = serde_json::to_string(&self).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(serialized);
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Helper method to create a metadata update transaction.
    pub fn create_metadata_update(original_tx: &Transaction, new_metadata: String) -> Self {
        let mut updated_tx = original_tx.clone();
        updated_tx.update_metadata(new_metadata);
        updated_tx.id = updated_tx.compute_hash();
        updated_tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_update() {
        let original_tx = Transaction::new(
            "original_tx_hash".to_string(),
            "original_genesis_hash".to_string(),
            AssetType::Item,
            Some("Original metadata".to_string()),
        );

        let mut updated_tx = original_tx.clone();
        updated_tx.update_metadata("Updated metadata".to_string());

        assert_eq!(updated_tx.metadata.unwrap(), "Updated metadata");
        assert_eq!(updated_tx.genesis_hash, updated_tx.id);
    }

    #[test]
    fn test_validation_success() {
        let original_tx = Transaction::new(
            "original_tx_hash".to_string(),
            "original_genesis_hash".to_string(),
            AssetType::Item,
            Some("Original metadata".to_string()),
        );

        let updated_tx = Transaction::create_metadata_update(&original_tx, "Updated metadata".to_string());

        let input_tx = original_tx.clone();
        assert!(updated_tx.validate(Some(&input_tx)).is_ok());
    }

    #[test]
    fn test_validation_failure() {
        let original_tx = Transaction::new(
            "original_tx_hash".to_string(),
            "original_genesis_hash".to_string(),
            AssetType::Item,
            Some("Original metadata".to_string()),
        );

        let mut updated_tx = Transaction::create_metadata_update(&original_tx, "Updated metadata".to_string());
        // Introduce invalid genesis hash
        updated_tx.genesis_hash = "invalid_genesis_hash".to_string();

        let input_tx = original_tx.clone();
        assert!(matches!(
            updated_tx.validate(Some(&input_tx)),
            Err(TransactionError::InvalidGenesisHash)
        ));
    }

    #[test]
    fn test_genesis_transaction_validation() {
        let genesis_tx = Transaction::new(
            "genesis_tx_hash".to_string(),
            "genesis_tx_hash".to_string(),
            AssetType::Item,
            Some("Genesis metadata".to_string()),
        );

        assert!(genesis_tx.validate(None).is_ok());

        let mut invalid_genesis_tx = genesis_tx.clone();
        invalid_genesis_tx.genesis_hash = "wrong_genesis_hash".to_string();

        assert!(matches!(
            invalid_genesis_tx.validate(None),
            Err(TransactionError::InvalidGenesisHash)
        ));
    }
}
use crate::models::{Transaction, AssetType, Metadata};
use crate::errors::ValidationError;
use crate::utils::hash::calculate_hash;

pub struct TransactionValidator;

impl TransactionValidator {
    pub fn validate(transaction: &Transaction) -> Result<(), ValidationError> {
        // Existing validation logic
        Self::validate_basic(transaction)?;
        
        // Additional validation for item asset type transactions
        if let AssetType::Item = transaction.asset_type {
            Self::validate_item_genesis_hash(transaction)?;
        }
        
        Ok(())
    }

    fn validate_basic(transaction: &Transaction) -> Result<(), ValidationError> {
        // Implement existing basic validation logic
        // For example, check signatures, format, etc.
        if transaction.signature.is_empty() {
            return Err(ValidationError::InvalidSignature);
        }
        // Add other basic validations as needed
        Ok(())
    }

    fn validate_item_genesis_hash(transaction: &Transaction) -> Result<(), ValidationError> {
        if let Some(metadata) = &transaction.metadata {
            let genesis_hash = &metadata.genesis_hash;
            let expected_genesis_hash = calculate_hash(&transaction.id);
            if genesis_hash != &expected_genesis_hash {
                return Err(ValidationError::InvalidGenesisHash {
                    expected: expected_genesis_hash,
                    found: genesis_hash.clone(),
                });
            }
        } else {
            return Err(ValidationError::MissingMetadata);
        }
        Ok(())
    }

    pub fn update_metadata(transaction: &mut Transaction) -> Result<(), ValidationError> {
        if let AssetType::Item = transaction.asset_type {
            let new_genesis_hash = calculate_hash(&transaction.id);
            if let Some(metadata) = &mut transaction.metadata {
                metadata.genesis_hash = new_genesis_hash;
            } else {
                return Err(ValidationError::MissingMetadata);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Transaction, AssetType, Metadata};
    
    #[test]
    fn test_validate_item_genesis_hash_success() {
        let transaction_id = "tx123";
        let transaction = Transaction {
            id: transaction_id.to_string(),
            asset_type: AssetType::Item,
            metadata: Some(Metadata {
                genesis_hash: calculate_hash(transaction_id),
                // other metadata fields
            }),
            signature: "valid_signature".to_string(),
            // other transaction fields
        };
        assert!(TransactionValidator::validate(&transaction).is_ok());
    }

    #[test]
    fn test_validate_item_genesis_hash_failure() {
        let transaction_id = "tx123";
        let transaction = Transaction {
            id: transaction_id.to_string(),
            asset_type: AssetType::Item,
            metadata: Some(Metadata {
                genesis_hash: "invalid_hash".to_string(),
                // other metadata fields
            }),
            signature: "valid_signature".to_string(),
            // other transaction fields
        };
        let result = TransactionValidator::validate(&transaction);
        assert!(matches!(result, Err(ValidationError::InvalidGenesisHash { .. })));
    }

    #[test]
    fn test_update_metadata() {
        let mut transaction = Transaction {
            id: "tx123".to_string(),
            asset_type: AssetType::Item,
            metadata: Some(Metadata {
                genesis_hash: "old_hash".to_string(),
                // other metadata fields
            }),
            signature: "valid_signature".to_string(),
            // other transaction fields
        };
        let new_hash = calculate_hash(&transaction.id);
        TransactionValidator::update_metadata(&mut transaction).unwrap();
        assert_eq!(transaction.metadata.as_ref().unwrap().genesis_hash, new_hash);
    }

    #[test]
    fn test_update_metadata_non_item_asset() {
        let mut transaction = Transaction {
            id: "tx123".to_string(),
            asset_type: AssetType::Currency,
            metadata: Some(Metadata {
                genesis_hash: "old_hash".to_string(),
                // other metadata fields
            }),
            signature: "valid_signature".to_string(),
            // other transaction fields
        };
        TransactionValidator::update_metadata(&mut transaction).unwrap();
        assert_eq!(transaction.metadata.as_ref().unwrap().genesis_hash, "old_hash".to_string());
    }
}
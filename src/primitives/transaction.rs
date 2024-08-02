#![allow(unused)]
use crate::constants::*;
use crate::crypto::sign_ed25519::{PublicKey, Signature};
use crate::primitives::{
    asset::{Asset, ItemAsset, TokenAmount},
    druid::{DdeValues, DruidExpectation},
};
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
use crate::utils::is_valid_amount;
use serde::{Deserialize, Serialize};
use std::fmt;
use bincode::{Decode, Encode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GenesisTxHashSpec {
    Create,
    Default,
    //TODO: Eventually custom?
}

impl GenesisTxHashSpec {
    pub fn get_genesis_hash(&self) -> Option<String> {
        match self {
            GenesisTxHashSpec::Create => None, /* Unique DRS transaction hash will be assigned */
            GenesisTxHashSpec::Default => Some(ITEM_DEFAULT_DRS_TX_HASH.to_string()),
        }
    }
}

/// A user-friendly construction struct for a TxIn
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxConstructor {
    pub previous_out: OutPoint,
    pub signatures: Vec<Signature>,
    pub pub_keys: Vec<PublicKey>,
    pub address_version: Option<u64>,
}

/// An outpoint - a combination of a transaction hash and an index n into its vout
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct OutPoint {
    pub t_hash: String,
    pub n: i32,
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "t_hash:{}-n:{}", self.t_hash, self.n)
    }
}

impl OutPoint {
    /// Creates a new outpoint instance
    pub fn new(t_hash: String, n: i32) -> OutPoint {
        OutPoint { t_hash, n }
    }
}

impl Default for OutPoint {
    fn default() -> Self {
        Self::new(String::new(), 0)
    }
}

/// An input of a transaction. It contains the location of the previous
/// transaction's output that it claims and a signature that matches the
/// output's public key.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct TxIn {
    pub previous_out: Option<OutPoint>,
    pub script_signature: Script,
}

impl Default for TxIn {
    fn default() -> Self {
        Self::new()
    }
}

impl TxIn {
    /// Creates a new TxIn instance
    pub fn new() -> TxIn {
        let mut script_sig = Script::new();
        script_sig.stack.push(StackEntry::Op(OpCodes::OP_0));

        TxIn {
            previous_out: None,
            script_signature: script_sig,
        }
    }

    /// Creates a new TxIn instance from provided script and no previous_out
    ///
    /// ### Arguments
    ///
    /// * `script_sig`      - Script signature of the previous outpoint
    pub fn new_from_script(script_sig: Script) -> TxIn {
        TxIn {
            previous_out: None,
            script_signature: script_sig,
        }
    }

    /// Creates a new TxIn instance from provided inputs
    ///
    /// ### Arguments
    ///
    /// * `previous_out`    - OutPoint of the previous transaction
    /// * `script_sig`      - Script signature of the previous outpoint
    pub fn new_from_input(previous_out: OutPoint, script_sig: Script) -> TxIn {
        TxIn {
            previous_out: Some(previous_out),
            script_signature: script_sig,
        }
    }
}

/// An output of a transaction. It contains the public key that the next input
/// must be able to sign with to claim it. It also contains the block hash for the
/// potential DRS if this is a data asset transaction
#[derive(Default, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct TxOut {
    pub value: Asset,
    pub locktime: u64,
    pub script_public_key: Option<String>,
}

impl TxOut {
    /// Creates a new TxOut instance
    pub fn new() -> TxOut {
        Default::default()
    }

    pub fn new_token_amount(
        to_address: String,
        amount: TokenAmount,
        locktime: Option<u64>,
    ) -> TxOut {
        let value = match is_valid_amount(&amount) {
            true => Asset::Token(amount),
            false => Asset::Token(TokenAmount::default()),
        };

        TxOut {
            value,
            locktime: locktime.unwrap_or(ZERO as u64),
            script_public_key: Some(to_address),
        }
    }

    /// Creates a new TxOut instance for a `Item` asset
    ///
    /// **NOTE:** Only create transactions may have `Item` assets that have a `None` `genesis_hash`
    pub fn new_item_amount(to_address: String, item: ItemAsset, locktime: Option<u64>) -> TxOut {
        TxOut {
            value: Asset::Item(item),
            locktime: locktime.unwrap_or(ZERO as u64),
            script_public_key: Some(to_address),
        }
    }

    //TODO: Add handling for `Data' asset variant
    pub fn new_asset(to_address: String, asset: Asset, locktime: Option<u64>) -> TxOut {
        match asset {
            Asset::Token(amount) => TxOut::new_token_amount(to_address, amount, locktime),
            Asset::Item(item) => TxOut::new_item_amount(to_address, item, locktime),
            _ => panic!("Cannot create TxOut for asset of type {:?}", asset),
        }
    }

    /// Returns whether current tx_out is a P2SH
    pub fn is_p2sh_tx_out(&self) -> bool {
        if let Some(pk) = &self.script_public_key {
            let pk_bytes = pk.as_bytes();
            return pk_bytes[0] == P2SH_PREPEND;
        }

        false
    }
}

/// The basic transaction that is broadcasted on the network and contained in
/// blocks. A transaction can contain multiple inputs and outputs.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Transaction {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub version: usize,
    pub fees: Vec<TxOut>,
    pub druid_info: Option<DdeValues>,
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Transaction {
    /// Creates a new Transaction instance
    pub fn new() -> Transaction {
        Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fees: Vec::new(),
            version: NETWORK_VERSION as usize,
            druid_info: None,
        }
    }

    /// Gets the create asset assigned to this transaction, if it exists
    fn get_create_asset(&self) -> Option<&Asset> {
        let is_create = self.inputs.len() == 1
            && self.inputs[0].previous_out.is_none()
            && self.outputs.len() == 1;

        is_create.then(|| &self.outputs[0].value)
    }

    /// Returns whether current transaction is a coinbase tx
    pub fn is_coinbase(&self) -> bool {
        self.get_create_asset()
            .map(|a| a.is_token())
            .unwrap_or_default()
    }

    /// Returns whether current transaction creates a new asset
    pub fn is_create_tx(&self) -> bool {
        self.get_create_asset()
            .map(|a| !a.is_token())
            .unwrap_or_default()
    }

    /// Returns whether current transaction is a P2SH tx
    pub fn is_p2sh_tx(&self) -> bool {
        if self.outputs.len() != 1 {
            return false;
        }

        if let Some(pk) = &self.outputs[0].script_public_key {
            let pk_bytes = pk.as_bytes();
            return pk_bytes[0] == P2SH_PREPEND;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use crate::primitives::asset::{Asset, TokenAmount};
    use crate::primitives::transaction::TxOut;

    #[test]
    fn test_overflow_tx_out() {
        let amount = TokenAmount(u64::MAX);
        let tx_out = TxOut::new_token_amount("test".to_string(), amount, None);

        assert_eq!(tx_out.value, Asset::Token(TokenAmount::default()));
    }
}

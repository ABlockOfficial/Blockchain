use crate::primitives::asset::Asset;
use serde::{Deserialize, Serialize};
use crate::primitives::address::{AnyAddress, TxInsAddress};

/// The expectation to be met in a specific DRUID transaction
#[derive(Clone, Debug, Ord, Eq, PartialEq, Serialize, Deserialize, PartialOrd)]
pub struct DruidExpectation {
    pub from: TxInsAddress,
    pub to: AnyAddress,
    pub asset: Asset,
}

/// A structure to hold DDE-specific content in a transaction
///
/// `druid`                 - DRUID to match on
/// `participants`          - Participants in trade
/// `expect_value`          - The value expected by another party for this tx
/// `expect_value_amount`   - The amount of the asset expected by another party for this tx
/// `expect_address`        - The address the other party is expected to pay to
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DdeValues {
    pub druid: String,
    pub participants: usize,
    pub expectations: Vec<DruidExpectation>,
    pub genesis_hash: Option<String>,
}

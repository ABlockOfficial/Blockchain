use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use crate::primitives::asset::Asset;

/// The expectation to be met in a specific DRUID transaction
#[derive(Default, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct DruidExpectation {
    pub from: String,
    pub to: String,
    pub asset: Asset,
}

/// A structure to hold DDE-specific content in a transaction
///
/// `druid`                 - DRUID to match on
/// `participants`          - Participants in trade
/// `expect_value`          - The value expected by another party for this tx
/// `expect_value_amount`   - The amount of the asset expected by another party for this tx
/// `expect_address`        - The address the other party is expected to pay to
#[derive(Default, Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct DdeValues {
    pub druid: String,
    pub participants: u64,
    pub expectations: Vec<DruidExpectation>,
    pub genesis_hash: Option<String>,
}

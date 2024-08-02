use crate::primitives::transaction::OutPoint;
use crate::utils::{add_btreemap, format_for_display, is_valid_amount};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, iter, mem::size_of, ops};
use bincode::{Decode, Encode};
use tracing::debug;

/// A structure representing the amount of tokens in an instance
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize, Encode, Decode)]
pub struct TokenAmount(pub u64);

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let format_result = format_for_display(&self.0);
        write!(f, "{format_result}")
    }
}

impl ops::Add for TokenAmount {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        match self.0.checked_add(other.0) {
            Some(v) => Self(v),
            None => Self(u64::MAX),
        }
    }
}

impl ops::AddAssign for TokenAmount {
    fn add_assign(&mut self, other: Self) {
        self.0 = match self.0.checked_add(other.0) {
            Some(v) => v,
            None => u64::MAX,
        }
    }
}

impl ops::Sub for TokenAmount {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        match self.0.checked_sub(other.0) {
            Some(v) => Self(v),
            None => Self(u64::MIN),
        }
    }
}

impl ops::SubAssign for TokenAmount {
    fn sub_assign(&mut self, other: Self) {
        self.0 = match self.0.checked_sub(other.0) {
            Some(v) => v,
            None => u64::MIN,
        }
    }
}

impl ops::Mul<u64> for TokenAmount {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        match self.0.checked_mul(rhs) {
            Some(v) => Self(v),
            None => Self(u64::MAX),
        }
    }
}

impl ops::MulAssign<u64> for TokenAmount {
    fn mul_assign(&mut self, rhs: u64) {
        self.0 = match self.0.checked_mul(rhs) {
            Some(v) => v,
            None => u64::MAX,
        }
    }
}

impl ops::Div<u64> for TokenAmount {
    type Output = Self;

    fn div(self, rhs: u64) -> Self {
        match self.0.checked_div(rhs) {
            Some(v) => Self(v),
            None => Self(u64::MAX),
        }
    }
}

impl ops::DivAssign<u64> for TokenAmount {
    fn div_assign(&mut self, rhs: u64) {
        self.0 = match self.0.checked_div(rhs) {
            Some(v) => v,
            None => u64::MAX,
        }
    }
}

impl iter::Sum for TokenAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |r, l| r + l)
    }
}

/// Item asset struct
#[derive(Default, Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct ItemAsset {
    pub amount: u64,
    pub genesis_hash: Option<String>,
    pub metadata: Option<String>,
}

impl ItemAsset {
    pub fn new(amount: u64, genesis_hash: Option<String>, metadata: Option<String>) -> Self {
        Self {
            amount,
            genesis_hash,
            metadata,
        }
    }
}

/// Asset struct
///
/// * `Token`   - An asset struct representation of the ZNT token
/// * `Data`    - A data asset
/// * `Item` - A item for a payment. The value indicates the number of item assets
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, Encode, Decode)]
pub enum Asset {
    Token(TokenAmount),
    Item(ItemAsset),
}

impl Default for Asset {
    fn default() -> Self {
        Asset::Token(Default::default())
    }
}

impl Asset {
    /// Modify `self` of `Asset` struct to obtain `genesis_hash`
    /// from either the asset itself or its corresponding `OutPoint`
    pub fn with_fixed_hash(mut self, out_point: &OutPoint) -> Self {
        if let Asset::Item(ref mut item_asset) = self {
            if item_asset.genesis_hash.is_none() {
                item_asset.genesis_hash = Some(&out_point.t_hash).cloned();
            }
        }
        self
    }

    /// Get optional `genesis_hash` value for `Asset`
    pub fn get_genesis_hash(&self) -> Option<&String> {
        match self {
            Asset::Token(_) => None,
            Asset::Item(item) => item.genesis_hash.as_ref(),
        }
    }

    pub fn get_metadata(&self) -> Option<&String> {
        match self {
            Asset::Token(_) => None,
            Asset::Item(item) => item.metadata.as_ref(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Asset::Token(_) => size_of::<TokenAmount>(),
            Asset::Item(_) => size_of::<u64>(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Asset::Token(token) => token.0 == 0,
            Asset::Item(item) => item.amount == 0,
        }
    }

    pub fn token_u64(amount: u64) -> Self {
        Asset::Token(TokenAmount(amount))
    }

    pub fn item(amount: u64, genesis_hash: Option<String>, metadata: Option<String>) -> Self {
        Asset::Item(ItemAsset::new(amount, genesis_hash, metadata))
    }

    /// Add an asset of the same variant to `self` asset.
    /// TODO: Add handling for `Data` asset variant. Will return false when `Data` asset is presented.
    ///
    /// ### Note
    ///
    /// This function will return false for `Item` assets
    /// getting added together that do not have the same `genesis_hash`
    ///
    /// ### Arguments
    ///
    ///* `rhs`          - The right-hand-side (RHS) asset to add to `self`
    pub fn add_assign(&mut self, rhs: &Self) -> bool {
        match (self, rhs) {
            (Asset::Token(lhs_tokens), Asset::Token(rhs_tokens)) => {
                *lhs_tokens += *rhs_tokens;
                true
            }
            (Asset::Item(lhs_items), Asset::Item(rhs_items)) => {
                if lhs_items.genesis_hash != rhs_items.genesis_hash {
                    return false;
                }
                lhs_items.amount += rhs_items.amount;
                true
            }
            _ => false,
        }
    }

    /// Determine if `self` asset is greater or equal to another asset of the same variant.
    /// TODO: Add handling for `Data` asset variant. Will return None if `Data` asset is presented.
    ///
    /// ### Arguments
    ///
    ///* `rhs`                  - Reference to right-hand-side (RHS) `Asset`
    pub fn is_greater_or_equal_to(&self, rhs: &Asset) -> Option<bool> {
        match (&self, &rhs) {
            (Asset::Token(lhs_token_amount), Asset::Token(rhs_token_amount)) => {
                Some(lhs_token_amount >= rhs_token_amount)
            }
            (Asset::Item(lhs_item), Asset::Item(rhs_item)) => {
                if lhs_item.genesis_hash != rhs_item.genesis_hash {
                    return None;
                }
                Some(lhs_item.amount >= rhs_item.amount)
            }
            _ => None,
        }
    }

    /// Determine if `self` asset is greater than another asset of the same variant.
    /// If `self` asset is greater, return the excess.
    /// TODO: Add handling for `Data` asset variant. Will return None if `Data` asset is presented.
    ///
    /// ### Arguments
    ///
    ///* `rhs`                  - Reference to right-hand-side (RHS) `Asset`
    pub fn get_excess(&self, rhs: &Asset) -> Option<Asset> {
        match (&self, &rhs) {
            (Asset::Token(lhs_tokens), Asset::Token(rhs_tokens)) => {
                debug!("LHS tokens: {:?}, RHS tokens: {:?}", lhs_tokens, rhs_tokens);
                if lhs_tokens > rhs_tokens {
                    Some(Asset::Token(*lhs_tokens - *rhs_tokens))
                } else {
                    None
                }
            }
            (Asset::Item(lhs_items), Asset::Item(rhs_items)) => {
                if lhs_items.amount > rhs_items.amount
                    && lhs_items.genesis_hash == rhs_items.genesis_hash
                {
                    Some(Asset::item(
                        lhs_items.amount - rhs_items.amount,
                        lhs_items.genesis_hash.clone(),
                        lhs_items.metadata.clone(),
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Determine if the asset in question is of the same variant as `self`
    ///
    /// ### Arguments
    ///
    ///* `other`  - Reference to other `Asset` to test against
    pub fn is_same_type_as(&self, other: &Asset) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    /// Creates a default asset of a given variant.
    /// TODO: Add handling for `Data` asset variant
    ///
    /// ### Arguments
    ///
    ///* `asset_type`          - Default asset variant type
    pub fn default_of_type(asset_type: &Self) -> Self {
        match asset_type {
            Self::Token(_) => Self::Token(Default::default()),
            Self::Item(item) => Self::item(
                Default::default(),
                item.genesis_hash.clone(),
                item.metadata.clone(),
            ),
        }
    }

    pub fn is_token(&self) -> bool {
        matches!(self, Asset::Token(_))
    }

    pub fn is_item(&self) -> bool {
        matches!(self, Asset::Item(_))
    }

    pub fn token_amount(&self) -> TokenAmount {
        match self {
            Asset::Token(v) => *v,
            _ => TokenAmount(0),
        }
    }

    pub fn item_amount(&self) -> u64 {
        match self {
            Asset::Item(v) => v.amount,
            _ => 0,
        }
    }
}

/// `AssetValue` struct used to represent the a running total of `Token` and `Item` assets
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct AssetValues {
    pub tokens: TokenAmount,
    // Note: Items from create transactions will have `genesis_hash` = `t_hash`
    pub items: BTreeMap<String, u64>, /* `genesis_hash` - amount */
}

impl ops::AddAssign for AssetValues {
    fn add_assign(&mut self, rhs: Self) {
        self.tokens += rhs.tokens;
        add_btreemap(&mut self.items, rhs.items);
    }
}

impl AssetValues {
    pub fn new(tokens: TokenAmount, items: BTreeMap<String, u64>) -> Self {
        Self { tokens, items }
    }

    pub fn token_u64(tokens: u64) -> Self {
        AssetValues::new(TokenAmount(tokens), Default::default())
    }

    pub fn item(items: BTreeMap<String, u64>) -> Self {
        AssetValues::new(TokenAmount(0), items)
    }

    pub fn is_empty(&self) -> bool {
        self == &AssetValues::default()
    }

    pub fn is_equal(&self, rhs: &AssetValues) -> bool {
        self.tokens == rhs.tokens && self.items == rhs.items
    }

    // See if the running total is enough for a required `Asset` amount
    pub fn has_enough(&self, asset_required: &Asset) -> bool {
        match asset_required {
            Asset::Token(tokens) => self.tokens >= *tokens,
            Asset::Item(items) => {
                if let Some(genesis_hash) = &items.genesis_hash {
                    self.items
                        .get(genesis_hash)
                        .map_or(false, |amount| *amount >= items.amount)
                } else {
                    false
                }
            }
        }
    }

    /// Add the `rhs` parameter to `self`
    pub fn update_add(&mut self, rhs: &Asset) {
        match rhs {
            Asset::Token(tokens) => {
                let add = self.tokens + *tokens;

                match is_valid_amount(&add) {
                    true => self.tokens += *tokens,
                    false => self.tokens += TokenAmount::default(),
                }
            },
            Asset::Item(items) => {
                if let Some(genesis_hash) = &items.genesis_hash {
                    self.items
                        .entry(genesis_hash.clone())
                        .and_modify(|amount| *amount += items.amount)
                        .or_insert(items.amount);
                }
            }
        }
    }

    // Subtract the `rhs` parameter from `self`
    pub fn update_sub(&mut self, rhs: &Asset) {
        match rhs {
            Asset::Token(tokens) => self.tokens -= *tokens,
            Asset::Item(items) => {
                items.genesis_hash.as_ref().and_then(|genesis_hash| {
                    self.items
                        .get_mut(genesis_hash)
                        .map(|amount| *amount -= items.amount)
                });
            }
        }
    }
}

#[test]
fn test_token_amount_operations() {
    // add
    let token1: TokenAmount = TokenAmount(u64::MAX - 1);
    let token2: TokenAmount = TokenAmount(2);
    assert_eq!(token1 + token2, TokenAmount(u64::MAX));
    // add_assign
    let mut token1: TokenAmount = TokenAmount(u64::MAX - 1);
    let token2: TokenAmount = TokenAmount(2);
    token1 += token2;
    assert_eq!(token1, TokenAmount(u64::MAX));
    // sub
    let token1: TokenAmount = TokenAmount(u64::MIN);
    let token2: TokenAmount = TokenAmount(1);
    assert_eq!(token1 - token2, TokenAmount(u64::MIN));
    // sub_assign
    let mut token1: TokenAmount = TokenAmount(u64::MIN);
    let token2: TokenAmount = TokenAmount(1);
    token1 -= token2;
    assert_eq!(token1, TokenAmount(u64::MIN));
    // mul
    let token: TokenAmount = TokenAmount(u64::MAX - 1);
    let rhs: u64 = 2;
    assert_eq!(token * rhs, TokenAmount(u64::MAX));
    // mul_assign
    let mut token: TokenAmount = TokenAmount(u64::MAX - 1);
    let rhs: u64 = 2;
    token *= rhs;
    assert_eq!(token, TokenAmount(u64::MAX));
    // div
    let token: TokenAmount = TokenAmount(1);
    let rhs: u64 = 0;
    assert_eq!(token / rhs, TokenAmount(u64::MAX));
    // div_assign
    let mut token: TokenAmount = TokenAmount(1);
    let rhs: u64 = 0;
    token /= rhs;
    assert_eq!(token, TokenAmount(u64::MAX));
}

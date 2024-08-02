use std::collections::BTreeMap;

use crate::constants::{D_DISPLAY_PLACES, TOTAL_TOKENS};
use crate::primitives::asset::TokenAmount;

// ------- MODS ------- //

pub mod druid_utils;
pub mod error_utils;
pub mod script_utils;
pub mod test_utils;
pub mod transaction_utils;

// ------- FUNCTIONS ------- //

/// Determines whether the passed value is within bounds of
/// available tokens in the supply
pub fn is_valid_amount(value: &TokenAmount) -> bool {
    value.0 <= TOTAL_TOKENS
}

/// Formats an incoming value to be displayed
///
/// ### Arguments
///
/// * `value`   - Value to format for display
pub fn format_for_display(value: &u64) -> String {
    if value < &TOTAL_TOKENS {
        let value_f64 = *value as f64;
        return (value_f64 / D_DISPLAY_PLACES).to_string();
    }

    "Value out of bounds".to_string()
}

/// Create a single `BTreeMap<E, T>` struct from two `BTreeMap<E, T>` structs
/// , summing the values of `T` for each corresponding entry `E`
///
/// ### Arguments
///
/// * `m1` - First map
/// * `m2` - Second map
pub fn add_btreemap<E: Ord, T: Copy + std::ops::AddAssign>(
    m1: &mut BTreeMap<E, T>,
    m2: BTreeMap<E, T>,
) -> &BTreeMap<E, T> {
    m2.into_iter().for_each(|(key, value)| {
        m1.entry(key).and_modify(|e| *e += value).or_insert(value);
    });
    m1
}

/// A trait which indicates that a type can be represented by an ordinal number.
pub trait ToOrdinal {
    /// Gets the ordinal number from a value.
    fn to_ordinal(&self) -> u32;
}

/// A trait which indicates that a type can be instantiated from an ordinal number.
pub trait FromOrdinal : Sized {
    /// A slice containing every valid ordinal number.
    const ALL_ORDINALS : &'static [u32];

    /// Gets the value corresponding to the given ordinal number.
    ///
    /// ### Arguments
    ///
    /// * `ordinal` - The ordinal number
    fn from_ordinal(ordinal: u32) -> Result<Self, u32>;
}

/// A trait which indicates that a type can be represented by a string name.
pub trait ToName {
    /// Gets a value's string name.
    fn to_name(&self) -> &'static str;
}

/// A trait which indicates that a type can be instantiated from a string name.
pub trait FromName : Sized {
    /// A slice containing every valid name.
    const ALL_NAMES : &'static [&'static str];

    /// Gets the value corresponding to the given name.
    ///
    /// ### Arguments
    ///
    /// * `name` - The name
    fn from_name(name: &str) -> Result<Self, &str>;
}
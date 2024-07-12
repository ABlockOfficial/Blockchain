use std::collections::BTreeMap;

use crate::constants::{D_DISPLAY_PLACES, TOTAL_TOKENS};
use crate::primitives::asset::TokenAmount;

// ------- MODS ------- //

pub mod druid_utils;
pub mod error_utils;
pub mod script_utils;
pub mod serialize_utils;
pub mod test_utils;
pub mod transaction_utils;

// ------- FUNCTIONS ------- //

/// Determines whether the passed value is within bounds of
/// available tokens in the supply.
///
/// TODO: Currently placeholder, needs to be filled in once requirements known
pub fn is_valid_amount(_value: &TokenAmount) -> bool {
    true
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

/// A trait which indicates that it is possible to acquire a "placeholder" value
/// of a type, which can be used for test purposes.
#[cfg(test)]
pub trait Placeholder : Sized {
    /// Gets a placeholder value of this type which can be used for test purposes.
    fn placeholder() -> Self;

    /// Gets an array of placeholder values of this type which can be used for test purposes.
    fn placeholder_array<const N: usize>() -> [Self; N] {
        core::array::from_fn(|_| Self::placeholder())
    }
}

/// A trait which indicates that it is possible to acquire a "placeholder" value
/// of a type, which can be used for test purposes. These placeholder values are consistent
/// across program runs.
#[cfg(test)]
pub trait PlaceholderIndexed : Sized {
    /// Gets a dummy valid of this type which can be used for test purposes.
    ///
    /// This allows acquiring multiple distinct placeholder values which are still consistent
    /// between runs.
    ///
    /// ### Arguments
    ///
    /// * `index`  - the index of the placeholder value to obtain. Two placeholder values generated
    ///              from the same index are guaranteed to be equal (even across multiple test runs,
    ///              so long as the value format doesn't change).
    fn placeholder_indexed(index: u64) -> Self;

    /// Gets an array of placeholder values of this type which can be used for test purposes.
    fn placeholder_array_indexed<const N: usize>(base_index: u64) -> [Self; N] {
        core::array::from_fn(|n| Self::placeholder_indexed(base_index.wrapping_add(n as u64)))
    }
}

#[cfg(test)]
impl<T: PlaceholderIndexed> Placeholder for T {
    fn placeholder() -> Self {
        Self::placeholder_indexed(0)
    }
}

/// Generates the given number of pseudorandom bytes based on the given seed.
///
/// This is intended to be used in tests, where random but reproducible placeholder values are often
/// required.
///
/// ### Arguments
///
/// * `seed_parts`   - the parts of the seed, which will be concatenated to form the RNG seed
#[cfg(test)]
pub fn placeholder_bytes<const N: usize>(seed_parts: &[&[u8]]) -> [u8; N] {
    // Use Shake-256 to generate an arbitrarily large number of random bytes based on the given seed.
    let mut shake256 = sha3::Shake256::default();
    for slice in seed_parts {
        sha3::digest::Update::update(&mut shake256, slice);
    }
    let mut reader = sha3::digest::ExtendableOutput::finalize_xof(shake256);

    let mut res = [0u8; N];
    sha3::digest::XofReader::read(&mut reader, &mut res);
    res
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
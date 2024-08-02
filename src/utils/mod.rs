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
pub trait PlaceholderSeed: Sized + PartialEq {
    /// Gets a dummy valid of this type which can be used for test purposes.
    ///
    /// This allows acquiring multiple distinct placeholder values which are still consistent
    /// between runs.
    ///
    /// ### Arguments
    ///
    /// * `seed_parts`  - the parts of the seed for the placeholder value to obtain. Two placeholder
    ///                   values generated from the same seed are guaranteed to be equal (even
    ///                   across multiple test runs, so long as the value format doesn't change).
    fn placeholder_seed_parts<'a>(seed_parts: impl IntoIterator<Item = &'a [u8]>) -> Self;

    /// Gets a dummy valid of this type which can be used for test purposes.
    ///
    /// This allows acquiring multiple distinct placeholder values which are still consistent
    /// between runs.
    ///
    /// ### Arguments
    ///
    /// * `seed`  - the seed for the placeholder value to obtain. Two placeholder
    ///             values generated from the same seed are guaranteed to be equal (even
    ///             across multiple test runs, so long as the value format doesn't change).
    fn placeholder_seed(seed: impl AsRef<[u8]>) -> Self {
        Self::placeholder_seed_parts([ seed.as_ref() ])
    }

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
    fn placeholder_indexed(index: u64) -> Self {
        Self::placeholder_seed_parts([ index.to_le_bytes().as_slice() ])
    }

    /// Gets an array of placeholder values of this type which can be used for test purposes.
    fn placeholder_array_seed<const N: usize>(seed: impl AsRef<[u8]>) -> [Self; N] {
        core::array::from_fn(|n| Self::placeholder_seed_parts(
            [ seed.as_ref(), &(n as u64).to_le_bytes() ]
        ))
    }

    /// Gets an array of placeholder values of this type which can be used for test purposes.
    fn placeholder_array_indexed<const N: usize>(base_index: u64) -> [Self; N] {
        Self::placeholder_array_seed(base_index.to_le_bytes())
    }
}

#[cfg(test)]
impl<T: PlaceholderSeed> Placeholder for T {
    fn placeholder() -> Self {
        <Self as PlaceholderSeed>::placeholder_seed_parts([])
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
pub fn placeholder_bytes<'a, const N: usize>(
    seed_parts: impl IntoIterator<Item = &'a [u8]>
) -> [u8; N] {
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

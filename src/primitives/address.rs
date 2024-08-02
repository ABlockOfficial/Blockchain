use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use bincode::{Decode, Encode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::PublicKey;
use crate::utils::serialize_utils::FixedByteArray;

const STANDARD_ADDRESS_BYTES : usize = sha3_256::HASH_LEN;

/// A standard 32-byte address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Encode, Decode)]
struct StandardAddress(FixedByteArray<STANDARD_ADDRESS_BYTES>);

impl StandardAddress {
    /// Creates a new address out of the given SHA3-256 `Hash`.
    fn new(hash: sha3_256::Hash) -> Self {
        Self(hash.deref().into())
    }
}

#[cfg(test)]
impl crate::utils::PlaceholderSeed for StandardAddress {
    fn placeholder_seed_parts<'a>(seed_parts: impl IntoIterator<Item=&'a [u8]>) -> Self {
        Self(crate::utils::placeholder_bytes(seed_parts).into())
    }
}

impl Display for StandardAddress {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(self.as_ref()))
    }
}

impl FromStr for StandardAddress {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

impl AsRef<[u8]> for StandardAddress {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

make_error_type!(
#[derive(PartialEq)]
pub enum ParseAddressError {
    BadPrefix(address: String); "Address \"{address}\" has unknown prefix",
    ParseFailed(cause: hex::FromHexError); "{cause}"; cause,
});

macro_rules! standard_address_type {
    ($doc:literal, $name:ident, $prefix:literal $(, wrap: $anyname:ident)?) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Encode, Decode)]
        pub struct $name { standard_address: StandardAddress }

        impl $name {
            #[doc = "Gets the SHA3-256 hash which this address wraps"]
            pub fn get_hash(&self) -> sha3_256::Hash {
                sha3_256::Hash::from_slice(self.standard_address.as_ref()).unwrap()
            }
        }

        $( impl $name {
            #[doc = "Wraps this address into an `AnyAddress`"]
            pub fn wrap(self) -> AnyAddress {
                AnyAddress::$anyname(self)
            }
        }

        impl From<$name> for AnyAddress {
            fn from(value: $name) -> Self {
                value.wrap()
            }
        } )?

        impl From<StandardAddress> for $name {
            fn from(standard_address: StandardAddress) -> Self {
                Self { standard_address }
            }
        }

        #[cfg(test)]
        impl crate::utils::PlaceholderSeed for $name {
            fn placeholder_seed_parts<'a>(seed_parts: impl IntoIterator<Item=&'a [u8]>) -> Self {
                StandardAddress::placeholder_seed_parts(
                    [ concat!(stringify!($name), ":").as_bytes() ].iter().cloned().chain(seed_parts)
                ).into()
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
                write!(f, concat!($prefix, "{}"), self.standard_address)
            }
        }

        impl FromStr for $name {
            type Err = ParseAddressError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if let Some(s) = s.strip_prefix($prefix) {
                    StandardAddress::from_str(s).map(Self::from).map_err(ParseAddressError::ParseFailed)
                } else {
                    Err(ParseAddressError::BadPrefix(s.to_string()))
                }
            }
        }
    };
}

standard_address_type!("The type of address used for P2PKH outputs", P2PKHAddress, "", wrap: P2PKH);

impl P2PKHAddress {
    /// Creates a new P2PKH address from the hash of the given public key.
    pub fn from_pubkey(public_key: &PublicKey) -> Self {
        StandardAddress::new(sha3_256::digest(public_key.as_ref())).into()
    }
}

//standard_address_type!("The type of address used for P2SH outputs", P2SHAddress, "H", wrap: P2SH);

standard_address_type!("The type of address used for DRUID input expectations outputs", TxInsAddress, "");

impl TxInsAddress {
    /// Creates a new TxIns address from the hash of the given public key.
    pub fn from_hash(hash: sha3_256::Hash) -> Self {
        StandardAddress::new(hash).into()
    }
}

/// Wrapper enum representing an address of any type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Encode, Decode)]
pub enum AnyAddress {
    Burn,
    P2PKH(P2PKHAddress),
    //P2SH(P2SHAddress),
}

impl AnyAddress {
    /// Identifies which sort of address this is.
    pub fn sort(&self) -> AddressSort {
        match self {
            Self::P2PKH(_) => AddressSort::P2PKH,
            Self::Burn => AddressSort::Burn,
        }
    }
}

impl Display for AnyAddress {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            AnyAddress::Burn => f.write_str("BURN"),
            AnyAddress::P2PKH(address) => address.fmt(f),
            //AnyAddress::P2SH(address) => address.fmt(f),
        }
    }
}

impl FromStr for AnyAddress {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = P2PKHAddress::from_str(s) {
            Ok(Self::P2PKH(addr))
        //} else if let Ok(addr) = P2SHAddress::from_str(s) {
        //    Ok(Self::P2SH(addr))
        } else if s == "BURN" {
            Ok(Self::Burn)
        } else {
            Err(ParseAddressError::BadPrefix(s.to_string()))
        }
    }
}

impl Serialize for AnyAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        assert!(serializer.is_human_readable(), "serializer must be human-readable!");
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AnyAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        assert!(deserializer.is_human_readable(), "deserializer must be human-readable!");

        let text : String = serde::Deserialize::deserialize(deserializer)?;
        text.parse().map_err(<D::Error as serde::de::Error>::custom)
    }
}

#[cfg(test)]
impl crate::utils::Placeholder for AnyAddress {
    fn placeholder() -> Self {
        Self::P2PKH(P2PKHAddress::placeholder())
    }
}

make_trivial_enum!(
#[doc = "The different kinds of addresses."]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSort {
    Burn,
    P2PKH,
    //P2SH,
}
all_variants=ALL_SORTS);

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use crate::utils::PlaceholderSeed;
    use super::*;

    #[test]
    fn test_p2pkh_address() {
        let pks : [PublicKey; 2] = PlaceholderSeed::placeholder_array_indexed(1);

        let pk_hashes = pks.each_ref().map(|pk| sha3_256::digest(pk.as_ref()));
        let addresses = pks.each_ref().map(P2PKHAddress::from_pubkey);

        // The two addresses are generated from different public keys, so they should be distinct
        assert_ne!(addresses[0], addresses[1]);

        // The string representation of each address should be equal to the hex-encoded pubkey hash
        assert_eq!(
            pk_hashes.each_ref().map(sha3_256::Hash::to_string),
            addresses.each_ref().map(P2PKHAddress::to_string));

        // Converting an address to a string and parsing it should give the same address
        assert_eq!(
            addresses.each_ref()
                .map(|address| P2PKHAddress::from_str(&address.to_string()).unwrap()),
            addresses);
    }

    #[test]
    fn test_p2pkh_address_parse() {
        // Valid
        assert_eq!(
            P2PKHAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381d"),
            Ok(StandardAddress::new(sha3_256::digest(b"jeff")).into()));

        // Valid (upper-case hex chars)
        assert_eq!(
            P2PKHAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381D"),
            Ok(StandardAddress::new(sha3_256::digest(b"jeff")).into()));

        // Too short (even)
        assert_eq!(
            P2PKHAddress::from_str(""),
            Err(ParseAddressError::ParseFailed(hex::FromHexError::InvalidStringLength)));
        assert_eq!(
            P2PKHAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb038"),
            Err(ParseAddressError::ParseFailed(hex::FromHexError::InvalidStringLength)));

        // Too short (odd)
        assert_eq!(
            P2PKHAddress::from_str("0"),
            Err(ParseAddressError::ParseFailed(hex::FromHexError::OddLength)));
        assert_eq!(
            P2PKHAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381"),
            Err(ParseAddressError::ParseFailed(hex::FromHexError::OddLength)));

        // Too long (even)
        assert_eq!(
            P2PKHAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381d00"),
            Err(ParseAddressError::ParseFailed(hex::FromHexError::InvalidStringLength)));

        // Too long (odd)
        assert_eq!(
            P2PKHAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381d0"),
            Err(ParseAddressError::ParseFailed(hex::FromHexError::OddLength)));

        // Non-hex chars
        assert_eq!(
            P2PKHAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381Z"),
            Err(ParseAddressError::ParseFailed(hex::FromHexError::InvalidHexCharacter {
                c: 'Z',
                index: 63,
            })));
    }

    #[test]
    fn test_any_address_parse() {
        // Valid
        assert_eq!(
            AnyAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381d"),
            Ok(AnyAddress::P2PKH(StandardAddress::new(sha3_256::digest(b"jeff")).into())));
        assert_eq!(
            AnyAddress::from_str("BURN"),
            Ok(AnyAddress::Burn));

        // Valid (upper-case hex chars)
        assert_eq!(
            AnyAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381D"),
            Ok(AnyAddress::P2PKH(StandardAddress::new(sha3_256::digest(b"jeff")).into())));

        // Too short (even)
        assert_eq!(
            AnyAddress::from_str(""),
            Err(ParseAddressError::BadPrefix("".to_owned())));
        assert_eq!(
            AnyAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb038"),
            Err(ParseAddressError::BadPrefix("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb038".to_owned())));

        // Too short (odd)
        assert_eq!(
            AnyAddress::from_str("0"),
            Err(ParseAddressError::BadPrefix("0".to_owned())));
        assert_eq!(
            AnyAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381"),
            Err(ParseAddressError::BadPrefix("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381".to_owned())));

        // Too long (even)
        assert_eq!(
            AnyAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381d00"),
            Err(ParseAddressError::BadPrefix("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381d00".to_owned())));

        // Too long (odd)
        assert_eq!(
            AnyAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381d0"),
            Err(ParseAddressError::BadPrefix("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381d0".to_owned())));

        // Non-hex chars
        assert_eq!(
            AnyAddress::from_str("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381Z"),
            Err(ParseAddressError::BadPrefix("00f4381fd2f762b0b8532a4a4993be444f75bc8e57bf672c58effabeedb0381Z".to_owned())));
    }
}

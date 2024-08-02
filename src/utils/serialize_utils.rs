use std::any::TypeId;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use bincode::config::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{SeqAccess, Visitor};
use serde::ser::{SerializeTuple};

pub fn bincode_default() -> WithOtherTrailing<WithOtherIntEncoding<DefaultOptions, FixintEncoding>, RejectTrailing> {
    DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

pub fn bincode_compact() -> WithOtherTrailing<WithOtherIntEncoding<DefaultOptions, VarintEncoding>, RejectTrailing> {
    DefaultOptions::new()
        .with_varint_encoding()
        .reject_trailing_bytes()
}

/// Simple wrapper around a fixed-length byte array.
///
/// This can be formatted to and parsed from a hexadecimal string using `Display` and `FromStr`.
/// When serialized as JSON, it is also represented as a hexadecimal string.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FixedByteArray<const N: usize>(
    #[serde(with = "fixed_array_codec")]
    [u8; N],
);

impl<const N: usize> FixedByteArray<N> {
    pub fn new(arr: [u8; N]) -> Self {
        Self(arr)
    }
}

impl<const N: usize> AsRef<[u8]> for FixedByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for FixedByteArray<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> Deref for FixedByteArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for FixedByteArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> From<[u8; N]> for FixedByteArray<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> From<&[u8; N]> for FixedByteArray<N> {
    fn from(value: &[u8; N]) -> Self {
        Self(*value)
    }
}

impl<const N: usize> TryFrom<&[u8]> for FixedByteArray<N> {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into().map(Self)
    }
}

impl<const N: usize> TryFrom<&Vec<u8>> for FixedByteArray<N> {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into().map(Self)
    }
}

impl<const N: usize> fmt::LowerHex for FixedByteArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // This is hacky because we can't make an array of type [u8; {N * 2}] due to
        // generic parameters not being allowed in constant expressions on stable rust
        assert_eq!(std::mem::size_of::<[u16; N]>(), std::mem::size_of::<[u8; N]>() * 2);
        let mut buf = [0u16; N];
        let slice = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, N * 2) };
        hex::encode_to_slice(&self.0, slice).unwrap();
        f.write_str(std::str::from_utf8(slice).unwrap())
    }
}

impl<const N: usize> fmt::Display for FixedByteArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl<const N: usize> fmt::Debug for FixedByteArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FixedByteArray<{N}>({self:x})")
    }
}

impl<const N: usize> FromStr for FixedByteArray<N> {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut buf = [0u8; N];
        hex::decode_to_slice(s, &mut buf)?;
        Ok(Self(buf))
    }
}

/// A codec for fixed-size arrays.
pub mod fixed_array_codec {
    use super::*;

    pub fn serialize<T: Serialize + 'static, S: Serializer, const N: usize>(
        values: &[T; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() && serializer.is_human_readable() {
            // We're serializing a byte array for a human-readable format, make it a hex string
            vec_codec::serialize(values, serializer)
        } else {
            // Serialize the array as a tuple, to avoid adding a length prefix
            let mut tuple = serializer.serialize_tuple(N)?;
            for e in values {
                tuple.serialize_element(e)?;
            }
            tuple.end()
        }
    }

    pub fn deserialize<'de, T: Deserialize<'de> + 'static, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[T; N], D::Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() && deserializer.is_human_readable() {
            // We're deserializing a byte array for a human-readable format, we'll accept two different
            // representations:
            // - A hexadecimal string
            // - An array of byte literals (this format should never be produced by the serializer
            //   for human-readable formats, but it was in the past, so we'll still support reading
            //   it for backwards-compatibility).
            vec_to_fixed_array(vec_codec::deserialize(deserializer)?)
        } else {
            // We're deserializing a binary format, read the array as a tuple
            // (to avoid adding a length prefix)

            struct FixedArrayVisitor<T, const N: usize>(PhantomData<T>);
            impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for FixedArrayVisitor<T, N> {
                type Value = [T; N];

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "a sequence")
                }

                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                    let mut vec = Vec::with_capacity(N);
                    while let Some(val) = seq.next_element::<T>()? {
                        vec.push(val)
                    }
                    vec_to_fixed_array(vec)
                }
            }

            deserializer.deserialize_tuple(N, FixedArrayVisitor(Default::default()))
        }
    }
}

/// A codec for variable-length `Vec`s.
pub mod vec_codec {
    use super::*;

    pub fn serialize<T: Serialize + 'static, S: Serializer>(
        values: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() && serializer.is_human_readable() {
            // We're serializing a byte array for a human-readable format, make it a hex string
            let bytes = unsafe { std::slice::from_raw_parts(values.as_ptr() as *const u8, values.len()) };
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            // Serialize the array as a length-prefixed sequence
            values.serialize(serializer)
        }
    }

    pub fn deserialize<'de, T: Deserialize<'de> + 'static, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<T>, D::Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() && deserializer.is_human_readable() {
            // We're deserializing a byte array for a human-readable format, we'll accept two different
            // representations:
            // - A hexadecimal string
            // - An array of byte literals (this format should never be produced by the serializer
            //   for human-readable formats, but it was in the past, so we'll still support reading
            //   it for backwards-compatibility).

            struct HexStringOrBytesVisitor();
            impl<'de> Visitor<'de> for HexStringOrBytesVisitor {
                type Value = Vec<u8>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("hex string or byte array")
                }

                fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                    hex::decode(value).map_err(E::custom)
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where A: SeqAccess<'de> {
                    let mut vec = Vec::new();
                    while let Some(elt) = seq.next_element::<u8>()? {
                        vec.push(elt);
                    }
                    Ok(vec)
                }
            }

            Ok(deserializer.deserialize_any(HexStringOrBytesVisitor())?.into_iter()
                // This is a hack to convert the Vec<u8> into a Vec<T>, even though we already know
                // that T = u8. This could be done in a much nicer way if trait specialization were
                // a thing, but unfortunately it's still only available on nightly :(
                .map(|b| unsafe { std::mem::transmute_copy::<u8, T>(&b) })
                .collect::<Vec<T>>())
        } else {
            // Read a length-prefixed sequence as a Vec<T>
            <Vec<T>>::deserialize(deserializer)
        }
    }
}

fn vec_to_fixed_array<E: serde::de::Error, T, const N: usize>(
    vec: Vec<T>,
) -> Result<[T; N], E> {
    <[T; N]>::try_from(vec)
        .map_err(|vec| E::custom(format!("expected exactly {} elements, but read {}", N, vec.len())))
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use std::fmt::{Debug, Display};
    use bincode::Options;

    use serde::{Deserialize, Serialize};
    use serde::de::DeserializeOwned;
    use super::*;

    fn repeat(orig: &str, n: usize) -> String {
        let mut res = String::with_capacity(orig.len() * n);
        for _ in 0..n {
            res.push_str(orig)
        }
        res
    }

    fn test_bin_codec<O: Options, T: Clone + Debug + Eq + Serialize + DeserializeOwned>(
        options: fn() -> O,
        obj: T,
        expect: &str,
    ) {
        let bytes = options().serialize(&obj).unwrap();
        assert_eq!(hex::encode(&bytes), expect);
        assert_eq!(options().deserialize::<T>(&bytes).unwrap(), obj);
    }

    fn test_json_codec<T: Clone + Debug + Eq + Serialize + DeserializeOwned>(
        obj: T,
        expect: &str,
    ) {
        let json = serde_json::to_string(&obj).unwrap();
        assert_eq!(json, expect);
        assert_eq!(serde_json::from_str::<T>(&json).unwrap(), obj);
    }

    fn test_json_deserialize<T: Clone + Debug + Eq + DeserializeOwned>(
        obj: T,
        json: &str,
    ) {
        assert_eq!(serde_json::from_str::<T>(&json).unwrap(), obj);
    }

    fn test_display_fromstr<T: Clone + Debug + Eq + Display + FromStr>(
        obj: T,
        expect: &str,
    ) {
        let string = obj.to_string();
        assert_eq!(string, expect);
        assert_eq!(<T as FromStr>::from_str(&string).ok().unwrap(), obj);
    }

    macro_rules! test_fixed_array {
        ($n:literal) => {
            test_bin_codec(bincode_default, [VAL; $n], &repeat(HEX, $n));
            test_json_codec([VAL; $n], &serde_json::to_string(&[VAL; $n].to_vec()).unwrap());
        };
    }

    macro_rules! test_fixed_array_wrapper {
        ($e:ty, $t:ident, $n:literal) => {
            #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
            struct $t([$e; $n]);
            test_bin_codec(bincode_default, $t([VAL; $n]), &repeat(HEX, $n));
            test_json_codec($t([VAL; $n]), &serde_json::to_string(&[VAL; $n].to_vec()).unwrap());
        };
    }

    #[test]
    fn test_fixed_u32_arrays() {
        const VAL : u32 = 0xDEADBEEF;
        const HEX : &str = "efbeadde";

        test_fixed_array!(0);
        test_fixed_array!(1);
        test_fixed_array!(32);

        test_fixed_array_wrapper!(u32, FixedArrayWrapper0, 0);
        test_fixed_array_wrapper!(u32, FixedArrayWrapper1, 1);
        test_fixed_array_wrapper!(u32, FixedArrayWrapper32, 32);

        macro_rules! test_fixed_array_wrapper_codec {
            ($t:ident, $n:literal) => {
                #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
                struct $t(#[serde(with = "fixed_array_codec")] [u32; $n]);
                test_bin_codec(bincode_default, $t([VAL; $n]), &repeat(HEX, $n));
                test_json_codec($t([VAL; $n]), &serde_json::to_string(&[VAL; $n].to_vec()).unwrap());
            };
        }

        test_fixed_array_wrapper_codec!(CodecFixedArrayWrapper0, 0);
        test_fixed_array_wrapper_codec!(CodecFixedArrayWrapper1, 1);
        test_fixed_array_wrapper_codec!(CodecFixedArrayWrapper32, 32);
        test_fixed_array_wrapper_codec!(CodecFixedArrayWrapper33, 33);
    }

    #[test]
    fn test_fixed_u8_arrays() {
        const VAL : u8 = 123;
        const HEX : &str = "7b";

        test_fixed_array!(0);
        test_fixed_array!(1);
        test_fixed_array!(32);

        test_fixed_array_wrapper!(u8, FixedArrayWrapper0, 0);
        test_fixed_array_wrapper!(u8, FixedArrayWrapper1, 1);
        test_fixed_array_wrapper!(u8, FixedArrayWrapper32, 32);

        macro_rules! test_fixed_array_wrapper_codec {
            ($t:ident, $n:literal) => {
                #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
                struct $t(#[serde(with = "fixed_array_codec")] [u8; $n]);
                test_bin_codec(bincode_default, $t([VAL; $n]), &repeat(HEX, $n));
                test_json_codec($t([VAL; $n]), &format!("\"{}\"", hex::encode(&[VAL; $n].to_vec())));
                test_json_deserialize($t([VAL; $n]), &serde_json::to_string(&[VAL; $n].to_vec()).unwrap());
            };
        }

        test_fixed_array_wrapper_codec!(CodecFixedArrayWrapper0, 0);
        test_fixed_array_wrapper_codec!(CodecFixedArrayWrapper1, 1);
        test_fixed_array_wrapper_codec!(CodecFixedArrayWrapper32, 32);
        test_fixed_array_wrapper_codec!(CodecFixedArrayWrapper33, 33);
    }

    fn size_to_hex_default(n: usize) -> String {
        hex::encode(bincode_default().serialize(&n).unwrap())
    }

    macro_rules! test_vec {
        ($n:literal) => {
            test_bin_codec(bincode_default, [VAL; $n].to_vec(), &format!("{}{}", size_to_hex_default($n), repeat(HEX, $n)));
            test_json_codec([VAL; $n].to_vec(), &serde_json::to_string(&[VAL; $n].to_vec()).unwrap());
        };
    }

    macro_rules! test_vec_wrapper {
        ($n:literal) => {
            test_bin_codec(bincode_default, VecWrapper([VAL; $n].to_vec()), &format!("{}{}", size_to_hex_default($n), repeat(HEX, $n)));
            test_json_codec(VecWrapper([VAL; $n].to_vec()), &serde_json::to_string(&[VAL; $n].to_vec()).unwrap());
        };
    }

    #[test]
    fn test_u32_vecs() {
        const VAL : u32 = 0xDEADBEEF;
        const HEX : &str = "efbeadde";

        test_vec!(0);
        test_vec!(1);
        test_vec!(32);
        test_vec!(33);

        #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
        struct VecWrapper(Vec<u32>);

        test_vec_wrapper!(0);
        test_vec_wrapper!(1);
        test_vec_wrapper!(32);
        test_vec_wrapper!(33);

        #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
        struct CodecVecWrapper(#[serde(with = "vec_codec")] Vec<u32>);
        macro_rules! test_vec_wrapper_codec {
            ($n:literal) => {
                test_bin_codec(bincode_default, CodecVecWrapper([VAL; $n].to_vec()), &format!("{}{}", size_to_hex_default($n), repeat(HEX, $n)));
                test_json_codec(CodecVecWrapper([VAL; $n].to_vec()), &serde_json::to_string(&[VAL; $n].to_vec()).unwrap());
            };
        }

        test_vec_wrapper_codec!(0);
        test_vec_wrapper_codec!(1);
        test_vec_wrapper_codec!(32);
        test_vec_wrapper_codec!(33);
    }

    #[test]
    fn test_u8_vecs() {
        const VAL : u8 = 123;
        const HEX : &str = "7b";

        test_vec!(0);
        test_vec!(1);
        test_vec!(32);
        test_vec!(33);

        #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
        struct VecWrapper(Vec<u8>);

        test_vec_wrapper!(0);
        test_vec_wrapper!(1);
        test_vec_wrapper!(32);
        test_vec_wrapper!(33);

        #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
        struct CodecVecWrapper(#[serde(with = "vec_codec")] Vec<u8>);
        macro_rules! test_vec_wrapper_codec {
            ($n:literal) => {
                test_bin_codec(bincode_default, CodecVecWrapper([VAL; $n].to_vec()), &format!("{}{}", size_to_hex_default($n), repeat(HEX, $n)));
                test_json_codec(CodecVecWrapper([VAL; $n].to_vec()), &format!("\"{}\"", hex::encode(&[VAL; $n].to_vec())));
                test_json_deserialize(CodecVecWrapper([VAL; $n].to_vec()), &serde_json::to_string(&[VAL; $n].to_vec()).unwrap());
            };
        }

        test_vec_wrapper_codec!(0);
        test_vec_wrapper_codec!(1);
        test_vec_wrapper_codec!(32);
        test_vec_wrapper_codec!(33);
    }

    #[test]
    fn test_fixed_byte_array() {
        const VAL : u8 = 123;
        const HEX : &str = "7b";

        macro_rules! test_fixed_byte_array {
            ($n:literal) => {
                test_bin_codec(bincode_default, FixedByteArray::<$n>([VAL; $n]), &repeat(HEX, $n));
                test_json_codec(FixedByteArray::<$n>([VAL; $n]), &format!("\"{}\"", repeat(HEX, $n)));
                test_json_deserialize(FixedByteArray::<$n>([VAL; $n]), &serde_json::to_string(&[VAL; $n].to_vec()).unwrap());
                test_display_fromstr(FixedByteArray::<$n>([VAL; $n]), &repeat(HEX, $n));
                assert_eq!(format!("{:x}", FixedByteArray::<$n>([VAL; $n])), repeat(HEX, $n));
                assert_eq!(
                    format!("{:?}", FixedByteArray::<$n>([VAL; $n])),
                    format!("FixedByteArray<{}>({})", $n, repeat(HEX, $n)));
                assert_eq!(
                    format!("{:x?}", FixedByteArray::<$n>([VAL; $n])),
                    format!("FixedByteArray<{}>({})", $n, repeat(HEX, $n)));
            };
        }

        test_fixed_byte_array!(0);
        test_fixed_byte_array!(1);
        test_fixed_byte_array!(32);
        test_fixed_byte_array!(33);
    }
}

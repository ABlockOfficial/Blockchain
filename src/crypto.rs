pub use ring;
use tracing::warn;

macro_rules! fixed_bytes_wrapper {
    ($vis:vis struct $name:ident, $n:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
        $vis struct $name(crate::utils::serialize_utils::FixedByteArray<$n>);

        impl $name {
            pub fn from_slice(slice: &[u8]) -> Option<Self> {
                Some(Self(slice.try_into().ok()?))
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = <crate::utils::serialize_utils::FixedByteArray<$n> as std::str::FromStr>::Err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                <crate::utils::serialize_utils::FixedByteArray<$n> as std::str::FromStr>::from_str(s).map(Self)
            }
        }

        #[cfg(test)]
        impl crate::utils::PlaceholderSeed for $name {
            fn placeholder_seed_parts<'a>(seed_parts: impl IntoIterator<Item=&'a [u8]>) -> Self {
                Self(crate::utils::placeholder_bytes(
                    [ concat!(stringify!($name), ":").as_bytes() ].iter().copied().chain(seed_parts)
                ).into())
            }
        }
    };
}

pub mod sign_ed25519 {
    pub use ring::signature::Ed25519KeyPair as SecretKeyBase;
    use ring::signature::KeyPair;
    pub use ring::signature::Signature as SignatureBase;
    pub use ring::signature::UnparsedPublicKey;
    pub use ring::signature::{ED25519, ED25519_PUBLIC_KEY_LEN};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;
    use crate::crypto::generate_random;

    // Constants copied from the ring library
    const SCALAR_LEN: usize = 32;
    const ELEM_LEN: usize = 32;
    const SIGNATURE_LEN: usize = ELEM_LEN + SCALAR_LEN;
    pub const ED25519_SIGNATURE_LEN: usize = SIGNATURE_LEN;

    pub const ED25519_SEED_LEN: usize = 32;

    fixed_bytes_wrapper!(pub struct Signature, ED25519_SIGNATURE_LEN, "Signature data");
    fixed_bytes_wrapper!(pub struct PublicKey, ED25519_PUBLIC_KEY_LEN, "Public key data");

    /// PKCS8 encoded secret key pair
    /// We used sodiumoxide serialization before (treated it as slice with 64 bit length prefix).
    /// Slice and vector are serialized the same.
    #[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SecretKey(#[serde(with = "crate::utils::serialize_utils::vec_codec")] Vec<u8>);

    impl SecretKey {
        /// Constructs a `SecretKey` from the given PKCS8 document.
        ///
        /// ### Arguments
        ///
        /// * `slice`  - a slice containing the encoded PKCS8 document
        pub fn from_slice(slice: &[u8]) -> Option<Self> {
            match SecretKeyBase::from_pkcs8(slice) {
                Ok(_) => Some(Self(slice.to_vec())),
                Err(_) => None,
            }
        }

        /// Gets the public key corresponding to this secret key.
        pub fn get_public_key(&self) -> PublicKey {
            let keypair = SecretKeyBase::from_pkcs8(&self.0)
                .expect("SecretKey contains invalid PKCS8 document?!?");

            PublicKey::from_slice(keypair.public_key().as_ref())
                .expect("Keypair public key length is invalid?!?")
        }
    }

    impl From<ring::pkcs8::Document> for SecretKey {
        fn from(value: ring::pkcs8::Document) -> Self {
            Self(value.as_ref().to_vec())
        }
    }

    #[cfg(test)]
    impl crate::utils::PlaceholderSeed for SecretKey {
        fn placeholder_seed_parts<'a>(seed_parts: impl IntoIterator<Item=&'a [u8]>) -> Self {
            gen_keypair_from_seed(&crate::utils::placeholder_bytes(
                [ "SecretKey:".as_bytes() ].iter().copied().chain(seed_parts)
            )).1
        }
    }

    #[cfg(test)]
    impl crate::utils::PlaceholderSeed for (PublicKey, SecretKey) {
        fn placeholder_seed_parts<'a>(seed_parts: impl IntoIterator<Item=&'a [u8]>) -> Self {
            gen_keypair_from_seed(&crate::utils::placeholder_bytes(
                [ "(PublicKey, SecretKey):".as_bytes() ].iter().copied().chain(seed_parts)
            ))
        }
    }

    impl AsRef<[u8]> for SecretKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    pub fn verify_detached(sig: &Signature, msg: &[u8], pk: &PublicKey) -> bool {
        let upk = UnparsedPublicKey::new(&ED25519, pk);
        upk.verify(msg, sig.as_ref()).is_ok()
    }

    pub fn sign_detached(msg: &[u8], sk: &SecretKey) -> Signature {
        let keypair = SecretKeyBase::from_pkcs8(sk.as_ref())
                .expect("Invalid PKCS8 secret key?!?");

        let signature = keypair.sign(msg).as_ref().try_into()
            .expect("Invalid signature?!?");
        Signature(signature)
    }

    /// Generates a completely random Ed25519 keypair.
    pub fn gen_keypair() -> (PublicKey, SecretKey) {
        let seed = generate_random();
        gen_keypair_from_seed(&seed)
    }

    /// Generates an Ed25519 keypair based on the given seed.
    ///
    /// ### Arguments
    ///
    /// * `seed`   - the seed to generate the keypair from
    fn gen_keypair_from_seed(seed: &[u8; ED25519_SEED_LEN]) -> (PublicKey, SecretKey) {
        let rand = ring::test::rand::FixedSliceSequenceRandom {
            bytes: &[ seed ],
            current: core::cell::UnsafeCell::new(0),
        };

        let pkcs8 = SecretKeyBase::generate_pkcs8(&rand)
            .expect("Failed to generate secret key base for pkcs8");

        let keypair = SecretKeyBase::from_pkcs8(pkcs8.as_ref())
            .expect("Generated PKCS8 document is invalid?!?");

        let public_key = PublicKey(keypair.public_key().as_ref().try_into()
            .expect("Generated keypair contains an invalid public key?!?"));
        let secret_key = pkcs8.into();
        (public_key, secret_key)
    }
}

pub mod secretbox_chacha20_poly1305 {
    // Use key and nonce separately like rust-tls does
    use super::generate_random;
    pub use ring::aead::LessSafeKey as KeyBase;
    pub use ring::aead::Nonce as NonceBase;
    pub use ring::aead::NONCE_LEN;
    use ring::aead::{Aad, UnboundKey, CHACHA20_POLY1305};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;

    pub const KEY_LEN: usize = 256 / 8;

    fixed_bytes_wrapper!(pub struct Key, KEY_LEN, "Key data");
    fixed_bytes_wrapper!(pub struct Nonce, NONCE_LEN, "Nonce data");

    pub fn seal(mut plain_text: Vec<u8>, nonce: &Nonce, key: &Key) -> Option<Vec<u8>> {
        let key = get_keybase(key)?;
        let nonce = get_noncebase(nonce);
        let aad = Aad::empty();
        let cipher_text = {
            key.seal_in_place_append_tag(nonce, aad, &mut plain_text)
                .ok()?;
            plain_text
        };
        Some(cipher_text)
    }

    pub fn open(mut cipher_text: Vec<u8>, nonce: &Nonce, key: &Key) -> Option<Vec<u8>> {
        let key = get_keybase(key)?;
        let nonce = get_noncebase(nonce);
        let aad = Aad::empty();
        let plain_text = {
            let len = key.open_in_place(nonce, aad, &mut cipher_text).ok()?.len();
            cipher_text.truncate(len);
            cipher_text
        };
        Some(plain_text)
    }

    fn get_keybase(key: &Key) -> Option<KeyBase> {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key.as_ref()).ok()?;
        Some(KeyBase::new(key))
    }

    fn get_noncebase(nonce: &Nonce) -> NonceBase {
        NonceBase::assume_unique_for_key(*nonce.0)
    }

    pub fn gen_key() -> Key {
        Key(generate_random().into())
    }

    pub fn gen_nonce() -> Nonce {
        Nonce(generate_random().into())
    }
}

pub mod pbkdf2 {
    use super::generate_random;
    use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA256};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;
    use std::num::NonZeroU32;
    use tracing::warn;

    pub const SALT_LEN: usize = 256 / 8;
    pub const OPSLIMIT_INTERACTIVE: u32 = 100_000;

    fixed_bytes_wrapper!(pub struct Salt, SALT_LEN, "Salt data");

    pub fn derive_key(key: &mut [u8], passwd: &[u8], salt: &Salt, iterations: u32) {
        let iterations = match NonZeroU32::new(iterations) {
            Some(iterations) => iterations,
            None => {
                warn!("Invalid iterations in key derivation");
                return;
            }
        };
        derive(PBKDF2_HMAC_SHA256, iterations, salt.as_ref(), passwd, key);
    }

    pub fn gen_salt() -> Salt {
        Salt(generate_random().into())
    }
}

pub mod sha3_256 {
    use std::convert::TryInto;
    use std::fmt::{Display, Formatter};
    use std::ops::Deref;
    use std::str::FromStr;

    pub use sha3::digest::Output;
    pub use sha3::Digest;
    pub use sha3::Sha3_256;

    pub const HASH_LEN : usize = 256 / 8;

    /// A SHA3-256 hash.
    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq)]
    pub struct Hash(
        [u8; HASH_LEN],
    );

    impl Hash {
        pub fn from_slice(slice: &[u8]) -> Option<Self> {
            Some(Self(slice.try_into().ok()?))
        }
    }

    impl Display for Hash {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            f.write_str(&hex::encode(&self.0))
        }
    }

    impl FromStr for Hash {
        type Err = hex::FromHexError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut buf = [0u8; HASH_LEN];
            match hex::decode_to_slice(s, &mut buf) {
                Ok(_) => Ok(Self(buf)),
                Err(e) => Err(e),
            }
        }
    }

    impl AsRef<[u8]> for Hash {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Deref for Hash {
        type Target = [u8; HASH_LEN];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    pub fn digest(data: &[u8]) -> Hash {
        Hash(Sha3_256::digest(data).try_into().unwrap())
    }

    pub fn digest_all<'a>(data: impl Iterator<Item = &'a [u8]>) -> Hash {
        let mut hasher = Sha3_256::new();
        data.for_each(|v| hasher.update(v));
        Hash(hasher.finalize().try_into().unwrap())
    }
}

fn generate_random<const N: usize>() -> [u8; N] {
    let mut value: [u8; N] = [0; N];

    use ring::rand::SecureRandom;
    let rand = ring::rand::SystemRandom::new();
    match rand.fill(&mut value) {
        Ok(_) => (),
        Err(_) => warn!("Failed to generate random bytes"),
    };

    value
}

#[cfg(test)]
mod test {
    use std::fmt::{Debug, Display};
    use std::str::FromStr;
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use crate::utils::PlaceholderSeed;
    use super::*;

    fn test_placeholders_different_seed<W: Eq + Debug + PlaceholderSeed>() {
        let [v0, v1] = W::placeholder_array_seed::<2>([]);
        assert_eq!(v0, v0);
        assert_eq!(v1, v1);
        assert_ne!(v0, v1);
    }

    fn test_fixed_bytes_wrapper<W: Eq + Debug + Display + FromStr<Err = hex::FromHexError> + PlaceholderSeed + Serialize + DeserializeOwned>(
        expected_placeholder_hex: &str,
    ) {
        let placeholder = W::placeholder_seed([]);
        assert_eq!(placeholder.to_string(), expected_placeholder_hex);
        assert_eq!(W::from_str(expected_placeholder_hex).unwrap(), placeholder);

        let expected_json = format!("\"{}\"", expected_placeholder_hex);
        assert_eq!(serde_json::to_string(&placeholder).unwrap(), expected_json);
        assert_eq!(serde_json::from_str::<W>(&expected_json).unwrap(), placeholder);

        test_placeholders_different_seed::<W>();
    }

    #[test]
    fn test_ed25519_signature() {
        test_fixed_bytes_wrapper::<sign_ed25519::Signature>(
            "9c4e2259fc9b47b4c4cf672c7436dc16ace2970955a002b69a495ca96d9dfaf026dbee622284a1cf306a1189af8a462d2ea498d10f14b637c848168b0ba698a7",
        );
    }

    #[test]
    fn test_ed25519_public_key() {
        test_fixed_bytes_wrapper::<sign_ed25519::PublicKey>(
            "1d67f7de4c59192568f8e0381fcd1eb9ce044568e4670038e0b42e421540b4f6",
        );
    }

    #[test]
    fn test_ed25519_secret_key() {
        assert_eq!(hex::encode(sign_ed25519::SecretKey::placeholder_seed([])),
                   "3053020101300506032b6570042204203651dccde39be8697d8e0690acd90e3b8ce7f596c5f205fbd0b3b3e3a68629e1a12303210092bc778f74110b3fcbcf8a4df71ed9a33c62faa8d01417d381745ef700ef6b73");

        test_placeholders_different_seed::<sign_ed25519::SecretKey>();
    }

    #[test]
    fn test_ed25519_keypair() {
        test_placeholders_different_seed::<(sign_ed25519::PublicKey, sign_ed25519::SecretKey)>();
    }

    #[test]
    fn test_chacha20_key() {
        test_fixed_bytes_wrapper::<secretbox_chacha20_poly1305::Key>(
            "d2678ac6abff79fa16d2a8f762a3c33b227a519ac1830aee33a19605b7f9cd35",
        );
    }

    #[test]
    fn test_chacha20_nonce() {
        test_fixed_bytes_wrapper::<secretbox_chacha20_poly1305::Nonce>(
            "b0980a0a073d6b828fb48ad5",
        );
    }

    #[test]
    fn test_pbkdf2_salt() {
        test_fixed_bytes_wrapper::<pbkdf2::Salt>(
            "81c4a8cde605d6b51857eb6ebaead0de98cf254d4855725db7aec45a98699e9c",
        );
    }
}

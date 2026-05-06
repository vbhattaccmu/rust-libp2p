// Copyright 2026 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! FN-DSA-512 (Falcon-512) keys.
//!
//! Experimental: wraps the unaudited [`fn_dsa`](https://crates.io/crates/fn-dsa)
//! 0.3 crate. The FN-DSA standard is still being drafted by NIST; key and
//! signature encodings may change before the upstream library hits 1.0, so
//! pin the dependency exactly.

use core::fmt;

use fn_dsa::{
    sign_key_size, signature_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard,
    SigningKey as _, SigningKeyStandard, VerifyingKey as _, VerifyingKeyStandard, DOMAIN_NONE,
    FN_DSA_LOGN_512, HASH_ID_RAW,
};
use zeroize::Zeroize;

use super::error::DecodingError;

pub const PUBLIC_KEY_LENGTH: usize = vrfy_key_size(FN_DSA_LOGN_512);
pub const SECRET_KEY_LENGTH: usize = sign_key_size(FN_DSA_LOGN_512);
pub const SIGNATURE_LENGTH: usize = signature_size(FN_DSA_LOGN_512);

#[derive(Clone)]
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

impl Keypair {
    pub fn generate() -> Keypair {
        let mut sk = [0u8; SECRET_KEY_LENGTH];
        let mut pk = [0u8; PUBLIC_KEY_LENGTH];
        let mut kg = KeyPairGeneratorStandard::default();
        kg.keygen(FN_DSA_LOGN_512, &mut rand::rngs::OsRng, &mut sk, &mut pk);
        Keypair {
            secret: SecretKey(sk),
            public: PublicKey(pk),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut signer =
            SigningKeyStandard::decode(&self.secret.0).expect("Keypair holds a valid signing key");
        let mut sig = vec![0u8; SIGNATURE_LENGTH];
        signer.sign(
            &mut rand::rngs::OsRng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            msg,
            &mut sig,
        );
        sig
    }

    pub fn public(&self) -> PublicKey {
        self.public.clone()
    }

    pub fn secret(&self) -> SecretKey {
        self.secret.clone()
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FnDsaKeypair")
            .field("public", &self.public)
            .finish()
    }
}

impl From<Keypair> for SecretKey {
    fn from(kp: Keypair) -> SecretKey {
        kp.secret
    }
}

impl From<SecretKey> for Keypair {
    fn from(sk: SecretKey) -> Keypair {
        let signer = SigningKeyStandard::decode(&sk.0)
            .expect("SecretKey only holds bytes validated as a signing key");
        let mut public = [0u8; PUBLIC_KEY_LENGTH];
        signer.to_verifying_key(&mut public);
        Keypair {
            secret: sk,
            public: PublicKey(public),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FnDsaPublicKey({:02x?}…)", &self.0[..8])
    }
}

impl PublicKey {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Some(verifier) = VerifyingKeyStandard::decode(&self.0) else {
            return false;
        };
        verifier.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, msg)
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0
    }

    pub fn try_from_bytes(k: &[u8]) -> Result<PublicKey, DecodingError> {
        let arr = <[u8; PUBLIC_KEY_LENGTH]>::try_from(k)
            .map_err(|e| DecodingError::failed_to_parse("FN-DSA-512 public key", e))?;
        // Reject malformed encodings even when the byte length matches.
        if VerifyingKeyStandard::decode(&arr).is_none() {
            return Err(DecodingError::failed_to_parse(
                "FN-DSA-512 public key",
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not a valid FN-DSA-512 verifying key encoding",
                ),
            ));
        }
        Ok(PublicKey(arr))
    }
}

#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_LENGTH]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FnDsaSecretKey")
    }
}

impl SecretKey {
    /// Parse an FN-DSA-512 secret key from a byte slice, zeroing the input on success.
    pub fn try_from_bytes(mut sk_bytes: impl AsMut<[u8]>) -> Result<SecretKey, DecodingError> {
        let sk_bytes = sk_bytes.as_mut();
        let arr = <[u8; SECRET_KEY_LENGTH]>::try_from(&*sk_bytes)
            .map_err(|e| DecodingError::failed_to_parse("FN-DSA-512 secret key", e))?;
        if SigningKeyStandard::decode(&arr).is_none() {
            return Err(DecodingError::failed_to_parse(
                "FN-DSA-512 secret key",
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not a valid FN-DSA-512 signing key encoding",
                ),
            ));
        }
        sk_bytes.zeroize();
        Ok(SecretKey(arr))
    }

    pub(crate) fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_sign_verify_roundtrip() {
        let kp = Keypair::generate();
        let pk = kp.public();
        let msg = b"hello, post-quantum world";
        let sig = kp.sign(msg);

        assert_eq!(sig.len(), SIGNATURE_LENGTH);
        assert!(pk.verify(msg, &sig));
    }

    #[test]
    fn tampered_sig_does_not_verify() {
        let kp = Keypair::generate();
        let pk = kp.public();
        let msg = b"important message";
        let mut sig = kp.sign(msg);
        sig[SIGNATURE_LENGTH / 2] ^= 0xAA;
        assert!(!pk.verify(msg, &sig));
    }

    #[test]
    fn wrong_message_does_not_verify() {
        let kp = Keypair::generate();
        let pk = kp.public();
        let sig = kp.sign(b"message A");
        assert!(!pk.verify(b"message B", &sig));
    }

    #[test]
    fn wrong_pubkey_does_not_verify() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let msg = b"hello";
        let sig = kp1.sign(msg);
        assert!(!kp2.public().verify(msg, &sig));
    }

    #[test]
    fn pubkey_byte_roundtrip() {
        let kp = Keypair::generate();
        let pk1 = kp.public();
        let bytes = pk1.to_bytes();
        let pk2 = PublicKey::try_from_bytes(&bytes).expect("valid bytes");
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn pubkey_wrong_length_rejected() {
        assert!(PublicKey::try_from_bytes(&[0u8; 32]).is_err());
        assert!(PublicKey::try_from_bytes(&[0u8; PUBLIC_KEY_LENGTH + 1]).is_err());
    }

    #[test]
    fn pubkey_invalid_bytes_rejected() {
        // Right length but not a valid encoded key.
        let bogus = [0u8; PUBLIC_KEY_LENGTH];
        assert!(PublicKey::try_from_bytes(&bogus).is_err());
    }

    #[test]
    fn secret_key_byte_roundtrip() {
        let kp = Keypair::generate();
        let mut sk_bytes = kp.secret().to_bytes();
        let sk = SecretKey::try_from_bytes(&mut sk_bytes).expect("valid bytes");
        assert_eq!(sk.as_ref(), kp.secret().as_ref());
        assert!(sk_bytes.iter().all(|b| *b == 0), "input should be zeroed");
    }
}

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

//! Long-lived static keypair + libp2p identity binding for the pqXX handshake.

use clatter::KeyPair as ClatterKeyPair;
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem768;
use clatter::traits::Kem;
use libp2p_identity as identity;

use crate::Error;
use crate::protocol::KeypairIdentity;

// Distinct from `STATIC_KEY_DOMAIN` so a `/noise` signature cannot be
// replayed as `/noise/pqxx/1.0.0` authentication.
pub(crate) const STATIC_KEY_DOMAIN_PQ: &str = "noise-libp2p-static-key-pq:";

pub(crate) type PqKeyPair =
    ClatterKeyPair<<MlKem768 as Kem>::PubKey, <MlKem768 as Kem>::SecretKey>;

#[derive(Clone)]
pub(crate) struct PqStaticKeypair {
    inner: PqKeyPair,
}

#[derive(Clone)]
pub(crate) struct AuthenticPqKeypair {
    pub(crate) keypair: PqStaticKeypair,
    pub(crate) identity: KeypairIdentity,
}

impl PqStaticKeypair {
    pub(crate) fn new() -> Result<Self, Error> {
        let inner =
            MlKem768::genkey().map_err(|e| Error::PqHandshake(format!("keygen failed: {e:?}")))?;
        Ok(Self { inner })
    }

    pub(crate) fn public(&self) -> &[u8] {
        self.inner.public.as_slice()
    }

    pub(crate) fn into_inner(self) -> PqKeyPair {
        self.inner
    }

    pub(crate) fn into_authentic(
        self,
        id_keys: &identity::Keypair,
    ) -> Result<AuthenticPqKeypair, Error> {
        let sig =
            id_keys.sign(&[STATIC_KEY_DOMAIN_PQ.as_bytes(), self.public()].concat())?;

        let identity = KeypairIdentity {
            public: id_keys.public(),
            signature: sig,
        };

        Ok(AuthenticPqKeypair {
            keypair: self,
            identity,
        })
    }
}

pub(crate) fn verify_pq_static_sig(
    id_pk: &identity::PublicKey,
    pq_static_pubkey: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if id_pk.verify(
        &[STATIC_KEY_DOMAIN_PQ.as_bytes(), pq_static_pubkey].concat(),
        signature,
    ) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generates_and_signs() {
        let id_keys = identity::Keypair::generate_ed25519();
        let pq = PqStaticKeypair::new().expect("keygen");

        assert_eq!(pq.public().len(), 1184);

        let authentic = pq.into_authentic(&id_keys).expect("sign");
        verify_pq_static_sig(
            &id_keys.public(),
            authentic.keypair.public(),
            &authentic.identity.signature,
        )
        .expect("sig must verify");
    }

    #[test]
    fn cross_domain_sig_does_not_verify() {
        // A signature made under the *classic* domain must NOT verify against
        // the PQ verifier — protects against cross-protocol downgrade.
        let id_keys = identity::Keypair::generate_ed25519();
        let pq = PqStaticKeypair::new().unwrap();

        let classic_sig = id_keys
            .sign(
                &[
                    crate::protocol::STATIC_KEY_DOMAIN.as_bytes(),
                    pq.public(),
                ]
                .concat(),
            )
            .unwrap();

        let result = verify_pq_static_sig(&id_keys.public(), pq.public(), &classic_sig);
        assert!(matches!(result, Err(Error::BadSignature)));
    }
}

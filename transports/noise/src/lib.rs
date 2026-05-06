// Copyright 2019 Parity Technologies (UK) Ltd.
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

//! [Noise protocol framework][noise] support for libp2p.
//!
//! > **Note**: This crate is still experimental and subject to major breaking changes
//! > both on the API and the wire protocol.
//!
//! This crate provides `libp2p_core::InboundUpgrade` and `libp2p_core::OutboundUpgrade`
//! implementations for various noise handshake patterns (currently `IK`, `IX`, and `XX`)
//! over a particular choice of Diffie–Hellman key agreement (currently only X25519).
//!
//! > **Note**: Only the `XX` handshake pattern is currently guaranteed to provide
//! > interoperability with other libp2p implementations.
//!
//! All upgrades produce as output a pair, consisting of the remote's static public key
//! and a `NoiseOutput` which represents the established cryptographic session with the
//! remote, implementing `futures::io::AsyncRead` and `futures::io::AsyncWrite`.
//!
//! # Usage
//!
//! Example:
//!
//! ```
//! use libp2p_core::{Transport, transport::MemoryTransport, upgrade};
//! use libp2p_identity as identity;
//! use libp2p_noise as noise;
//!
//! # fn main() {
//! let id_keys = identity::Keypair::generate_ed25519();
//! let noise = noise::Config::new(&id_keys).unwrap();
//! let builder = MemoryTransport::default()
//!     .upgrade(upgrade::Version::V1)
//!     .authenticate(noise);
//! // let transport = builder.multiplex(...);
//! # }
//! ```
//!
//! With the `pq` feature: experimental post-quantum [`PqConfig`] driving
//! `Noise_pqXX_MLKEM768_ChaChaPoly_SHA256` under the `/noise/pqxx/1.0.0`
//! multistream id. Backed by the unaudited [`clatter`](https://crates.io/crates/clatter) crate.
//!
//! [noise]: http://noiseprotocol.org/

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod io;
mod protocol;
#[cfg(feature = "pq")]
mod protocol_pq;

use std::{collections::HashSet, fmt::Write, pin::Pin};

use futures::prelude::*;
pub use io::Output;
use libp2p_core::{
    UpgradeInfo,
    upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade},
};
use libp2p_identity as identity;
use libp2p_identity::PeerId;
use multiaddr::Protocol;
use multihash::Multihash;
use snow::params::NoiseParams;

use crate::{
    handshake::State,
    io::handshake,
    protocol::{AuthenticKeypair, Keypair, PARAMS_XX, noise_params_into_builder},
};

#[cfg(feature = "pq")]
use crate::{
    io::{handshake_pq, handshake_pq::PqState},
    protocol_pq::{AuthenticPqKeypair, PqStaticKeypair},
};
#[cfg(feature = "pq")]
use clatter::{
    PqHandshake,
    crypto::{cipher::ChaChaPoly, hash::Sha256, kem::rust_crypto_ml_kem::MlKem768},
    handshakepattern::noise_pqxx,
};

/// The configuration for the noise handshake.
#[derive(Clone)]
pub struct Config {
    dh_keys: AuthenticKeypair,
    params: NoiseParams,
    webtransport_certhashes: Option<HashSet<Multihash<64>>>,

    /// Prologue to use in the noise handshake.
    ///
    /// The prologue can contain arbitrary data that will be hashed into the noise handshake.
    /// For the handshake to succeed, both parties must set the same prologue.
    ///
    /// For further information, see <https://noiseprotocol.org/noise.html#prologue>.
    prologue: Vec<u8>,
}

impl Config {
    /// Construct a new configuration for the noise handshake using the XX handshake pattern.
    pub fn new(identity: &identity::Keypair) -> Result<Self, Error> {
        let noise_keys = Keypair::new().into_authentic(identity)?;

        Ok(Self {
            dh_keys: noise_keys,
            params: PARAMS_XX.clone(),
            webtransport_certhashes: None,
            prologue: vec![],
        })
    }

    /// Set the noise prologue.
    pub fn with_prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = prologue;
        self
    }

    /// Set WebTransport certhashes extension.
    ///
    /// In case of initiator, these certhashes will be used to validate the ones reported by
    /// responder.
    ///
    /// In case of responder, these certhashes will be reported to initiator.
    pub fn with_webtransport_certhashes(mut self, certhashes: HashSet<Multihash<64>>) -> Self {
        self.webtransport_certhashes = Some(certhashes).filter(|h| !h.is_empty());
        self
    }

    fn into_responder<S: AsyncRead + AsyncWrite>(self, socket: S) -> Result<State<S>, Error> {
        let session = noise_params_into_builder(
            self.params,
            &self.prologue,
            self.dh_keys.keypair.secret(),
            None,
        )
        .build_responder()?;

        let state = State::new(
            socket,
            session,
            self.dh_keys.identity,
            None,
            self.webtransport_certhashes,
        );

        Ok(state)
    }

    fn into_initiator<S: AsyncRead + AsyncWrite>(self, socket: S) -> Result<State<S>, Error> {
        let session = noise_params_into_builder(
            self.params,
            &self.prologue,
            self.dh_keys.keypair.secret(),
            None,
        )
        .build_initiator()?;

        let state = State::new(
            socket,
            session,
            self.dh_keys.identity,
            None,
            self.webtransport_certhashes,
        );

        Ok(state)
    }
}

impl UpgradeInfo for Config {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once("/noise")
    }
}

impl<T> InboundConnectionUpgrade<T> for Config
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, Output<T>);
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: T, _: Self::Info) -> Self::Future {
        async move {
            let mut state = self.into_responder(socket)?;

            handshake::recv_empty(&mut state).await?;
            handshake::send_identity(&mut state).await?;
            handshake::recv_identity(&mut state).await?;

            let (pk, io) = state.finish()?;

            Ok((pk.to_peer_id(), io))
        }
        .boxed()
    }
}

impl<T> OutboundConnectionUpgrade<T> for Config
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, Output<T>);
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: T, _: Self::Info) -> Self::Future {
        async move {
            let mut state = self.into_initiator(socket)?;

            handshake::send_empty(&mut state).await?;
            handshake::recv_identity(&mut state).await?;
            handshake::send_identity(&mut state).await?;

            let (pk, io) = state.finish()?;

            Ok((pk.to_peer_id(), io))
        }
        .boxed()
    }
}

/// Configuration for the post-quantum (`pqXX`) Noise handshake.
///
/// Drives the `Noise_pqXX_MLKEM768_ChaChaPoly_SHA256` pattern, negotiated as
/// the multistream protocol id `/noise/pqxx/1.0.0`. Sibling to [`Config`];
/// they can be composed via [`libp2p_core::upgrade::SelectUpgrade`] (or the
/// higher-level `SelectSecurityUpgrade` in `libp2p`) to advertise both PQ and
/// classic Noise on the same connection.
///
/// **Note on assurance.** The PQ path depends on the unaudited [`clatter`]
/// crate for the Noise framework with KEM extensions and on RustCrypto's
/// `ml-kem` for the underlying KEM. Treat this as experimental; it is gated
/// behind the `pq` cargo feature precisely so it is opt-in.
///
/// The libp2p identity flow is unchanged: the static key signed by the
/// libp2p identity is the ML-KEM-768 encapsulation key (instead of an X25519
/// public key in the classic path), and a distinct domain separator
/// (`noise-libp2p-static-key-pq:`) is used to prevent any cross-protocol
/// confusion with `/noise`.
#[cfg(feature = "pq")]
#[derive(Clone)]
pub struct PqConfig {
    pq_keys: AuthenticPqKeypair,
    /// Prologue to use in the noise handshake. See [`Config::with_prologue`].
    prologue: Vec<u8>,
}

#[cfg(feature = "pq")]
impl PqConfig {
    /// Construct a new configuration for the post-quantum `pqXX` handshake.
    /// Generates a fresh ML-KEM-768 static keypair signed by the libp2p
    /// identity.
    pub fn new(identity: &identity::Keypair) -> Result<Self, Error> {
        let pq_keys = PqStaticKeypair::new()?.into_authentic(identity)?;
        Ok(Self {
            pq_keys,
            prologue: vec![],
        })
    }

    /// Set the noise prologue. Both peers must agree on the same prologue.
    pub fn with_prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = prologue;
        self
    }

    fn into_session<S: AsyncRead + AsyncWrite>(
        self,
        socket: S,
        is_initiator: bool,
    ) -> Result<PqState<S>, Error> {
        let identity = self.pq_keys.identity.clone();
        let static_kp = self.pq_keys.keypair.into_inner();

        let session = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256>::new(
            noise_pqxx(),
            &self.prologue,
            is_initiator,
            Some(static_kp),
            None,
            None,
            None,
        )
        .map_err(|e| Error::PqHandshake(format!("session init: {e:?}")))?;

        Ok(PqState::new(socket, session, identity, is_initiator))
    }
}

#[cfg(feature = "pq")]
impl UpgradeInfo for PqConfig {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once("/noise/pqxx/1.0.0")
    }
}

#[cfg(feature = "pq")]
impl<T> InboundConnectionUpgrade<T> for PqConfig
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, Output<T>);
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: T, _: Self::Info) -> Self::Future {
        // pqXX responder flow:
        //   <- e
        //   -> ekem, s     (responder identity payload)
        //   <- skem, s     (initiator identity payload)
        //   -> skem        (final ack, empty payload)
        async move {
            let mut state = self.into_session(socket, false)?;

            handshake_pq::recv_empty(&mut state).await?;
            handshake_pq::send_identity(&mut state).await?;
            handshake_pq::recv_identity(&mut state).await?;
            handshake_pq::send_empty(&mut state).await?;

            let (pk, io) = state.finish()?;
            Ok((pk.to_peer_id(), io))
        }
        .boxed()
    }
}

#[cfg(feature = "pq")]
impl<T> OutboundConnectionUpgrade<T> for PqConfig
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, Output<T>);
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: T, _: Self::Info) -> Self::Future {
        // pqXX initiator flow:
        //   -> e
        //   <- ekem, s     (responder identity payload)
        //   -> skem, s     (initiator identity payload)
        //   <- skem        (final ack, empty payload)
        async move {
            let mut state = self.into_session(socket, true)?;

            handshake_pq::send_empty(&mut state).await?;
            handshake_pq::recv_identity(&mut state).await?;
            handshake_pq::send_identity(&mut state).await?;
            handshake_pq::recv_empty(&mut state).await?;

            let (pk, io) = state.finish()?;
            Ok((pk.to_peer_id(), io))
        }
        .boxed()
    }
}

/// Composition that advertises both the post-quantum (`/noise/pqxx/1.0.0`)
/// and the classic (`/noise`) handshakes on the same connection. PQ is
/// preferred; multistream-select falls back to classic when the remote does
/// not advertise PQ.
///
/// Produced by [`pq_or_classic`]. Both arms produce a `(PeerId, Output<T>)`,
/// so the upgrade output is *flat* — callers don't have to deal with an
/// `Either` at the multiplexer layer.
#[cfg(feature = "pq")]
#[derive(Clone)]
pub struct PqOrClassic {
    pq: PqConfig,
    classic: Config,
}

#[cfg(feature = "pq")]
impl PqOrClassic {
    /// The protocol id advertised by the PQ arm.
    const PROTO_PQ: &'static str = "/noise/pqxx/1.0.0";
    /// The protocol id advertised by the classic arm.
    const PROTO_CLASSIC: &'static str = "/noise";
}

/// Build a [`PqOrClassic`] upgrade from a single libp2p identity. The
/// resulting upgrade advertises `/noise/pqxx/1.0.0` first, with `/noise` as
/// a fallback for peers that have not enabled PQ. Both arms bind the same
/// PeerId, so downstream peer-store / discovery logic is unaffected by which
/// arm wins negotiation.
#[cfg(feature = "pq")]
pub fn pq_or_classic(identity: &identity::Keypair) -> Result<PqOrClassic, Error> {
    Ok(PqOrClassic {
        pq: PqConfig::new(identity)?,
        classic: Config::new(identity)?,
    })
}

#[cfg(feature = "pq")]
impl UpgradeInfo for PqOrClassic {
    type Info = &'static str;
    type InfoIter = std::array::IntoIter<&'static str, 2>;

    fn protocol_info(&self) -> Self::InfoIter {
        // Order matters: multistream-select prefers earlier entries.
        [Self::PROTO_PQ, Self::PROTO_CLASSIC].into_iter()
    }
}

#[cfg(feature = "pq")]
impl<T> InboundConnectionUpgrade<T> for PqOrClassic
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, Output<T>);
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: T, info: Self::Info) -> Self::Future {
        match info {
            Self::PROTO_PQ => self.pq.upgrade_inbound(socket, info),
            Self::PROTO_CLASSIC => self.classic.upgrade_inbound(socket, info),
            other => async move {
                Err(Error::PqHandshake(format!(
                    "unexpected negotiated protocol: {other}"
                )))
            }
            .boxed(),
        }
    }
}

#[cfg(feature = "pq")]
impl<T> OutboundConnectionUpgrade<T> for PqOrClassic
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, Output<T>);
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: T, info: Self::Info) -> Self::Future {
        match info {
            Self::PROTO_PQ => self.pq.upgrade_outbound(socket, info),
            Self::PROTO_CLASSIC => self.classic.upgrade_outbound(socket, info),
            other => async move {
                Err(Error::PqHandshake(format!(
                    "unexpected negotiated protocol: {other}"
                )))
            }
            .boxed(),
        }
    }
}

/// libp2p_noise error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Noise(#[from] snow::Error),
    #[error("Invalid public key")]
    InvalidKey(#[from] libp2p_identity::DecodingError),
    #[error("Only keys of length 32 bytes are supported")]
    InvalidLength,
    #[error("Remote authenticated with an unexpected public key")]
    UnexpectedKey,
    #[error("The signature of the remote identity's public key does not verify")]
    BadSignature,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("failed to decode protobuf ")]
    InvalidPayload(#[from] DecodeError),
    #[error(transparent)]
    #[allow(clippy::enum_variant_names)]
    SigningError(#[from] libp2p_identity::SigningError),
    #[error("Expected WebTransport certhashes ({}) are not a subset of received ones ({})", certhashes_to_string(.0), certhashes_to_string(.1))]
    UnknownWebTransportCerthashes(HashSet<Multihash<64>>, HashSet<Multihash<64>>),
    #[cfg(feature = "pq")]
    #[error("Post-quantum handshake error: {0}")]
    PqHandshake(String),
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct DecodeError(quick_protobuf::Error);

fn certhashes_to_string(certhashes: &HashSet<Multihash<64>>) -> String {
    let mut s = String::new();

    for hash in certhashes {
        write!(&mut s, "{}", Protocol::Certhash(*hash)).unwrap();
    }

    s
}

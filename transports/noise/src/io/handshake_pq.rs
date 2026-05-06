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

//! Post-quantum (`pqXX`) Noise handshake driver.
//!
//! 4-message flow (identity payload in messages 2 and 3):
//!
//! ```text
//! ->  e
//! <-  ekem, s        (responder identity)
//! ->  skem, s        (initiator identity)
//! <-  skem
//! ```

use std::{io, mem};

use asynchronous_codec::Framed;
use futures::prelude::*;
use libp2p_identity as identity;
use quick_protobuf::MessageWrite;

use super::framed_pq::{PqCodec, PqHandshakeSession, PqTransportSession};
use super::handshake::proto;
use crate::Error;
use crate::io::Output;
use crate::protocol::KeypairIdentity;
use crate::protocol_pq::verify_pq_static_sig;

pub(crate) struct PqState<T> {
    io: Framed<T, PqCodec<PqHandshakeSession>>,
    identity: KeypairIdentity,
    is_initiator: bool,
    remote_static_sig: Option<Vec<u8>>,
    remote_id_pubkey: Option<identity::PublicKey>,
}

impl<T> PqState<T>
where
    T: AsyncRead + AsyncWrite,
{
    pub(crate) fn new(
        io: T,
        session: PqHandshakeSession,
        identity: KeypairIdentity,
        is_initiator: bool,
    ) -> Self {
        Self {
            io: Framed::new(io, PqCodec::new(session)),
            identity,
            is_initiator,
            remote_static_sig: None,
            remote_id_pubkey: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    pub(crate) fn finish(self) -> Result<(identity::PublicKey, Output<T>), Error> {
        let (remote_static_bytes, framed) = map_into_transport(self.io)?;

        let id_pk = self.remote_id_pubkey.ok_or(Error::AuthenticationFailed)?;
        let sig = self
            .remote_static_sig
            .as_deref()
            .ok_or(Error::AuthenticationFailed)?;
        verify_pq_static_sig(&id_pk, &remote_static_bytes, sig)?;

        Ok((id_pk, Output::new_pq(framed)))
    }
}

fn map_into_transport<T>(
    framed: Framed<T, PqCodec<PqHandshakeSession>>,
) -> Result<(Vec<u8>, Framed<T, PqCodec<PqTransportSession>>), Error>
where
    T: AsyncRead + AsyncWrite,
{
    let mut parts = framed.into_parts().map_codec(Some);

    let (remote_static, codec) = mem::take(&mut parts.codec)
        .expect("We just set it to `Some`")
        .into_transport()?;

    let parts = parts.map_codec(|_| codec);
    let framed = Framed::from_parts(parts);

    Ok((remote_static, framed))
}

async fn recv<T>(state: &mut PqState<T>) -> Result<proto::NoiseHandshakePayload, Error>
where
    T: AsyncRead + Unpin,
{
    match state.io.next().await {
        None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof").into()),
        Some(Err(e)) => Err(e.into()),
        Some(Ok(p)) => Ok(p),
    }
}

pub(crate) async fn recv_empty<T>(state: &mut PqState<T>) -> Result<(), Error>
where
    T: AsyncRead + Unpin,
{
    let payload = recv(state).await?;
    if payload.get_size() != 0 {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "Expected empty payload.").into(),
        );
    }
    Ok(())
}

pub(crate) async fn send_empty<T>(state: &mut PqState<T>) -> Result<(), Error>
where
    T: AsyncWrite + Unpin,
{
    state
        .io
        .send(&proto::NoiseHandshakePayload::default())
        .await?;
    Ok(())
}

pub(crate) async fn recv_identity<T>(state: &mut PqState<T>) -> Result<(), Error>
where
    T: AsyncRead + Unpin,
{
    let pb = recv(state).await?;
    state.remote_id_pubkey = Some(identity::PublicKey::try_decode_protobuf(&pb.identity_key)?);
    if !pb.identity_sig.is_empty() {
        state.remote_static_sig = Some(pb.identity_sig);
    }
    Ok(())
}

pub(crate) async fn send_identity<T>(state: &mut PqState<T>) -> Result<(), Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut pb = proto::NoiseHandshakePayload {
        identity_key: state.identity.public.encode_protobuf(),
        ..Default::default()
    };
    pb.identity_sig.clone_from(&state.identity.signature);
    state.io.send(&pb).await?;
    Ok(())
}

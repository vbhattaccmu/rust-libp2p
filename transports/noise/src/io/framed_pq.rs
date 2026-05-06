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

//! Length-prefixed framing codec for the pqXX Noise variant. Mirrors
//! [`super::framed`] but drives a [`clatter`] session instead of [`snow`].

use std::{io, mem::size_of};

use asynchronous_codec::{Decoder, Encoder};
use bytes::{Buf, Bytes, BytesMut};
use clatter::PqHandshake;
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::hash::Sha256;
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem768;
use clatter::traits::{Handshaker, Kem};
use clatter::transportstate::TransportState;
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};

use super::handshake::proto;
use crate::Error;

// Headroom for KEM material in handshake messages (~2.3 KB for ML-KEM-768
// pk+ct). Larger than the classic codec's 1 KB; over-allocated for transport.
const EXTRA_ENCRYPT_SPACE: usize = 4096;

pub(crate) type PqHandshakeSession = PqHandshake<MlKem768, MlKem768, ChaChaPoly, Sha256>;
pub(crate) type PqTransportSession = TransportState<ChaChaPoly, Sha256>;

pub(crate) struct PqCodec<S> {
    session: S,
    write_buffer: BytesMut,
    encrypt_buffer: BytesMut,
}

impl<S> PqCodec<S> {
    pub(crate) fn new(session: S) -> Self {
        PqCodec {
            session,
            write_buffer: BytesMut::default(),
            encrypt_buffer: BytesMut::default(),
        }
    }
}

impl PqCodec<PqHandshakeSession> {
    /// Convert a finished handshake session into a transport session and
    /// extract the remote's static ML-KEM-768 pubkey for sig verification.
    pub(crate) fn into_transport(self) -> Result<(Vec<u8>, PqCodec<PqTransportSession>), Error> {
        let remote_static = self
            .session
            .get_remote_static()
            .ok_or(Error::AuthenticationFailed)?;
        let remote_static_bytes = <MlKem768 as Kem>::PubKey::as_slice(&remote_static).to_vec();

        let transport = self
            .session
            .finalize()
            .map_err(|e| Error::PqHandshake(format!("finalize: {e:?}")))?;

        Ok((
            remote_static_bytes,
            PqCodec {
                session: transport,
                write_buffer: BytesMut::default(),
                encrypt_buffer: BytesMut::default(),
            },
        ))
    }
}

impl Encoder for PqCodec<PqHandshakeSession> {
    type Error = io::Error;
    type Item<'a> = &'a proto::NoiseHandshakePayload;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let item_size = item.get_size();
        self.write_buffer.resize(item_size, 0);
        let mut writer = Writer::new(&mut self.write_buffer[..item_size]);
        item.write_message(&mut writer)
            .expect("Protobuf encoding to succeed");

        encrypt_pq(
            &self.write_buffer[..item_size],
            dst,
            &mut self.encrypt_buffer,
            |item, buffer| {
                self.session
                    .write_message(item, buffer)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
            },
        )
    }
}

impl Decoder for PqCodec<PqHandshakeSession> {
    type Error = io::Error;
    type Item = proto::NoiseHandshakePayload;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(cleartext) = decrypt_pq(src, |ciphertext, decrypt_buffer| {
            self.session
                .read_message(ciphertext, decrypt_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
        })?
        else {
            return Ok(None);
        };

        let mut reader = BytesReader::from_bytes(&cleartext[..]);
        let pb =
            proto::NoiseHandshakePayload::from_reader(&mut reader, &cleartext).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed decoding handshake payload",
                )
            })?;

        Ok(Some(pb))
    }
}

impl Encoder for PqCodec<PqTransportSession> {
    type Error = io::Error;
    type Item<'a> = &'a [u8];

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        encrypt_pq(item, dst, &mut self.encrypt_buffer, |item, buffer| {
            self.session
                .send(item, buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
        })
    }
}

impl Decoder for PqCodec<PqTransportSession> {
    type Error = io::Error;
    type Item = Bytes;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decrypt_pq(src, |ciphertext, decrypt_buffer| {
            self.session
                .receive(ciphertext, decrypt_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
        })
    }
}

fn encrypt_pq(
    cleartext: &[u8],
    dst: &mut BytesMut,
    encrypt_buffer: &mut BytesMut,
    encrypt_fn: impl FnOnce(&[u8], &mut [u8]) -> io::Result<usize>,
) -> io::Result<()> {
    encrypt_buffer.resize(cleartext.len() + EXTRA_ENCRYPT_SPACE, 0);
    let n = encrypt_fn(cleartext, encrypt_buffer)?;
    encode_length_prefixed_pq(&encrypt_buffer[..n], dst);
    Ok(())
}

fn decrypt_pq(
    ciphertext: &mut BytesMut,
    decrypt_fn: impl FnOnce(&[u8], &mut [u8]) -> io::Result<usize>,
) -> io::Result<Option<Bytes>> {
    let Some(ciphertext) = decode_length_prefixed_pq(ciphertext) else {
        return Ok(None);
    };

    let mut decrypt_buffer = BytesMut::zeroed(ciphertext.len());
    let n = decrypt_fn(&ciphertext, &mut decrypt_buffer)?;
    Ok(Some(decrypt_buffer.split_to(n).freeze()))
}

const U16_LENGTH: usize = size_of::<u16>();

fn encode_length_prefixed_pq(src: &[u8], dst: &mut BytesMut) {
    dst.reserve(U16_LENGTH + src.len());
    dst.extend_from_slice(&(src.len() as u16).to_be_bytes());
    dst.extend_from_slice(src);
}

fn decode_length_prefixed_pq(src: &mut BytesMut) -> Option<Bytes> {
    if src.len() < U16_LENGTH {
        return None;
    }
    let mut len_bytes = [0u8; U16_LENGTH];
    len_bytes.copy_from_slice(&src[..U16_LENGTH]);
    let len = u16::from_be_bytes(len_bytes) as usize;

    if src.len() - U16_LENGTH >= len {
        src.advance(U16_LENGTH);
        Some(src.split_to(len).freeze())
    } else {
        None
    }
}

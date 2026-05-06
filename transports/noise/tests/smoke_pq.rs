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

//! Smoke tests for the post-quantum (`pqXX`) Noise variant and the
//! [`PqOrClassic`] composition wrapper.

#![cfg(feature = "pq")]

use std::io;

use futures::prelude::*;
use libp2p_core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade};
use libp2p_identity as identity;
use libp2p_noise as noise;

#[test]
fn pq_xx_round_trip() {
    let server_id = identity::Keypair::generate_ed25519();
    let client_id = identity::Keypair::generate_ed25519();

    let (client_io, server_io) = futures_ringbuf::Endpoint::pair(64 * 1024, 64 * 1024);

    futures::executor::block_on(async move {
        let server = noise::PqConfig::new(&server_id).unwrap();
        let client = noise::PqConfig::new(&client_id).unwrap();

        let ((reported_client_id, mut server_session), (reported_server_id, mut client_session)) =
            futures::future::try_join(
                server.upgrade_inbound(server_io, "/noise/pqxx/1.0.0"),
                client.upgrade_outbound(client_io, "/noise/pqxx/1.0.0"),
            )
            .await
            .expect("pqXX handshake completes");

        assert_eq!(reported_client_id, client_id.public().to_peer_id());
        assert_eq!(reported_server_id, server_id.public().to_peer_id());

        let payloads: &[&[u8]] = &[b"ping", b"hello, post-quantum world", &[0xAB; 4096]];
        let client_fut = async {
            for m in payloads {
                let len = (m.len() as u64).to_be_bytes();
                client_session.write_all(&len).await.unwrap();
                client_session.write_all(m).await.unwrap();
            }
            client_session.flush().await.unwrap();
        };
        let server_fut = async {
            for m in payloads {
                let mut len_buf = [0u8; 8];
                server_session.read_exact(&mut len_buf).await.unwrap();
                let len = u64::from_be_bytes(len_buf);
                let mut buf = vec![0u8; len.try_into().unwrap()];
                server_session.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf.as_slice(), *m);
            }
        };
        futures::future::join(client_fut, server_fut).await;
    });
}

#[test]
fn pq_or_classic_picks_pq_arm() {
    let a_id = identity::Keypair::generate_ed25519();
    let b_id = identity::Keypair::generate_ed25519();
    let (a_io, b_io) = futures_ringbuf::Endpoint::pair(32 * 1024, 32 * 1024);

    futures::executor::block_on(async move {
        let a = noise::pq_or_classic(&a_id).unwrap();
        let b = noise::pq_or_classic(&b_id).unwrap();

        let result = futures::future::try_join(
            a.upgrade_inbound(a_io, "/noise/pqxx/1.0.0"),
            b.upgrade_outbound(b_io, "/noise/pqxx/1.0.0"),
        )
        .await;

        let ((server_saw_client, _), (client_saw_server, _)) = result.expect("PQ arm succeeds");
        assert_eq!(server_saw_client, b_id.public().to_peer_id());
        assert_eq!(client_saw_server, a_id.public().to_peer_id());
    });
}

#[test]
fn pq_or_classic_picks_classic_arm() {
    let a_id = identity::Keypair::generate_ed25519();
    let b_id = identity::Keypair::generate_ed25519();
    let (a_io, b_io) = futures_ringbuf::Endpoint::pair(8 * 1024, 8 * 1024);

    futures::executor::block_on(async move {
        let a = noise::pq_or_classic(&a_id).unwrap();
        let b = noise::pq_or_classic(&b_id).unwrap();

        let ((server_saw_client, _), (client_saw_server, _)) = futures::future::try_join(
            a.upgrade_inbound(a_io, "/noise"),
            b.upgrade_outbound(b_io, "/noise"),
        )
        .await
        .expect("classic arm succeeds");

        assert_eq!(server_saw_client, b_id.public().to_peer_id());
        assert_eq!(client_saw_server, a_id.public().to_peer_id());
    });
}

#[test]
fn pq_or_classic_rejects_unknown_protocol() {
    let a_id = identity::Keypair::generate_ed25519();
    let b_id = identity::Keypair::generate_ed25519();
    let (a_io, b_io) = futures_ringbuf::Endpoint::pair(1024, 1024);

    futures::executor::block_on(async move {
        let a = noise::pq_or_classic(&a_id).unwrap();
        let b = noise::pq_or_classic(&b_id).unwrap();

        let res = futures::future::try_join(
            a.upgrade_inbound(a_io, "/noise/wat/9.9.9"),
            b.upgrade_outbound(b_io, "/noise/wat/9.9.9"),
        )
        .await;
        assert!(res.is_err(), "unknown protocol must error out");
    });
}

#[test]
fn pq_only_vs_classic_only_fails() {
    let a_id = identity::Keypair::generate_ed25519();
    let b_id = identity::Keypair::generate_ed25519();
    let (a_io, b_io) = futures_ringbuf::Endpoint::pair(8 * 1024, 8 * 1024);

    futures::executor::block_on(async move {
        let pq = noise::PqConfig::new(&a_id).unwrap();
        let classic = noise::Config::new(&b_id).unwrap();

        let res = futures::future::try_join(
            pq.upgrade_inbound(a_io, "/noise/pqxx/1.0.0"),
            classic.upgrade_outbound(b_io, "/noise"),
        )
        .await;

        // We don't care which side errored or with what variant — only that
        // the futures didn't both complete with success.
        match res {
            Err(_) => {}
            Ok(_) => panic!("PQ ↔ classic must NOT successfully handshake"),
        }
    });
}

// Proves the identity-sig path is crypto-agnostic: same pqXX handshake but the
// libp2p identity is FN-DSA-512 instead of Ed25519. Zero noise-crate changes.
#[test]
fn pq_handshake_with_fndsa_identity() {
    let server_id = identity::Keypair::generate_fndsa();
    let client_id = identity::Keypair::generate_fndsa();

    let (client_io, server_io) = futures_ringbuf::Endpoint::pair(64 * 1024, 64 * 1024);

    futures::executor::block_on(async move {
        let server = noise::PqConfig::new(&server_id).unwrap();
        let client = noise::PqConfig::new(&client_id).unwrap();

        let ((reported_client_id, mut server_session), (reported_server_id, mut client_session)) =
            futures::future::try_join(
                server.upgrade_inbound(server_io, "/noise/pqxx/1.0.0"),
                client.upgrade_outbound(client_io, "/noise/pqxx/1.0.0"),
            )
            .await
            .expect("pqXX with FN-DSA identity completes");

        assert_eq!(reported_client_id, client_id.public().to_peer_id());
        assert_eq!(reported_server_id, server_id.public().to_peer_id());

        // Round-trip a small message to confirm the encrypted channel works.
        let msg = b"hello via FN-DSA-signed pq Noise";
        client_session.write_all(msg).await.unwrap();
        client_session.flush().await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        server_session.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf.as_slice(), msg);
    });
}

// 8 KB ringbuf — handshake must complete without buffer overflow.
#[test]
fn pq_handshake_fits_in_one_buffer_pass() {
    let server_id = identity::Keypair::generate_ed25519();
    let client_id = identity::Keypair::generate_ed25519();

    // 8 KB each direction — comfortably fits any single pqXX handshake
    // message (max ~1.2 KB pk or ~1.1 KB ct + framing) but tight enough to
    // catch unexpected blow-ups.
    let (client_io, server_io) = futures_ringbuf::Endpoint::pair(8 * 1024, 8 * 1024);

    futures::executor::block_on(async move {
        let server = noise::PqConfig::new(&server_id).unwrap();
        let client = noise::PqConfig::new(&client_id).unwrap();

        let res = futures::future::try_join(
            server.upgrade_inbound(server_io, "/noise/pqxx/1.0.0"),
            client.upgrade_outbound(client_io, "/noise/pqxx/1.0.0"),
        )
        .await;
        assert!(res.is_ok(), "handshake completed within 8 KB ringbuf");
    });
}

#[allow(dead_code)]
fn _io_marker(_: io::Error) {}

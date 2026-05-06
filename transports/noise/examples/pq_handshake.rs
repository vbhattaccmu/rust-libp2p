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

//! Demo of the pqXX Noise handshake.
//!
//! ```sh
//! cargo run --example pq_handshake -p libp2p-noise --features pq
//! ```

use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p_core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade};
use libp2p_identity as identity;
use libp2p_noise as noise;

const PQ_PROTOCOL: &str = "/noise/pqxx/1.0.0";

fn main() {
    let alice_id = identity::Keypair::generate_ed25519();
    let bob_id = identity::Keypair::generate_ed25519();

    let alice_peer_id = alice_id.public().to_peer_id();
    let bob_peer_id = bob_id.public().to_peer_id();

    println!("Alice PeerId: {alice_peer_id}");
    println!("Bob   PeerId: {bob_peer_id}");

    let (alice_io, bob_io) = futures_ringbuf::Endpoint::pair(64 * 1024, 64 * 1024);

    let result = futures::executor::block_on(async move {
        let alice = noise::pq_or_classic(&alice_id).expect("build alice");
        let bob = noise::pq_or_classic(&bob_id).expect("build bob");

        let ((bob_saw_alice_id, mut bob_session), (alice_saw_bob_id, mut alice_session)) =
            futures::future::try_join(
                bob.upgrade_inbound(bob_io, PQ_PROTOCOL),
                alice.upgrade_outbound(alice_io, PQ_PROTOCOL),
            )
            .await
            .expect("pqXX handshake completes");

        assert_eq!(bob_saw_alice_id, alice_peer_id);
        assert_eq!(alice_saw_bob_id, bob_peer_id);

        println!("Negotiated protocol: {PQ_PROTOCOL}");
        println!("Mutual authentication confirmed.");

        let greeting = b"hello from a post-quantum world";
        alice_session.write_all(greeting).await.unwrap();
        alice_session.flush().await.unwrap();

        let mut buf = vec![0u8; greeting.len()];
        bob_session.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, greeting);
        println!(
            "Bob decrypted: {}",
            std::str::from_utf8(&buf).unwrap()
        );

        Ok::<(), Box<dyn std::error::Error>>(())
    });

    result.expect("demo succeeded");
}

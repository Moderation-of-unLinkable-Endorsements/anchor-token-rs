# ihat-rs

A Rust implementation of the ihat cryptographic protocol, as
designed by the MoLE collaborators: a pairing-free, issuer-hiding endorsement
scheme over NIST P-256. A client obtains a blind endorsement from an anchor,
then redeems it with a 1-of-n OR-proof that hides which anchor issued it.

> **Warning:** This code has not been audited. Use it at your own risk.

## Usage

```rust
use rand_core::{OsRng, RngCore};
use anchor_token::anchor::AnchorSecretKey;
use anchor_token::client::ClientNeedsSignature;
use anchor_token::Params;

let pp = Params::standard();
let mut rng = OsRng;

// Verifier policy: accepted anchors.
let anchors: Vec<AnchorSecretKey> = (0..4).map(|_| AnchorSecretKey::random(&mut rng)).collect();
let accepted: Vec<_> = anchors.iter().map(|k| k.public_key(&pp)).collect();

// Issue an endorsement from anchor #2.
let issuer = &anchors[2];
let mut nf = [0u8; 32];
rng.fill_bytes(&mut nf);

let (request, client) = ClientNeedsSignature::request(nf.to_vec(), b"epoch-1".to_vec(), &mut rng);
let (signature, anchor) = request.sign(&pp, issuer, &mut rng);
let (proof_request, client) = client.request_proof(&pp, issuer.public_key(&pp), signature);
let proof = anchor.prove(proof_request);
let issued = client.finalize(&pp, proof).unwrap();

// Redeem, hiding which anchor issued it.
let pres = issued.show(&accepted, 2, &mut rng);
assert!(pres.verify(&pp, &accepted));
```

## Build & test

```sh
cargo test
cargo run --example end_to_end
cargo bench
```

## Wire format

Messages have a canonical byte encoding — the TLS 1.3 presentation language,
specified in [docs/wire-format.md](docs/wire-format.md) and implemented by the
`WireFormat` trait (`to_bytes` / `from_bytes`). Enabling the `serde` feature
wires this into serde: `Serialize` / `Deserialize` produce the same canonical
bytes, so the messages embed cleanly in other serializable types.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

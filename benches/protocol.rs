//! Criterion benchmarks for the IHAT issuer-hiding endorsement protocol.
//!
//! Groups:
//! * `issuance`   — each GetEnd party-step and the full four-message run.
//! * `verify`     — endorsement-only DLEQ check (`Endorsement::dleq_valid`).
//! * `redemption` — full Show + Verifier acceptance vs accepted-set size `n`
//!   (where the `1`-of-`n` OR-proof prove/verify cost shows up).
//!
//! Benchmarks use only the public API (the RNG-sampling `request`/`sign` verbs);
//! per-step setup is built outside the timed region.

use std::time::Duration;

use ihat::anchor::{AnchorPublicKey, AnchorSecretKey};
use ihat::client::{ClientNeedsSignature, IssuedEndorsement};
use ihat::Params;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand_core::{OsRng, RngCore};

const CTX: &[u8] = b"epoch-2026-07";

/// The presentation binding (a stand-in challenge digest) used by show/verify.
const BINDING: &[u8] = b"bench-binding";

fn random_nullifier() -> Vec<u8> {
    let mut nf = [0u8; 32];
    OsRng.fill_bytes(&mut nf);
    nf.to_vec()
}

/// One full honest issuance via the public per-step API (RNG-sampled).
fn issue(pp: &Params, key: &AnchorSecretKey, nf: Vec<u8>, ctx: Vec<u8>) -> IssuedEndorsement {
    let (req, client) = ClientNeedsSignature::request(nf, ctx, &mut OsRng);
    let (sig, anchor) = req.sign(pp, key, &mut OsRng);
    let (proof_req, client) = client.request_proof(pp, key.public_key(pp), sig);
    let proof = anchor.prove(proof_req);
    client.finalize(pp, proof).unwrap()
}

fn bench_issuance(c: &mut Criterion) {
    let pp = Params::standard();
    let key = AnchorSecretKey::random(&mut OsRng);
    let x = key.public_key(&pp);

    let mut g = c.benchmark_group("issuance");

    g.bench_function("keygen", |b| b.iter(|| AnchorSecretKey::random(&mut OsRng)));

    g.bench_function("client_request", |b| {
        b.iter_batched(
            random_nullifier,
            |nf| ClientNeedsSignature::request(nf, CTX.to_vec(), &mut OsRng),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("anchor_sign", |b| {
        b.iter_batched(
            || {
                let (req, _) =
                    ClientNeedsSignature::request(random_nullifier(), CTX.to_vec(), &mut OsRng);
                req
            },
            |req| req.sign(&pp, &key, &mut OsRng),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("client_request_proof", |b| {
        b.iter_batched(
            || {
                let (req, client) =
                    ClientNeedsSignature::request(random_nullifier(), CTX.to_vec(), &mut OsRng);
                let (sig, _) = req.sign(&pp, &key, &mut OsRng);
                (client, sig)
            },
            |(client, sig)| client.request_proof(&pp, x, sig),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("anchor_prove", |b| {
        b.iter_batched(
            || {
                let (req, client) =
                    ClientNeedsSignature::request(random_nullifier(), CTX.to_vec(), &mut OsRng);
                let (sig, anchor) = req.sign(&pp, &key, &mut OsRng);
                let (proof_req, _) = client.request_proof(&pp, x, sig);
                (anchor, proof_req)
            },
            |(anchor, proof_req)| anchor.prove(proof_req),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("client_finalize", |b| {
        b.iter_batched(
            || {
                let (req, client) =
                    ClientNeedsSignature::request(random_nullifier(), CTX.to_vec(), &mut OsRng);
                let (sig, anchor) = req.sign(&pp, &key, &mut OsRng);
                let (proof_req, client) = client.request_proof(&pp, x, sig);
                let proof = anchor.prove(proof_req);
                (client, proof)
            },
            |(client, proof)| client.finalize(&pp, proof),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("full_issuance", |b| {
        b.iter_batched(
            random_nullifier,
            |nf| issue(&pp, &key, nf, CTX.to_vec()),
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

fn bench_verify(c: &mut Criterion) {
    let pp = Params::standard();
    let key = AnchorSecretKey::random(&mut OsRng);
    let end = issue(&pp, &key, random_nullifier(), CTX.to_vec()).endorsement;

    c.bench_function("endorsement_dleq_valid", |b| b.iter(|| end.dleq_valid(&pp)));
}

fn bench_redemption(c: &mut Criterion) {
    let pp = Params::standard();
    let mut g = c.benchmark_group("redemption");

    for &n in &[1usize, 2, 4, 8, 16, 32] {
        let anchors: Vec<AnchorSecretKey> = (0..n)
            .map(|_| AnchorSecretKey::random(&mut OsRng))
            .collect();
        let accepted: Vec<AnchorPublicKey> = anchors.iter().map(|k| k.public_key(&pp)).collect();
        let true_index = n / 2;
        let issued = issue(&pp, &anchors[true_index], random_nullifier(), CTX.to_vec());

        g.bench_with_input(BenchmarkId::new("show", n), &n, |b, _| {
            b.iter_batched(
                || issued.clone(),
                |i| i.show(&accepted, true_index, BINDING, &mut OsRng),
                BatchSize::SmallInput,
            )
        });

        let pres = issued.clone().show(&accepted, true_index, BINDING, &mut OsRng);
        g.bench_with_input(BenchmarkId::new("verify", n), &n, |b, _| {
            b.iter(|| pres.verify(&pp, &accepted, BINDING))
        });
    }

    g.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(50);
    targets = bench_issuance, bench_verify, bench_redemption
}
criterion_main!(benches);

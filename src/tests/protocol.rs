//! End-to-end tests for the Anchor token issuer-hiding endorsement protocol.

use crate::anchor::{AnchorNeedsProofRequest, AnchorPublicKey, AnchorRandomness, AnchorSecretKey};
use crate::client::{ClientNeedsSignature, ClientRandomness};
use crate::orproof::OrProof;
use crate::{honest_run, Params, Point, Scalar};
use elliptic_curve::Field;
use rand_core::{OsRng, RngCore};

/// A fresh random byte-string nullifier.
fn random_nullifier<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let mut nf = [0u8; 32];
    rng.fill_bytes(&mut nf);
    nf.to_vec()
}

/// A uniform nonzero scalar (an OR-proof witness for the standalone tests).
fn random_nonzero_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(&mut *rng);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

const CTX: &[u8] = b"epoch-2026-07";

/// An honest end-to-end issuance produces a well-formed endorsement (its DLEQ
/// proof checks out) — protocol correctness.
#[test]
fn issuance_is_correct() {
    let pp = Params::standard();
    let mut rng = OsRng;

    for _ in 0..32 {
        let key = AnchorSecretKey::random(&mut rng);
        let cr = ClientRandomness::random(&mut rng);
        let ar = AnchorRandomness::random(&mut rng);
        let nf = random_nullifier(&mut rng);

        let issued = honest_run(&pp, &key, cr, ar, nf, CTX.to_vec())
            .expect("honest run yields an endorsement");
        assert!(
            issued.endorsement.dleq_valid(&pp),
            "an honest endorsement must be well-formed"
        );
    }
}

/// The message-by-message state machine composes exactly like `honest_run`.
#[test]
fn stepwise_issuance_matches_honest_run() {
    let pp = Params::standard();
    let mut rng = OsRng;

    let key = AnchorSecretKey::random(&mut rng);
    let cr = ClientRandomness::random(&mut rng);
    let ar = AnchorRandomness::random(&mut rng);
    let nf = random_nullifier(&mut rng);

    // Drive the four messages by hand, each step consuming the previous state.
    let (req, client) = ClientNeedsSignature::request_with_randomness(cr, nf.clone(), CTX.to_vec());
    let (sig, anchor) = req.sign_with_randomness(&pp, &key, ar);
    let (proof_req, client) = client.request_proof(&pp, key.public_key(&pp), sig);
    let proof = anchor.prove(proof_req);
    let issued = client
        .finalize(&pp, proof)
        .expect("finalize succeeds for an honest anchor");

    assert!(issued.endorsement.dleq_valid(&pp));
    assert_eq!(issued.gamma, cr.gamma, "the carried witness is γ");

    // Same inputs through the one-shot helper give the same endorsement.
    let issued2 = honest_run(&pp, &key, cr, ar, nf, CTX.to_vec()).unwrap();
    let (end, end2) = (issued.endorsement, issued2.endorsement);
    assert_eq!(end.x_hat, end2.x_hat);
    assert_eq!(end.z_hat, end2.z_hat);
    assert_eq!(end.e, end2.e);
    assert_eq!(end.a, end2.a);
    assert_eq!(end.b, end2.b);
    assert_eq!(end.r, end2.r);
    assert_eq!(end.nf, end2.nf);
    assert_eq!(end.endorsement_context, end2.endorsement_context);
}

/// The rerandomised statement is what the paper claims: `X_hat = γ·X` and
/// `Z_hat = γ·x·Y`, both hidden from the Anchor (who only ever sees `Y' = v·Y`).
#[test]
fn rerandomised_statement_is_well_formed() {
    let pp = Params::standard();
    let mut rng = OsRng;

    let key = AnchorSecretKey::random(&mut rng);
    let cr = ClientRandomness::random(&mut rng);
    let ar = AnchorRandomness::random(&mut rng);
    let nf = random_nullifier(&mut rng);

    let issued = honest_run(&pp, &key, cr, ar, nf.clone(), CTX.to_vec()).unwrap();

    let x = key.public_key(&pp);
    let y = crate::hash::hash_nullifier(&nf);
    assert_eq!(issued.endorsement.x_hat, x.pk * cr.gamma, "X_hat = γ·X");
    assert_eq!(
        issued.endorsement.z_hat,
        y * (cr.gamma * key.sk),
        "Z_hat = γ·x·Y"
    );
}

/// Tampering with any endorsement field is rejected.
#[test]
fn tampered_endorsements_are_rejected() {
    let pp = Params::standard();
    let mut rng = OsRng;

    let key = AnchorSecretKey::random(&mut rng);
    let cr = ClientRandomness::random(&mut rng);
    let ar = AnchorRandomness::random(&mut rng);
    let nf = random_nullifier(&mut rng);
    let end = honest_run(&pp, &key, cr, ar, nf, CTX.to_vec())
        .unwrap()
        .endorsement;
    assert!(end.dleq_valid(&pp));

    let bump = |s: Scalar| s + Scalar::ONE;

    let mut t = end.clone();
    t.a = bump(t.a);
    assert!(!t.dleq_valid(&pp), "tampered a");

    let mut t = end.clone();
    t.b = bump(t.b);
    assert!(!t.dleq_valid(&pp), "tampered b");

    let mut t = end.clone();
    t.r = bump(t.r);
    assert!(!t.dleq_valid(&pp), "tampered r");

    let mut t = end.clone();
    t.e = bump(t.e);
    assert!(!t.dleq_valid(&pp), "tampered e");

    let mut t = end.clone();
    t.nf[0] ^= 0x01;
    assert!(!t.dleq_valid(&pp), "tampered nullifier");

    let mut t = end.clone();
    t.endorsement_context = b"epoch-1999-01".to_vec();
    assert!(!t.dleq_valid(&pp), "tampered endorsement context");

    let mut t = end.clone();
    t.x_hat += pp.g;
    assert!(!t.dleq_valid(&pp), "tampered X_hat");

    // The `a ≠ 0` guard.
    let mut t = end;
    t.a = Scalar::ZERO;
    assert!(!t.dleq_valid(&pp), "a = 0 must be rejected");
}

/// Identity-point forgery: with `X_hat = Z_hat = 0` the challenge cancels from the
/// DLEQ recomputation, so an attacker can fake a self-consistent endorsement,
/// and the OR-proof accepts the identity for every base. Both `dleq_valid` and
/// `verify` must reject it.
#[test]
fn identity_point_forgery_is_rejected() {
    use crate::hash::{fiat_shamir, hash_nullifier, pedersen_generator};
    use crate::orproof::OrProof;
    use crate::{Endorsement, Presentation};

    let pp = Params::standard();
    let mut rng = OsRng;

    let anchors: Vec<AnchorSecretKey> = (0..4).map(|_| AnchorSecretKey::random(&mut rng)).collect();
    let accepted: Vec<AnchorPublicKey> = anchors.iter().map(|k| k.public_key(&pp)).collect();
    let keys: Vec<Point> = accepted.iter().map(|k| k.pk).collect();

    // Forge a self-consistent DLEQ transcript around the identity statement.
    let x_hat = Point::IDENTITY;
    let z_hat = Point::IDENTITY;
    let nf = b"attacker-chosen".to_vec();
    let ctx = CTX.to_vec();
    let y = hash_nullifier(&nf);
    let a = Scalar::ONE; // any nonzero a
    let b = random_nonzero_scalar(&mut rng);
    let r = random_nonzero_scalar(&mut rng);
    let t1 = y * r; // = y·r − z_hat·(e·a) with z_hat = 0
    let t2 = pp.g * r; // = g·r − x_hat·(e·a) with x_hat = 0
    let h = pedersen_generator(&ctx);
    let c = pp.g * a + h * b;
    let e = fiat_shamir(&x_hat, &y, &z_hat, &t1, &t2, &c, &ctx);

    let endorsement = Endorsement {
        x_hat,
        z_hat,
        nf,
        e,
        a,
        b,
        r,
        endorsement_context: ctx,
    };
    assert!(
        !endorsement.dleq_valid(&pp),
        "identity endorsement must be rejected by dleq_valid"
    );

    // Even paired with an OR-proof over the identity statement, verify rejects.
    let or_proof = OrProof::prove(&keys, &x_hat, 0, Scalar::ZERO, &mut rng);
    let forgery = Presentation {
        endorsement,
        or_proof,
    };
    assert!(
        !forgery.verify(&pp, &accepted),
        "forged identity presentation must be rejected"
    );
}

/// A wrong-key anchor cannot make the client's finalize checks pass: if the
/// proof is computed under a different secret, the DLEQ response check fails.
#[test]
fn dishonest_anchor_proof_is_caught() {
    let pp = Params::standard();
    let mut rng = OsRng;

    let key = AnchorSecretKey::random(&mut rng);
    let other = AnchorSecretKey::random(&mut rng);
    let cr = ClientRandomness::random(&mut rng);
    let ar = AnchorRandomness::random(&mut rng);
    let nf = random_nullifier(&mut rng);

    let (req, client) = ClientNeedsSignature::request_with_randomness(cr, nf, CTX.to_vec());
    // Anchor signs honestly under `key`...
    let (sig, _anchor) = req.sign_with_randomness(&pp, &key, ar);
    let (proof_req, client) = client.request_proof(&pp, key.public_key(&pp), sig);
    // ...but proves with the WRONG secret key.
    let bad_anchor = AnchorNeedsProofRequest {
        key: other,
        randomness: ar,
    };
    let bad_proof = bad_anchor.prove(proof_req);
    assert!(
        client.finalize(&pp, bad_proof).is_none(),
        "wrong-key proof must fail finalize"
    );
}

/// The Pedersen generator `H` is bound to the endorsement context: distinct
/// contexts give distinct, non-identity generators, deterministically.
#[test]
fn pedersen_generator_is_context_bound() {
    let h_a = crate::hash::pedersen_generator(b"epoch-A");
    let h_a_again = crate::hash::pedersen_generator(b"epoch-A");
    let h_b = crate::hash::pedersen_generator(b"epoch-B");

    assert_eq!(h_a, h_a_again, "H is deterministic in the context");
    assert_ne!(h_a, h_b, "distinct contexts give distinct H");
    assert_ne!(h_a, Point::IDENTITY, "H is never the identity");
}

/// The OR-proof Fiat–Shamir transcript is length-framed: two differently-shaped
/// `(accepted, X_hat, commitments)` triples that share the same flat point sequence
/// must still produce different challenges. Without length framing these collide.
#[test]
fn or_challenge_is_length_framed() {
    use crate::hash::{fiat_shamir_or, hash_nullifier};
    let (a, b, c, d, e) = (
        hash_nullifier(b"a"),
        hash_nullifier(b"b"),
        hash_nullifier(b"c"),
        hash_nullifier(b"d"),
        hash_nullifier(b"e"),
    );
    // Both hash the flat sequence [A, B, C, D, E], split differently.
    let c1 = fiat_shamir_or(&[a, b, c], &d, &[e]);
    let c2 = fiat_shamir_or(&[a], &b, &[c, d, e]);
    assert_ne!(c1, c2, "length framing must prevent shape collisions");
}

/// The Anchor must sign under the same endorsement context the Client finalizes
/// with. If the context carried in the `SignatureRequest` is switched after the
/// Client builds its state, the Anchor forms `C'` under a different `H` and the
/// Client's Pedersen check in `finalize` rejects it — so the context is enforced
/// on both sides, not just bound into the challenge.
#[test]
fn context_mismatch_between_anchor_and_client_is_rejected() {
    let pp = Params::standard();
    let mut rng = OsRng;

    let key = AnchorSecretKey::random(&mut rng);
    let nf = random_nullifier(&mut rng);

    // Client builds its request and state under context A.
    let (mut req, client) = ClientNeedsSignature::request(nf, b"epoch-A".to_vec(), &mut rng);

    // The context the Anchor sees is switched to B; the Client's state still says A.
    req.endorsement_context = b"epoch-B".to_vec();

    let (sig, anchor) = req.sign(&pp, &key, &mut rng);
    let (proof_req, client) = client.request_proof(&pp, key.public_key(&pp), sig);
    let proof = anchor.prove(proof_req);

    assert!(
        client.finalize(&pp, proof).is_none(),
        "context mismatch (anchor's H_B vs client's H_A) must fail finalize"
    );
}

/// The `1`-of-`n` OR-proof is complete for any true branch and sound against a
/// changed statement or a wrong witness. (Exercises the `orproof` primitive
/// directly, below the `AnchorPublicKey` layer.)
#[test]
fn or_proof_completeness_and_soundness() {
    let pp = Params::standard();
    let mut rng = OsRng;

    let anchors: Vec<AnchorSecretKey> = (0..6).map(|_| AnchorSecretKey::random(&mut rng)).collect();
    let accepted: Vec<Point> = anchors.iter().map(|k| k.public_key(&pp).pk).collect();

    for true_index in 0..accepted.len() {
        let gamma = random_nonzero_scalar(&mut rng);
        let x_hat = accepted[true_index] * gamma;

        let proof = OrProof::prove(&accepted, &x_hat, true_index, gamma, &mut rng);
        assert!(
            proof.verify(&accepted, &x_hat),
            "honest OR proof must verify (branch {true_index})"
        );

        // Same proof against a different statement must fail.
        let x_hat_other = accepted[true_index] * (gamma + Scalar::ONE);
        assert!(
            !proof.verify(&accepted, &x_hat_other),
            "OR proof bound to X_hat only"
        );
    }

    // A prover using the wrong witness produces a non-verifying proof.
    let true_index = 3;
    let gamma = random_nonzero_scalar(&mut rng);
    let x_hat = accepted[true_index] * gamma;
    let wrong = OrProof::prove(&accepted, &x_hat, true_index, gamma + Scalar::ONE, &mut rng);
    assert!(
        !wrong.verify(&accepted, &x_hat),
        "wrong witness must not verify"
    );

    // A statement outside the span of accepted keys cannot be honestly proven.
    let outsider = AnchorSecretKey::random(&mut rng);
    let gamma = random_nonzero_scalar(&mut rng);
    let x_hat = outsider.public_key(&pp).pk * gamma; // not γ·accepted[j] for any known j
    let attempt = OrProof::prove(&accepted, &x_hat, 0, gamma, &mut rng);
    assert!(
        !attempt.verify(&accepted, &x_hat),
        "non-member statement must not verify"
    );
}

/// Full issuer-hiding redemption: issue under one anchor in the accepted set,
/// present with the OR-proof, and have the Verifier accept without learning
/// which anchor issued.
#[test]
fn full_redemption_hides_the_issuer() {
    let pp = Params::standard();
    let mut rng = OsRng;

    let anchors: Vec<AnchorSecretKey> = (0..4).map(|_| AnchorSecretKey::random(&mut rng)).collect();
    let accepted: Vec<AnchorPublicKey> = anchors.iter().map(|k| k.public_key(&pp)).collect();

    for (true_index, issuing) in anchors.iter().enumerate() {
        let cr = ClientRandomness::random(&mut rng);
        let ar = AnchorRandomness::random(&mut rng);
        let nf = random_nullifier(&mut rng);

        // `IssuedEndorsement` carries the OR witness γ, so `show` needs nothing
        // squirreled away from issuance.
        let issued = honest_run(&pp, issuing, cr, ar, nf, CTX.to_vec()).unwrap();
        let pres = issued.show(&accepted, true_index, &mut rng);
        assert!(
            pres.verify(&pp, &accepted),
            "redemption must verify (issuer {true_index})"
        );
    }
}

/// If the issuing anchor is NOT in the verifier's accepted set, no honest
/// presentation verifies.
#[test]
fn redemption_fails_for_unaccepted_issuer() {
    let pp = Params::standard();
    let mut rng = OsRng;

    let accepted_anchors: Vec<AnchorSecretKey> =
        (0..3).map(|_| AnchorSecretKey::random(&mut rng)).collect();
    let accepted: Vec<AnchorPublicKey> =
        accepted_anchors.iter().map(|k| k.public_key(&pp)).collect();

    // Issue under an anchor outside the accepted set.
    let rogue = AnchorSecretKey::random(&mut rng);
    let cr = ClientRandomness::random(&mut rng);
    let ar = AnchorRandomness::random(&mut rng);
    let nf = random_nullifier(&mut rng);
    let issued = honest_run(&pp, &rogue, cr, ar, nf, CTX.to_vec()).unwrap();

    // The endorsement's DLEQ is well-formed on its own (X_hat is unconstrained, so
    // this says nothing about the issuer)...
    assert!(issued.endorsement.dleq_valid(&pp));

    // ...but no OR branch is real, so the Verifier rejects the presentation.
    for claimed_index in 0..accepted.len() {
        let pres = issued.clone().show(&accepted, claimed_index, &mut rng);
        assert!(
            !pres.verify(&pp, &accepted),
            "unaccepted issuer must fail redemption (claimed {claimed_index})"
        );
    }
}

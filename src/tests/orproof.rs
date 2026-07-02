//! Corner-case and adversarial tests for the `1`-of-`n` OR-proof.
//!
//! `protocol.rs` covers the OR-proof's completeness and honest-prover soundness
//! (right/wrong witness, non-member statement). This file targets the boundaries
//! and the checks `OrProof::verify` performs directly: its reject guards (empty
//! set, transcript-count mismatch), degenerate sizes (`n = 1`, duplicate keys),
//! the `prove` preconditions, per-transcript tampering, and a no-witness
//! challenge-splitting forgery.
//!
//! Because `OrProof`/`Transcript` expose public fields, the adversarial tests
//! hand-craft proofs rather than only running the honest prover — that is the
//! only way to exercise `verify`'s two lines of defence (`Σ cⱼ == c` and every
//! branch's `sⱼ·Bⱼ == tⱼ + cⱼ·X_hat`) against malicious input.

use crate::orproof::{OrProof, Transcript};
use crate::{Point, Scalar};
use elliptic_curve::Field;
use rand_core::OsRng;

/// A uniform nonzero scalar.
fn nonzero_scalar() -> Scalar {
    loop {
        let s = Scalar::random(&mut OsRng);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// `n` distinct, non-identity group elements to stand in for accepted keys.
fn accepted_set(n: usize) -> Vec<Point> {
    (0..n)
        .map(|_| Point::GENERATOR * nonzero_scalar())
        .collect()
}

// ---------------------------------------------------------------------------
// Boundary sizes and reject guards
// ---------------------------------------------------------------------------

/// A `1`-of-`1` OR is a degenerate (non-hiding) case, but must still be a
/// complete proof: the single branch is the real one.
#[test]
fn single_key_verifies() {
    let accepted = accepted_set(1);
    let gamma = nonzero_scalar();
    let x_hat = accepted[0] * gamma;

    let proof = OrProof::prove(&accepted, &x_hat, 0, gamma, &mut OsRng);
    assert!(proof.verify(&accepted, &x_hat), "1-of-1 OR must verify");
}

/// `verify`'s empty-set guard: an empty accepted set is never satisfiable, so a
/// proof over it (necessarily with zero transcripts) is rejected outright.
#[test]
fn empty_accepted_set_rejected() {
    let proof = OrProof {
        transcripts: Vec::new(),
    };
    assert!(
        !proof.verify(&[], &Point::GENERATOR),
        "empty accepted set must be rejected"
    );
}

/// `verify`'s length guard: the transcript count must equal the accepted-set
/// size. A proof with a branch dropped or an extra branch appended is rejected
/// before any arithmetic — a malformed proof can't be silently truncated to fit.
#[test]
fn transcript_count_mismatch_rejected() {
    let accepted = accepted_set(4);
    let gamma = nonzero_scalar();
    let x_hat = accepted[2] * gamma;
    let proof = OrProof::prove(&accepted, &x_hat, 2, gamma, &mut OsRng);
    assert!(proof.verify(&accepted, &x_hat));

    // One transcript too few.
    let mut short = proof.clone();
    short.transcripts.pop();
    assert!(
        !short.verify(&accepted, &x_hat),
        "too few transcripts must be rejected"
    );

    // One transcript too many (duplicate of an existing branch).
    let mut long = proof.clone();
    long.transcripts.push(long.transcripts[0]);
    assert!(
        !long.verify(&accepted, &x_hat),
        "too many transcripts must be rejected"
    );

    // Right count, but checked against a smaller accepted set.
    assert!(
        !proof.verify(&accepted[..3], &x_hat),
        "count must match the accepted set passed to verify"
    );
}

/// Repeated keys in the accepted set don't break completeness: proving against
/// one occurrence still verifies (the OR is over positions, not distinct keys).
#[test]
fn duplicate_keys_complete() {
    let mut accepted = accepted_set(3);
    accepted.push(accepted[0]); // a duplicate of branch 0 at branch 3
    let gamma = nonzero_scalar();

    for &idx in &[0usize, 3] {
        let x_hat = accepted[idx] * gamma;
        let proof = OrProof::prove(&accepted, &x_hat, idx, gamma, &mut OsRng);
        assert!(
            proof.verify(&accepted, &x_hat),
            "duplicate-key set must still verify (branch {idx})"
        );
    }
}

/// `prove` requires a non-empty accepted set.
#[test]
#[should_panic(expected = "accepted set must be non-empty")]
fn prove_panics_on_empty_set() {
    let _ = OrProof::prove(&[], &Point::GENERATOR, 0, Scalar::ONE, &mut OsRng);
}

/// `prove` requires `true_index` to be within range.
#[test]
#[should_panic(expected = "true branch out of range")]
fn prove_panics_on_out_of_range_index() {
    let accepted = accepted_set(3);
    let _ = OrProof::prove(&accepted, &Point::GENERATOR, 3, Scalar::ONE, &mut OsRng);
}

// ---------------------------------------------------------------------------
// Adversarial: tampering with a verifying proof
// ---------------------------------------------------------------------------

/// Bumping one branch's response `s` leaves the master challenge intact (the
/// commitments are unchanged, so `Σ cⱼ == c` still holds) but breaks that
/// branch's equation `sⱼ·Bⱼ == tⱼ + cⱼ·X_hat`. Exercises the per-branch check.
#[test]
fn tampered_response_rejected() {
    let accepted = accepted_set(5);
    let gamma = nonzero_scalar();
    let x_hat = accepted[1] * gamma;
    let mut proof = OrProof::prove(&accepted, &x_hat, 1, gamma, &mut OsRng);
    assert!(proof.verify(&accepted, &x_hat));

    proof.transcripts[3].s += Scalar::ONE;
    assert!(
        !proof.verify(&accepted, &x_hat),
        "tampered response must be rejected"
    );
}

/// Bumping one branch's commitment `t` changes the Fiat–Shamir input, so the
/// recomputed master challenge no longer equals `Σ cⱼ` (and the branch equation
/// breaks too). Exercises the binding of the challenge to the commitments.
#[test]
fn tampered_commitment_rejected() {
    let accepted = accepted_set(5);
    let gamma = nonzero_scalar();
    let x_hat = accepted[4] * gamma;
    let mut proof = OrProof::prove(&accepted, &x_hat, 4, gamma, &mut OsRng);
    assert!(proof.verify(&accepted, &x_hat));

    proof.transcripts[0].t += Point::GENERATOR;
    assert!(
        !proof.verify(&accepted, &x_hat),
        "tampered commitment must be rejected"
    );
}

/// Bumping one branch's sub-challenge `c` makes `Σ cⱼ` disagree with the master
/// challenge (which is fixed by the untouched commitments). Exercises the
/// sub-challenge sum check `Σ cⱼ == c`.
#[test]
fn tampered_subchallenge_rejected() {
    let accepted = accepted_set(5);
    let gamma = nonzero_scalar();
    let x_hat = accepted[2] * gamma;
    let mut proof = OrProof::prove(&accepted, &x_hat, 2, gamma, &mut OsRng);
    assert!(proof.verify(&accepted, &x_hat));

    proof.transcripts[2].c += Scalar::ONE;
    assert!(
        !proof.verify(&accepted, &x_hat),
        "tampered sub-challenge must be rejected"
    );
}

/// A no-witness forgery. An adversary with no `γ` can simulate *every* branch:
/// pick `cⱼ, sⱼ` at random and set `tⱼ = sⱼ·Bⱼ − cⱼ·X_hat`, so each branch equation
/// holds by construction. What they cannot control is Fiat–Shamir: the master
/// challenge `c` is fixed by the commitments they just derived, so `Σ cⱼ == c`
/// holds only with negligible probability. This is the crux of soundness, and
/// the honest-prover tests never reach it.
#[test]
fn challenge_split_forgery_rejected() {
    let accepted = accepted_set(6);
    let x_hat = Point::GENERATOR * nonzero_scalar(); // some statement, no witness known

    let transcripts: Vec<Transcript> = accepted
        .iter()
        .map(|b| {
            let c = Scalar::random(&mut OsRng);
            let s = Scalar::random(&mut OsRng);
            let t = *b * s - x_hat * c; // makes s·B == t + c·X_hat hold for this branch
            Transcript { t, c, s }
        })
        .collect();
    let forgery = OrProof { transcripts };

    // Every branch is individually consistent, so only the Σ cⱼ == c check can
    // reject it — and it does.
    assert!(
        !forgery.verify(&accepted, &x_hat),
        "simulated all-branch forgery must fail the challenge-sum check"
    );
}

/// Naming the wrong true branch: the prover holds a real `γ` with `X_hat = γ·Bⱼ`
/// but runs `prove` with `true_index = k ≠ j`. The honest branch `k` is built
/// for the statement `γ·Bₖ ≠ X_hat`, so its equation fails at verification.
#[test]
fn wrong_true_index_rejected() {
    let accepted = accepted_set(4);
    let gamma = nonzero_scalar();
    let real_index = 1;
    let x_hat = accepted[real_index] * gamma; // X_hat = γ·B₁

    let proof = OrProof::prove(&accepted, &x_hat, 3, gamma, &mut OsRng); // claims branch 3
    assert!(
        !proof.verify(&accepted, &x_hat),
        "proof built for the wrong branch must not verify"
    );
}

// ---------------------------------------------------------------------------
// Identity statement is rejected
// ---------------------------------------------------------------------------

/// The identity statement `X_hat = 0` holds for every base, so an OR over it would
/// bind nothing about the issuer. `verify` rejects it regardless of the witness
/// used to build the proof.
#[test]
fn identity_statement_is_rejected() {
    let accepted = accepted_set(4);
    let x_hat = Point::IDENTITY;

    for idx in [0usize, 2] {
        let proof = OrProof::prove(&accepted, &x_hat, idx, Scalar::ZERO, &mut OsRng);
        assert!(
            !proof.verify(&accepted, &x_hat),
            "identity statement must be rejected (claimed branch {idx})"
        );
    }
}

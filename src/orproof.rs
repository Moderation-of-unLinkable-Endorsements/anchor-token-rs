//! The redemption OR-proof: a Cramer–Damgård–Schoenmakers `1`-of-`n` OR over the
//! Schnorr relation `X = w·B`.
//!
//! At redemption the Client proves the rerandomised key `X_hat` is a scalar
//! multiple of *some* accepted Anchor key `Xⱼ ∈ AccSet` (the paper's redemption
//! "proof of knowledge of `γ` such that `X_hat` is in `{γ·X₁, …, γ·Xₙ}`"). Here
//! `B` ranges over the accepted keys and `X = X_hat`; the true branch `j*` uses
//! the witness `w = γ` (so `X_hat = γ·X_{j*}`) and the others are simulated.
//! Non-interactive via Fiat–Shamir.
//!
//! Crate-internal: an implementation detail of
//! [`Presentation`](crate::Presentation). Consumers build one via
//! [`IssuedEndorsement::show`](crate::client::IssuedEndorsement::show) and check
//! it via [`Presentation::verify`](crate::Presentation::verify); they never
//! touch this type directly.

use crate::hash::fiat_shamir_or;
use crate::{Point, Scalar};
use elliptic_curve::group::Group;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A Schnorr transcript for the relation `X = w·B`: commitment `t`, challenge
/// `c`, response `s`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Transcript {
    /// Commitment `t`.
    pub t: Point,
    /// Sub-challenge `c`.
    pub c: Scalar,
    /// Response `s`.
    pub s: Scalar,
}

/// Verifier for the Schnorr relation `X = w·B`: checks `s·B = t + c·X`.
/// (Verification is over public values, so it need not be constant-time;
/// point/scalar `==` route through `subtle::ct_eq` regardless.)
fn verify_branch(b: &Point, x: &Point, tr: &Transcript) -> bool {
    *b * tr.s == tr.t + *x * tr.c
}

/// A `1`-of-`n` OR proof: one transcript per branch.
#[derive(Clone, Debug)]
pub(crate) struct OrProof {
    /// One Schnorr transcript per accepted key.
    pub transcripts: Vec<Transcript>,
}

impl OrProof {
    /// **Prove** (non-interactive, Fiat–Shamir): `X = γ·B[true_index]` for a
    /// hidden `true_index`. Decoy branches are simulated; the real branch absorbs
    /// the master challenge so the sub-challenges sum to it. `binding` is
    /// caller-supplied bytes hashed into the master challenge, scoping the proof
    /// to the context that requested it (see
    /// [`show`](crate::client::IssuedEndorsement::show)).
    ///
    /// Constant-time in the secret `true_index`: no control flow depends on it.
    /// The real base `B_{j*}` is recovered with a `subtle` select over the
    /// accepted set (scalar-mul is constant-time in the point, so `k·B_{j*}`
    /// hides which base was chosen), then every branch does identical work — its
    /// simulated commitment, with the one honest commitment selected in at `j*`.
    ///
    /// # Panics
    /// If `true_index >= accepted.len()` or the accepted set is empty.
    pub(crate) fn prove<R: RngCore + CryptoRng>(
        accepted: &[Point],
        x: &Point,
        true_index: usize,
        witness: Scalar,
        binding: &[u8],
        rng: &mut R,
    ) -> OrProof {
        let n = accepted.len();
        assert!(!accepted.is_empty(), "accepted set must be non-empty");
        assert!(true_index < n, "true branch out of range");

        // Per-branch decoy challenge/response, the real branch's nonce, and a
        // constant-time "is this the real branch?" flag (compared as u64).
        let cdec: Vec<Scalar> = (0..n).map(|_| crate::random_scalar(rng)).collect();
        let sdec: Vec<Scalar> = (0..n).map(|_| crate::random_scalar(rng)).collect();
        let k = crate::random_scalar(rng);
        let is_real: Vec<Choice> = (0..n)
            .map(|l| (l as u64).ct_eq(&(true_index as u64)))
            .collect();

        // Recover, without indexing by the secret: the real base B_{j*}, Σ cdec,
        // and cdec[j*] (the latter two give the real branch's challenge below).
        let mut b_real = Point::IDENTITY;
        let mut total = Scalar::ZERO;
        let mut cdec_real = Scalar::ZERO;
        for l in 0..n {
            b_real = Point::conditional_select(&b_real, &accepted[l], is_real[l]);
            total += cdec[l];
            cdec_real = Scalar::conditional_select(&cdec_real, &cdec[l], is_real[l]);
        }
        let honest_t = b_real * k; // the single honest commitment k·B_{j*}

        // Each branch: its simulated commitment sₗ·Bₗ − cₗ·X, with honest_t
        // selected in at the real branch.
        let commitments: Vec<Point> = (0..n)
            .map(|l| {
                let sim_t = accepted[l] * sdec[l] - *x * cdec[l];
                Point::conditional_select(&sim_t, &honest_t, is_real[l])
            })
            .collect();

        let c = fiat_shamir_or(accepted, x, &commitments, binding);
        let c_real = c - (total - cdec_real); // c − Σ_{l≠j*} cdec[l]
        let s_real = k + c_real * witness;

        let transcripts = (0..n)
            .map(|l| Transcript {
                t: commitments[l],
                c: Scalar::conditional_select(&cdec[l], &c_real, is_real[l]),
                s: Scalar::conditional_select(&sdec[l], &s_real, is_real[l]),
            })
            .collect();

        OrProof { transcripts }
    }

    /// **Verify**: recompute the Fiat–Shamir master challenge from the branch
    /// commitments (under the same `binding` the prover used — any other value
    /// yields a different master challenge, so the proof fails), then check the
    /// sub-challenges sum to it and every branch verifies. Rejects degenerate
    /// inputs: the identity statement `X_hat = 0` (satisfiable for every base, so
    /// it would verify without a witness) and any identity key in the accepted
    /// set (a zero base is a meaningless anchor).
    pub(crate) fn verify(&self, accepted: &[Point], x: &Point, binding: &[u8]) -> bool {
        if self.transcripts.len() != accepted.len() || accepted.is_empty() {
            return false;
        }
        if bool::from(x.is_identity()) || accepted.iter().any(|b| bool::from(b.is_identity())) {
            return false;
        }
        // The transcripts' commitments (`tr.t`) are the FS input, so the verifier
        // reconstructs the master challenge from them.
        let commitments: Vec<Point> = self.transcripts.iter().map(|tr| tr.t).collect();
        let c = fiat_shamir_or(accepted, x, &commitments, binding);

        let sum: Scalar = self
            .transcripts
            .iter()
            .map(|tr| tr.c)
            .fold(Scalar::ZERO, |a, b| a + b);

        // Verification is over public data, so short-circuiting is fine.
        sum == c
            && accepted
                .iter()
                .zip(&self.transcripts)
                .all(|(b, tr)| verify_branch(b, x, tr))
    }
}

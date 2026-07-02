//! The Client role: obtain an endorsement obliviously, then present it.
//!
//! The Client drives issuance through a type-indexed state machine. Each step
//! consumes the previous state and returns the message to send together with
//! the next state, so the steps can only run in protocol order:
//!
//! ```text
//! ClientNeedsSignature::request        ⇒ (SignatureRequest ─▶ Anchor, ClientNeedsSignature)
//! (receive Signature)
//! ClientNeedsSignature::request_proof  ⇒ (ProofRequest ─▶ Anchor, ClientNeedsProof)
//! (receive Proof)
//! ClientNeedsProof::finalize           ⇒ IssuedEndorsement
//! IssuedEndorsement::show              ⇒ Presentation ─▶ Verifier
//! ```
//!
//! The terminal state [`IssuedEndorsement`] pairs the [`Endorsement`] with the
//! rerandomiser `γ` (the redemption OR witness), so the whole flow from
//! [`request`](ClientNeedsSignature::request) to [`Presentation`] runs without
//! the caller keeping any secrets on the side.

use crate::anchor::AnchorPublicKey;
use crate::hash::{fiat_shamir, hash_nullifier, pedersen_generator};
use crate::orproof::OrProof;
use crate::{
    Endorsement, Params, Point, Presentation, Proof, ProofRequest, Scalar, Signature,
    SignatureRequest,
};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

/// Per-issuance randomness for the Client (`v, α, ε ∈ ℤ_p^*`, `γ, β, ρ ∈ ℤ_p`).
/// Crate-internal: the public [`ClientNeedsSignature::request`] samples this
/// itself from an RNG. It must be fresh and unique per issuance (reuse breaks
/// the blinding), which is why it is not exposed in the public API.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClientRandomness {
    /// Input blinding (invertible).
    pub v: Scalar,
    /// Key rerandomisation.
    pub gamma: Scalar,
    /// Committed-challenge twist (invertible).
    pub alpha: Scalar,
    /// Pedersen re-randomiser.
    pub beta: Scalar,
    /// Response twist (invertible).
    pub epsilon: Scalar,
    /// Nonce re-randomiser.
    pub rho: Scalar,
}

impl ClientRandomness {
    /// Sample fresh Client randomness (the invertible fields uniform in `ℤ_p^*`).
    pub(crate) fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        ClientRandomness {
            v: crate::random_nonzero_scalar(rng),
            gamma: crate::random_nonzero_scalar(rng),
            alpha: crate::random_nonzero_scalar(rng),
            beta: crate::random_scalar(rng),
            epsilon: crate::random_nonzero_scalar(rng),
            rho: crate::random_scalar(rng),
        }
    }
}

/// Client state after sending the [`SignatureRequest`]; consumed by
/// [`ClientNeedsSignature::request_proof`] when the [`Signature`] arrives. You
/// only hold it and pass it to that next step; its fields are internal.
#[derive(Clone, Debug)]
pub struct ClientNeedsSignature {
    /// The nullifier.
    pub(crate) nf: Vec<u8>,
    /// Endorsement context (e.g. an epoch), bound into the Fiat–Shamir
    /// challenge.
    pub(crate) endorsement_context: Vec<u8>,
    /// `Y = H₁(nf)`.
    pub(crate) y: Point,
    /// `Y' = v·Y`.
    pub(crate) yp: Point,
    /// The Client's sampled randomness.
    pub(crate) randomness: ClientRandomness,
}

/// Client state after sending the [`ProofRequest`]; carries the transcript
/// needed to validate the Anchor's [`Proof`] and assemble the endorsement in
/// [`ClientNeedsProof::finalize`]. You only hold it and pass it to that next
/// step; its fields are internal.
#[derive(Clone, Debug)]
pub struct ClientNeedsProof {
    /// State from the first round.
    pub(crate) pre: ClientNeedsSignature,
    /// The Anchor's public key `X`.
    pub(crate) x: AnchorPublicKey,
    /// The Anchor's signature.
    pub(crate) sig: Signature,
    /// The twisted challenge `e'`.
    pub(crate) ep: Scalar,
    /// `X_hat = γ·X`.
    pub(crate) x_hat: Point,
    /// `Z_hat = γ·x·Y`.
    pub(crate) z_hat: Point,
    /// The (untwisted) Fiat–Shamir challenge `e`.
    pub(crate) e: Scalar,
}

/// The Client's terminal issuance state: the finished [`Endorsement`] together
/// with the rerandomiser `γ` — the witness that `x_hat = γ·X` — which
/// [`show`](Self::show) needs to build the redemption OR-proof. Produced by
/// [`ClientNeedsProof::finalize`].
///
/// Only the [`Endorsement`] ever crosses the wire; `γ` stays with the Client.
#[derive(Clone, Debug)]
pub struct IssuedEndorsement {
    /// The endorsement (the part sent to the Verifier inside a
    /// [`Presentation`]).
    pub endorsement: Endorsement,
    /// The issuance rerandomiser `γ`, the redemption OR witness. Internal —
    /// consumed by [`show`](Self::show); never read directly.
    pub(crate) gamma: Scalar,
}

impl ClientNeedsSignature {
    /// **Request** (Client → Anchor): blind the hashed nullifier, `Y' = v·Y`.
    /// Starts the state machine: returns the [`SignatureRequest`] to send and
    /// the state awaiting the Anchor's [`Signature`]. The `endorsement_context`
    /// (e.g. an epoch) is bound into the Fiat–Shamir challenge later, so the
    /// finished [`Endorsement`] commits to it.
    pub fn request<R: RngCore + CryptoRng>(
        nf: Vec<u8>,
        endorsement_context: Vec<u8>,
        rng: &mut R,
    ) -> (SignatureRequest, ClientNeedsSignature) {
        Self::request_with_randomness(ClientRandomness::random(rng), nf, endorsement_context)
    }

    /// Crate-internal: [`request`](Self::request) with caller-supplied
    /// randomness, for deterministic test runs. `randomness` must be fresh and
    /// unique per issuance — reuse leaks the Client's blinders and breaks
    /// unlinkability, which is why the public API only exposes the RNG-sampling
    /// [`request`](Self::request).
    pub(crate) fn request_with_randomness(
        randomness: ClientRandomness,
        nf: Vec<u8>,
        endorsement_context: Vec<u8>,
    ) -> (SignatureRequest, ClientNeedsSignature) {
        let y = hash_nullifier(&nf);
        let yp = y * randomness.v;
        (
            SignatureRequest {
                yp,
                endorsement_context: endorsement_context.clone(),
            },
            ClientNeedsSignature {
                nf,
                endorsement_context,
                y,
                yp,
                randomness,
            },
        )
    }

    /// **Request proof** (Client → Anchor): recover `Z_hat`, form the rerandomised
    /// proof's first messages, and send the multiplicatively-twisted challenge
    /// `e' = ε·α⁻¹·γ·e`. Consumes this state and the Anchor's [`Signature`],
    /// producing the [`ProofRequest`] to send and the state awaiting the
    /// Anchor's [`Proof`].
    pub fn request_proof(
        self,
        pp: &Params,
        x: AnchorPublicKey,
        sig: Signature,
    ) -> (ProofRequest, ClientNeedsProof) {
        let cr = self.randomness;
        let v_inv = cr.v.invert().unwrap();
        let alpha_inv = cr.alpha.invert().unwrap();
        let eps_inv = cr.epsilon.invert().unwrap();

        let h = pedersen_generator(&self.endorsement_context);
        let x_hat = x.pk * cr.gamma;
        let z_hat = sig.zp * (cr.gamma * v_inv);
        let c = sig.cp * alpha_inv - h * cr.beta;
        let t1 = (sig.t1p - self.yp * cr.rho) * (eps_inv * v_inv);
        let t2 = (sig.t2p - pp.g * cr.rho) * eps_inv;
        let e = fiat_shamir(
            &x_hat,
            &self.y,
            &z_hat,
            &t1,
            &t2,
            &c,
            &self.endorsement_context,
        );
        let ep = cr.epsilon * alpha_inv * cr.gamma * e;

        (
            ProofRequest { e_prime: ep },
            ClientNeedsProof {
                pre: self,
                x,
                sig,
                ep,
                x_hat,
                z_hat,
                e,
            },
        )
    }
}

impl ClientNeedsProof {
    /// **Finalize** (Client, local): validate the Anchor's [`Proof`] (`a'`
    /// invertible, the Pedersen opening, and the two `DLEQ` response checks),
    /// then unblind to the endorsement. Returns `None` if validation fails.
    pub fn finalize(self, pp: &Params, proof: Proof) -> Option<IssuedEndorsement> {
        let cr = self.pre.randomness;
        let ea = self.ep * proof.ap;

        // Evaluate all checks and combine as constant-time `Choice`s, branching
        // once on the (public) accept/reject result rather than short-circuiting.
        let h = pedersen_generator(&self.pre.endorsement_context);
        let ap_nonzero = !proof.ap.ct_eq(&Scalar::ZERO);
        let pedersen_ok = self.sig.cp.ct_eq(&(pp.g * proof.ap + h * proof.bp));
        let dleq_y = (self.pre.yp * proof.rp).ct_eq(&(self.sig.zp * ea + self.sig.t1p));
        let dleq_g = (pp.g * proof.rp).ct_eq(&(self.x.pk * ea + self.sig.t2p));
        if !bool::from(ap_nonzero & pedersen_ok & dleq_y & dleq_g) {
            return None;
        }

        let alpha_inv = cr.alpha.invert().unwrap();
        let eps_inv = cr.epsilon.invert().unwrap();
        Some(IssuedEndorsement {
            endorsement: Endorsement {
                x_hat: self.x_hat,
                z_hat: self.z_hat,
                nf: self.pre.nf,
                e: self.e,
                a: alpha_inv * proof.ap,
                b: alpha_inv * proof.bp - cr.beta,
                r: eps_inv * (proof.rp - cr.rho),
                endorsement_context: self.pre.endorsement_context,
            },
            gamma: cr.gamma,
        })
    }
}

impl IssuedEndorsement {
    /// **Show** (Client → Verifier): turn the endorsement into a presentation.
    /// `accepted` is the Verifier's accepted Anchor-key set and `true_index`
    /// the secret position of the issuing Anchor within it (so
    /// `endorsement.x_hat == gamma · accepted[true_index]`).
    ///
    /// # Panics
    /// If `true_index >= accepted.len()` or the accepted set is empty.
    pub fn show<R: RngCore + CryptoRng>(
        self,
        accepted: &[AnchorPublicKey],
        true_index: usize,
        rng: &mut R,
    ) -> Presentation {
        let keys: Vec<Point> = accepted.iter().map(|k| k.pk).collect();
        let or_proof = OrProof::prove(&keys, &self.endorsement.x_hat, true_index, self.gamma, rng);
        Presentation {
            endorsement: self.endorsement,
            or_proof,
        }
    }
}

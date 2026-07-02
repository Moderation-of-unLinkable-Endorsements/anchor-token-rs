//! The Anchor role: long-term keys and the two signing steps.
//!
//! The Anchor is stateless until it receives a [`SignatureRequest`]; from
//! there its half of issuance is a two-step state machine:
//!
//! ```text
//! (receive SignatureRequest)
//! SignatureRequest::sign          ⇒ (Signature ─▶ Client, AnchorNeedsProofRequest)
//! (receive ProofRequest)
//! AnchorNeedsProofRequest::prove  ⇒ Proof ─▶ Client
//! ```
//!
//! The Anchor never sees the unblinded nullifier `Y`, the rerandomised
//! statement `(X̂, Ẑ)`, or the untwisted challenge `e` — only the blinded
//! `Y' = v·Y` and the twisted `e' = ε·α⁻¹·γ·e`. It *does* learn the endorsement
//! context (public metadata), which it needs to derive the context-bound
//! Pedersen generator `H` when forming `C'`.

use crate::{Params, Point, Proof, ProofRequest, Scalar, Signature, SignatureRequest};
use rand_core::{CryptoRng, RngCore};

/// An Anchor's long-term secret key.
#[derive(Clone, Copy, Debug)]
pub struct AnchorSecretKey {
    /// Secret scalar `x`.
    pub sk: Scalar,
}

/// An Anchor's public key. The Verifier's policy (the accepted set passed to
/// [`show`](crate::client::IssuedEndorsement::show) and
/// [`verify`](crate::Presentation::verify)) is a slice of these.
#[derive(Clone, Copy, Debug)]
pub struct AnchorPublicKey {
    /// Public point `X = x·G`.
    pub pk: Point,
}

impl AnchorSecretKey {
    /// Sample a fresh Anchor secret key.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        AnchorSecretKey {
            sk: crate::random_nonzero_scalar(rng),
        }
    }

    /// The Anchor's public key `X = x·G`.
    pub fn public_key(&self, pp: &Params) -> AnchorPublicKey {
        AnchorPublicKey { pk: pp.g * self.sk }
    }
}

/// Per-issuance randomness for the Anchor (`a', b', t'`). Crate-internal: the
/// public [`SignatureRequest::sign`] samples this itself from an RNG. It must be
/// fresh and unique per issuance — reuse leaks the secret key (the response is a
/// Schnorr signature under the nonce `t'` against a Client-chosen challenge) —
/// which is why it is not exposed in the public API.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AnchorRandomness {
    /// Committed-challenge factor `a'` (invertible).
    pub ap: Scalar,
    /// Pedersen blinding `b'`.
    pub bp: Scalar,
    /// Proof nonce `t'`.
    pub tp: Scalar,
}

impl AnchorRandomness {
    /// Sample fresh Anchor randomness (`a'` uniform in `ℤ_p^*`).
    pub(crate) fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        AnchorRandomness {
            ap: crate::random_nonzero_scalar(rng),
            bp: crate::random_scalar(rng),
            tp: crate::random_scalar(rng),
        }
    }
}

/// Anchor state after sending the [`Signature`]; consumed by
/// [`AnchorNeedsProofRequest::prove`] when the Client's [`ProofRequest`]
/// arrives. You only hold it and pass it to that next step; its fields are
/// internal.
#[derive(Clone, Copy, Debug)]
pub struct AnchorNeedsProofRequest {
    /// The Anchor's secret key.
    pub(crate) key: AnchorSecretKey,
    /// The Anchor's sampled randomness from the signing step.
    pub(crate) randomness: AnchorRandomness,
}

impl SignatureRequest {
    /// **Sign** (Anchor → Client): the keyed value plus the proof's first
    /// messages. Returns the [`Signature`] to send and the Anchor's state
    /// awaiting the Client's [`ProofRequest`].
    pub fn sign<R: RngCore + CryptoRng>(
        self,
        pp: &Params,
        key: &AnchorSecretKey,
        rng: &mut R,
    ) -> (Signature, AnchorNeedsProofRequest) {
        self.sign_with_randomness(pp, key, AnchorRandomness::random(rng))
    }

    /// Crate-internal: [`sign`](Self::sign) with caller-supplied randomness, for
    /// deterministic test runs. `randomness` must be fresh and unique per
    /// issuance — the response `r' = t' + e'·a'·x` is a Schnorr signature under
    /// the nonce `t'` against a Client-chosen challenge `e'`, so reuse lets a
    /// malicious Client solve for the secret key `x`. That hazard is why the
    /// public API only exposes the RNG-sampling [`sign`](Self::sign).
    pub(crate) fn sign_with_randomness(
        self,
        pp: &Params,
        key: &AnchorSecretKey,
        randomness: AnchorRandomness,
    ) -> (Signature, AnchorNeedsProofRequest) {
        // The Pedersen generator is bound to the endorsement context the Client
        // sent, so `C'` commits under the same `H` the Client and Verifier use.
        let h = crate::hash::pedersen_generator(&self.endorsement_context);
        (
            Signature {
                zp: self.yp * key.sk,
                cp: pp.g * randomness.ap + h * randomness.bp,
                t1p: self.yp * randomness.tp,
                t2p: pp.g * randomness.tp,
            },
            AnchorNeedsProofRequest {
                key: *key,
                randomness,
            },
        )
    }
}

impl AnchorNeedsProofRequest {
    /// **Prove** (Anchor → Client): `r' = t' + e'·a'·x`, opening `a', b'`.
    /// Consumes this state and the Client's [`ProofRequest`].
    pub fn prove(self, req: ProofRequest) -> Proof {
        Proof {
            rp: self.randomness.tp + req.e_prime * self.randomness.ap * self.key.sk,
            ap: self.randomness.ap,
            bp: self.randomness.bp,
        }
    }
}

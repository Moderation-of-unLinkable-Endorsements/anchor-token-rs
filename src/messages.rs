//! The protocol's wire types: the four issuance messages (in order,
//! [`SignatureRequest`] → [`Signature`] → [`ProofRequest`] → [`Proof`]), the
//! finished [`Endorsement`], and the redemption [`Presentation`].
//!
//! These are pure data and are re-exported at the crate root. The verbs that
//! produce and consume them live with their roles — [`crate::client`],
//! [`crate::anchor`], and (for the Verifier) [`Presentation::verify`].

use crate::hash::{fiat_shamir, hash_nullifier, pedersen_generator};
use crate::orproof::OrProof;
use crate::{Params, Point, Scalar};
use elliptic_curve::group::Group;

/// Client → Anchor: the blinded input `Y' = v·Y` and the endorsement context.
/// Created by
/// [`ClientNeedsSignature::request`](crate::client::ClientNeedsSignature::request);
/// the Anchor answers it with [`sign`](Self::sign).
#[derive(Clone, Debug)]
pub struct SignatureRequest {
    /// Blinded nullifier hash `Y'`.
    pub yp: Point,
    /// Endorsement context (e.g. an epoch). The Anchor derives the context-bound
    /// Pedersen generator `H` from it to form `C'`, so it must be told the
    /// context at signing time and both parties commit under the same `H`.
    pub endorsement_context: Vec<u8>,
}

/// Anchor → Client: keyed value, commitment, and two nonce commitments.
/// Created by [`SignatureRequest::sign`]; consumed by
/// [`ClientNeedsSignature::request_proof`](crate::client::ClientNeedsSignature::request_proof).
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    /// `Z' = x·Y'`.
    pub zp: Point,
    /// `C' = a'·G + b'·H`, with `H = H(endorsement_context)`.
    pub cp: Point,
    /// `T₁' = t'·Y'`.
    pub t1p: Point,
    /// `T₂' = t'·G`.
    pub t2p: Point,
}

/// Client → Anchor: the twisted Fiat–Shamir challenge `e'`. Created by
/// [`ClientNeedsSignature::request_proof`](crate::client::ClientNeedsSignature::request_proof);
/// consumed by [`AnchorNeedsProofRequest::prove`](crate::anchor::AnchorNeedsProofRequest::prove).
#[derive(Clone, Copy, Debug)]
pub struct ProofRequest {
    /// The twisted Fiat–Shamir challenge `e' = ε·α⁻¹·γ·e`.
    pub(crate) e_prime: Scalar,
}

/// Anchor → Client: the twisted response and the opened factors. Created by
/// [`AnchorNeedsProofRequest::prove`](crate::anchor::AnchorNeedsProofRequest::prove);
/// consumed by [`ClientNeedsProof::finalize`](crate::client::ClientNeedsProof::finalize).
#[derive(Clone, Copy, Debug)]
pub struct Proof {
    /// `r' = t' + e'·a'·x`.
    pub rp: Scalar,
    /// `a'`.
    pub ap: Scalar,
    /// `b'`.
    pub bp: Scalar,
}

/// The endorsement: a publicly-verifiable `DLEQ` proof on the rerandomised
/// statement `(X_hat, Z_hat)`. Produced by
/// [`ClientNeedsProof::finalize`](crate::client::ClientNeedsProof::finalize)
/// (inside an [`IssuedEndorsement`](crate::client::IssuedEndorsement), which
/// also carries the witness needed to present it).
#[derive(Clone, Debug)]
pub struct Endorsement {
    /// `X_hat = γ·X`.
    pub x_hat: Point,
    /// `Z_hat = γ·x·Y`.
    pub z_hat: Point,
    /// The issuance nullifier.
    pub nf: Vec<u8>,
    /// Fiat–Shamir challenge.
    pub e: Scalar,
    /// Committed factor.
    pub a: Scalar,
    /// Pedersen opening.
    pub b: Scalar,
    /// Response.
    pub r: Scalar,
    /// Endorsement context (e.g. an epoch), bound into the Fiat–Shamir
    /// challenge `e`.
    pub endorsement_context: Vec<u8>,
}

impl Endorsement {
    /// Check the endorsement's Chaum–Pedersen `DLEQ` proof: the `a ≠ 0`,
    /// `Y ≠ 0`, and `X_hat, Z_hat ≠ 0` guards and the Fiat–Shamir check
    /// (recomputing `T₁, T₂, C`, with `X_hat` and the endorsement context bound
    /// into the challenge). The identity guard matters: `X_hat = Z_hat = 0`
    /// cancels the `e·a` terms from the transcript, so without it a forged
    /// endorsement would pass.
    ///
    /// **This is not acceptance.** It only says `(G, X_hat, Y, Z_hat)` is a
    /// well-formed DH tuple; because it never references an anchor key, `X_hat`
    /// is unconstrained and anyone can mint a passing endorsement. Binding
    /// `X_hat` to an accepted anchor is the redemption OR-proof's job, so the
    /// acceptance decision is [`Presentation::verify`], which takes a full
    /// [`Presentation`].
    pub fn dleq_valid(&self, pp: &Params) -> bool {
        if self.a == Scalar::ZERO {
            return false;
        }
        if bool::from(self.x_hat.is_identity()) || bool::from(self.z_hat.is_identity()) {
            return false;
        }
        let y = hash_nullifier(&self.nf);
        if bool::from(y.is_identity()) {
            return false;
        }
        let ea = self.e * self.a;
        let t1 = y * self.r - self.z_hat * ea;
        let t2 = pp.g * self.r - self.x_hat * ea;
        let h = pedersen_generator(&self.endorsement_context);
        let c = pp.g * self.a + h * self.b;
        self.e
            == fiat_shamir(
                &self.x_hat,
                &y,
                &self.z_hat,
                &t1,
                &t2,
                &c,
                &self.endorsement_context,
            )
    }
}

/// Client → Verifier: a redemption presentation, the endorsement and the
/// accepted-set OR-proof. Corresponds to the MoLE notes' `Show` figure
/// `ρ_A = (X_hat, Z_hat, nf, a, b, r)` together with `π_AccSet`. Built by
/// [`IssuedEndorsement::show`](crate::client::IssuedEndorsement::show),
/// accepted (or not) by [`Presentation::verify`].
#[derive(Clone, Debug)]
pub struct Presentation {
    /// The endorsement.
    pub endorsement: Endorsement,
    /// `1`-of-`n` OR-proof that `X_hat` is a `γ`-scaling of an accepted key.
    /// Internal to the presentation — built by
    /// [`show`](crate::client::IssuedEndorsement::show), checked by
    /// [`verify`](Presentation::verify).
    pub(crate) or_proof: OrProof,
}

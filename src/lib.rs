//! # IHAT: pairing-free, issuer-hiding anonymous tokens over NIST P-256
//!
//! A Rust implementation of the **IHAT (issuer-hiding anonymous token) cryptographic protocol**, as
//! designed by the MoLE collaborators: a pairing-free, issuer-hiding
//! endorsement scheme. It is oblivious issuance of a Chaum–Pedersen `DLEQ` proof
//! over the Diffie–Hellman keyed MAC `Z = x·Y`, plus a CDS `1`-of-`n` OR-proof
//! at redemption for issuer hiding.
//!
//! Two phases:
//! * **Issuance** — a two-round exchange after which the Client holds a
//!   publicly-verifiable endorsement on a *rerandomised* statement
//!   `(X_hat, Z_hat) = (γ·X, γ·x·Y)` the Anchor never sees.
//! * **Redemption** — the Client presents the endorsement with an OR-proof
//!   that `X_hat` scales some accepted Anchor key, hiding which one issued.
//!
//! ## Organization
//!
//! The crate is organized by **role**; each party's types and verbs live in
//! the module named for it, and the messages they exchange live here at the
//! crate root:
//!
//! * [`client`] — the Client's issuance state machine and redemption verb
//!   ([`IssuedEndorsement::show`](client::IssuedEndorsement::show)).
//! * [`anchor`] — the Anchor's keys, and its signing steps
//!   ([`SignatureRequest::sign`] and
//!   [`AnchorNeedsProofRequest::prove`](anchor::AnchorNeedsProofRequest::prove)).
//! * **Verifier** (the paper's *Moderator*) — a single verb,
//!   [`Presentation::verify`]: the *only* acceptance decision. It takes a
//!   whole [`Presentation`] (endorsement + issuer OR-proof), so a bare
//!   [`Endorsement`] cannot be accepted. ([`Endorsement::dleq_valid`] is a
//!   well-formedness check, not acceptance.)
//! * Crate root — the wire types, in protocol order: [`SignatureRequest`] →
//!   [`Signature`] → [`ProofRequest`] → [`Proof`], then [`Endorsement`] and
//!   [`Presentation`]. The redemption OR-proof is an internal detail of
//!   [`Presentation`], built by `show` and checked by `verify`.
//!
//! ## Flow
//!
//! Issuance is a type-indexed state machine: each step consumes the previous
//! state (or message) and produces the next, so the steps only run in protocol
//! order, and the terminal state carries everything redemption needs.
//!
//! ```text
//! anchor::AnchorSecretKey::random             ⇒ AnchorSecretKey
//!
//! client::ClientNeedsSignature::request   ─SignatureRequest─▶
//!                                         ◀─Signature────────  SignatureRequest::sign
//! ClientNeedsSignature::request_proof     ─ProofRequest─────▶
//!                                         ◀─Proof────────────  AnchorNeedsProofRequest::prove
//! ClientNeedsProof::finalize                  ⇒ IssuedEndorsement (endorsement + witness γ)
//!
//! IssuedEndorsement::show(AccSet, j*)         ⇒ Presentation
//! Presentation::verify(AccSet)                ⇒ accept / reject
//! ```
//!
//! ## Example
//!
//! ```
//! use rand_core::OsRng;
//! use ihat::anchor::AnchorSecretKey;
//! use ihat::client::ClientNeedsSignature;
//! use ihat::Params;
//!
//! let pp = Params::standard();
//! let mut rng = OsRng;
//!
//! // Anchors publish keys; the Verifier's policy is a set of accepted keys.
//! let anchors: Vec<AnchorSecretKey> =
//!     (0..4).map(|_| AnchorSecretKey::random(&mut rng)).collect();
//! let accepted: Vec<_> = anchors.iter().map(|k| k.public_key(&pp)).collect();
//!
//! // Issuance: the four-message GetEnd exchange with anchor #2.
//! let issuer = &anchors[2];
//! let (request, client) =
//!     ClientNeedsSignature::request(b"nullifier".to_vec(), b"epoch-1".to_vec(), &mut rng);
//! let (signature, anchor) = request.sign(&pp, issuer, &mut rng);
//! let (proof_request, client) = client.request_proof(&pp, issuer.public_key(&pp), signature);
//! let proof = anchor.prove(proof_request);
//! let issued = client.finalize(&pp, proof).expect("honest issuance succeeds");
//!
//! // Redemption: present with a 1-of-n OR-proof; the issuer stays hidden.
//! let presentation = issued.show(&accepted, 2, &mut rng);
//! assert!(presentation.verify(&pp, &accepted));
//! ```
//!
//! The construction follows the `GetEnd` figure in the MoLE notes; security
//! rests on DDH/CDH. The scalar field `𝔽 = ℤ_p` is [`Scalar`], the group `𝔾` is
//! [`Point`], and `•` is point multiplication.

#![forbid(unsafe_code)]

use elliptic_curve::Field as _; // brings `Scalar::random` / `Scalar::ZERO` into scope
use rand_core::{CryptoRng, RngCore};

pub use p256::{ProjectivePoint as Point, Scalar};

pub mod anchor;
pub mod client;
pub(crate) mod hash;
mod messages;
pub(crate) mod orproof;
mod verifier;
mod wire;

#[cfg(test)]
mod tests;

pub use messages::{Endorsement, Presentation, Proof, ProofRequest, Signature, SignatureRequest};
pub use wire::{WireError, WireFormat};

/// Public parameters: the primary generator `G`. The Pedersen generator `H` is
/// *not* fixed here — it is derived per endorsement context (a hash-to-curve of
/// the context), so the context is bound into the commitment `C = a·G + b·H`.
#[derive(Clone, Debug)]
pub struct Params {
    /// Primary generator (the curve's standard base point).
    pub g: Point,
}

impl Params {
    /// The standard public parameters: `G` is the P-256 base point. The Pedersen
    /// generator `H = H(endorsement_context)` is derived per context where it is
    /// used, so it is not stored here.
    pub fn standard() -> Self {
        Params {
            g: Point::GENERATOR,
        }
    }
}

impl Default for Params {
    fn default() -> Self {
        Params::standard()
    }
}

/// Internal test helper: the honest end-to-end issuance, composing the per-step
/// algorithms in a single process (running *both* roles locally). Not part of
/// the public API — real deployments run the [`client`] and [`anchor`] halves
/// on different machines via the per-step verbs, and no consumer should hold
/// both the anchor key and the client randomness at once. Deterministic in the
/// supplied randomness. Returns the finalised endorsement (or `None` if a check
/// fails, which never happens for honest parties).
#[cfg(test)]
pub(crate) fn honest_run(
    pp: &Params,
    key: &anchor::AnchorSecretKey,
    cr: client::ClientRandomness,
    ar: anchor::AnchorRandomness,
    nf: Vec<u8>,
    endorsement_context: Vec<u8>,
) -> Option<client::IssuedEndorsement> {
    let (request, client) =
        client::ClientNeedsSignature::request_with_randomness(cr, nf, endorsement_context);
    let (signature, anchor) = request.sign_with_randomness(pp, key, ar);
    let (proof_request, client) = client.request_proof(pp, key.public_key(pp), signature);
    let proof = anchor.prove(proof_request);
    client.finalize(pp, proof)
}

/// Sample a uniform nonzero scalar (`ℤ_p^*`), for the invertible blinders and the
/// OR-proof witness. The zero-rejection loop is the library's one data-dependent
/// branch; it retries with probability `2⁻²⁵⁶` and leaks nothing about the value.
pub(crate) fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(&mut *rng);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

/// Sample a uniform scalar (an element of `ℤ_p`).
pub(crate) fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    Scalar::random(&mut *rng)
}

//! Hashing primitives: the hash-to-group `H₁` and the Fiat–Shamir hashes.
//!
//! Crate-internal low-level building blocks — not part of the public API. They
//! are invoked by the [`crate::client`] and [`crate::anchor`] steps and the
//! verifiers.
//!
//! Both use RFC 9380 constructions over P-256 (`P256_XMD:SHA-256_SSWU_RO_` for
//! points, `expand_message_xmd` + reduction for scalars), so they are unbiased
//! and domain-separated.

use crate::{Point, Scalar};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::NistP256;
use sha2::Sha256;

/// Domain-separation tag for `H₁`, the hash-to-group applied to nullifiers.
const DST_H1: &[u8] = b"MOLE-AnchorToken-P256:H1-nullifier-to-group:v1";

/// Domain-separation tag for the Fiat–Shamir challenge hash of an issuance.
const DST_FS: &[u8] = b"MOLE-AnchorToken-P256:fiat-shamir-getend:v1";

/// Domain-separation tag for the context-bound Pedersen generator `H`.
const DST_H: &[u8] = b"MOLE-AnchorToken-P256:pedersen-generator-H:v1";

/// Generic hash-to-group with an explicit domain-separation tag. Used both for
/// deriving the Pedersen generator `H` and (via [`hash_nullifier`]) for `H₁`.
fn hash_to_group(dst: &[u8], msg: &[u8]) -> Point {
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[dst])
        .expect("P-256 hash-to-curve with a fixed valid DST cannot fail")
}

/// `H₁`: hash a nullifier to a group element (the paper's `H₁ : ℤ_p → 𝔾`; here
/// the domain is widened to arbitrary application-level nullifier bytes).
pub(crate) fn hash_nullifier(nf: &[u8]) -> Point {
    hash_to_group(DST_H1, nf)
}

/// The Pedersen generator `H` for a given endorsement context — the second
/// generator of the commitment `C = a·G + b·H`. Deriving `H` from the context
/// (rather than fixing one global `H`) binds the context into `C` structurally,
/// so it acts as public metadata every party commits under. Uses the same RFC
/// 9380 hash-to-curve as `H₁`, so `log_G H` is unknown for every context.
pub(crate) fn pedersen_generator(endorsement_context: &[u8]) -> Point {
    hash_to_group(DST_H, endorsement_context)
}

/// Reduce a domain-separated hash of arbitrary byte strings to a scalar,
/// uniformly (via RFC 9380 `hash_to_field`).
fn hash_to_scalar(dst: &[u8], msgs: &[&[u8]]) -> Scalar {
    let mut out = [Scalar::default()];
    elliptic_curve::hash2curve::hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(
        msgs,
        &[dst],
        &mut out,
    )
    .expect("P-256 hash-to-scalar with a fixed valid DST cannot fail");
    out[0]
}

/// A field's byte length as a fixed-width prefix. Transcript rule: fixed-width
/// points are bound as-is, and every variable-length or variable-count field is
/// preceded by its length, so the encoding is injective by construction.
fn len_prefix(n: usize) -> [u8; 8] {
    (n as u64).to_le_bytes()
}

/// The Fiat–Shamir challenge `e = H_FS(X_hat, Y, Z_hat, T₁, T₂, C, ctx)` of the issuance
/// proof (the `HFS` of the `GetEnd` figure, strengthened to bind the *full*
/// statement: the rerandomised key `X_hat` — so a proof cannot be transported to a
/// different `X_hat` — and the endorsement context, so the finished endorsement
/// commits to it). The six fixed-width points are bound in order; the
/// variable-length context is length-prefixed, keeping the encoding injective.
pub(crate) fn fiat_shamir(
    x_hat: &Point,
    y: &Point,
    z_hat: &Point,
    t1: &Point,
    t2: &Point,
    c: &Point,
    endorsement_context: &[u8],
) -> Scalar {
    let pts = [
        compress(x_hat),
        compress(y),
        compress(z_hat),
        compress(t1),
        compress(t2),
        compress(c),
    ];
    let ctx_len = len_prefix(endorsement_context.len());
    let mut refs: Vec<&[u8]> = pts.iter().map(|p| p.as_slice()).collect();
    refs.push(&ctx_len);
    refs.push(endorsement_context);
    hash_to_scalar(DST_FS, &refs)
}

/// The Fiat–Shamir challenge for the redemption OR-proof: hashes the accepted
/// Anchor keys, the rerandomised key `X_hat`, and the OR commitments. Binding
/// `AccSet` and `X_hat` (not just the commitments) is a soundness improvement in
/// the ROM; each variable-count group is length-prefixed, so the transcript is
/// injective for any shape — not only when the number of keys equals the number
/// of commitments.
pub(crate) fn fiat_shamir_or(accepted: &[Point], x_hat: &Point, commitments: &[Point]) -> Scalar {
    const DST_OR: &[u8] = b"MOLE-AnchorToken-P256:fiat-shamir-or-proof:v1";
    let n_acc = len_prefix(accepted.len());
    let n_com = len_prefix(commitments.len());
    let acc: Vec<[u8; 33]> = accepted.iter().map(compress).collect();
    let com: Vec<[u8; 33]> = commitments.iter().map(compress).collect();
    let xh = compress(x_hat);

    let mut refs: Vec<&[u8]> = Vec::with_capacity(acc.len() + com.len() + 3);
    refs.push(&n_acc);
    refs.extend(acc.iter().map(|p| p.as_slice()));
    refs.push(&xh);
    refs.push(&n_com);
    refs.extend(com.iter().map(|p| p.as_slice()));
    hash_to_scalar(DST_OR, &refs)
}

/// Fixed-width compressed encoding of a point (33 bytes for P-256).
fn compress(p: &Point) -> [u8; 33] {
    let mut out = [0u8; 33];
    out.copy_from_slice(p.to_bytes().as_ref());
    out
}

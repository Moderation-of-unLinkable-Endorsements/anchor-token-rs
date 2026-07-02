//! The Verifier role (the paper's *Moderator*): the acceptance decision.
//!
//! The Verifier has a single verb, [`Presentation::verify`], which hangs off
//! the [`Presentation`] wire type (so this module is private — there are no
//! Verifier-only types). Its policy is just the accepted Anchor-key set it
//! passes in.

use crate::anchor::AnchorPublicKey;
use crate::{Params, Point, Presentation};

impl Presentation {
    /// **Verify** (Verifier): the single acceptance decision. A presentation
    /// is accepted iff the endorsement's `DLEQ` proof is well-formed **and**
    /// the OR-proof binds `X̂` to some key in the accepted set. Both are
    /// required, so an endorsement alone can never be accepted (see
    /// [`Endorsement::dleq_valid`](crate::Endorsement::dleq_valid)).
    pub fn verify(&self, pp: &Params, accepted: &[AnchorPublicKey]) -> bool {
        let keys: Vec<Point> = accepted.iter().map(|k| k.pk).collect();
        self.endorsement.dleq_valid(pp) && self.or_proof.verify(&keys, &self.endorsement.x_hat)
    }
}

//! In-crate test suites. Kept as unit tests (compiled with the crate under
//! `#[cfg(test)]`) so they can exercise crate-internal helpers — `honest_run`,
//! the `*_with_randomness` constructors, and the randomness types — that are
//! intentionally not part of the public API.

mod orproof;
mod protocol;
mod wire;

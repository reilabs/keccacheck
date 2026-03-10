//! Keccacheck with direct bit verification.
//!
//! Reduces claims on the output words to claims on the input bits. The verifier
//! checks the input bit claims directly, as it has direct access to the bits.

pub mod prover;
pub mod verifier;

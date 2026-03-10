//! Keccacheck with WHIR polynomial commitment scheme.
//!
//! Claims on the output words are reduced to claims on the output bits, and
//! claims on the input words are reduced to claims on the input bits. There is an
//! additional check that the input bits are indeed boolean values.
//! The claims are combined via sumcheck.
//! The combined claim is then verified via the WHIR PCS.

pub(crate) mod protocol_utils;
pub mod prover;
pub mod verifier;

//! Implementation of GKR algorithm as described in [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.3) (Section 3.3)
//!
//! GKR will use `gkr_round_sumcheck` as a subroutine.

use core::marker::PhantomData;

use ark_ff::Field;

use crate::{gkr_round_sumcheck::{data_structures::GKRRoundProof, GKRRound}, rng::FeedableRNG};

/// GKR algorithm
pub struct GKR<F: Field> {
    _marker: PhantomData<F>,
}

/// Proof for GKR Circuit
pub struct GKRProof<F: Field> {
    /// Proofs for each GKR round
    pub rounds: Vec<GKRRoundProof<F>>,
}

impl<F: Field> GKR<F> {
    /// Takes a GKR Circuit and input, prove the sum.
    /// * `f1`,`f2`,`f3`: represents the GKR round function
    /// * `g`: represents the fixed input.
    pub fn prove<R: FeedableRNG>(
        rng: &mut R,
        round: &GKRRound<F>,
    ) -> GKRProof<F> {
        todo!()
    }
}
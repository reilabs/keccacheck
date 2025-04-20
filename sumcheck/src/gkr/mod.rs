//! Implementation of GKR algorithm as described in [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.3) (Section 3.3)
//!
//! GKR will use `gkr_round_sumcheck` as a subroutine.

use core::marker::PhantomData;

use ark_ff::Field;
use ark_poly::SparseMultilinearExtension;

use crate::{
    gkr_round_sumcheck::{data_structures::GKRRoundProof, GKRRound},
    rng::FeedableRNG,
};

/// GKR circuit definition
pub struct Circuit<F: Field> {
    /// GKR input data
    pub inputs: Vec<F>,
    /// GKR output data
    pub outputs: Vec<F>,
    /// GKR circuit layers
    pub layers: Vec<Layer<F>>,
}

/// Single GKR layer (round)
pub struct Layer<F: Field> {
    /// all gate types in a layer
    pub gates: Vec<LayerGate<F>>,
}

/// Supported gate types
pub enum Gate {
    /// Add gate
    Add,
    /// Mul gate
    Mul,
    /// Xor gate
    Xor,
}

/// wiring for a single gate type in a layer
pub struct LayerGate<F: Field> {
    /// GKR predicate
    pub wiring: SparseMultilinearExtension<F>,
    /// Gate type
    pub gate: Gate,
}

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
    pub fn prove<R: FeedableRNG>(rng: &mut R, round: &GKRRound<F>) -> GKRProof<F> {
        todo!()
    }
}

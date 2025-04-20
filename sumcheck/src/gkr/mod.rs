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
    /// number of variables in a layer
    pub num_vars: usize,
    /// all gate types in a layer
    pub gates: Vec<LayerGate<F>>,
}

#[derive(Debug)]
/// Supported gate types
pub enum Gate {
    /// Add gate
    Add,
    /// Mul gate
    Mul,
    /// Xor gate
    Xor,
}

impl Gate {
    /// Evaluate gate value
    pub fn evaluate<F: Field>(&self, left: F, right: F) -> F {
        match self {
            Gate::Add => left + right,
            Gate::Mul => left * right,
            Gate::Xor => left + right - left * right * F::from(2),
        }
    }
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

    /// Takes a GKR circuit definition and returns value assignments
    /// in all intermediate layers
    pub fn evaluate(circuit: &Circuit<F>) -> Vec<Vec<F>> {
        let mut result = Vec::with_capacity(circuit.layers.len());
        let mut previous_layer = &circuit.inputs;
        for layer in circuit.layers.iter().rev() {
            let mut evaluations = vec![F::ZERO; 1 << layer.num_vars];
            for gate in &layer.gates {
                let wiring = &gate.wiring;
                let input_vars = previous_layer.len().ilog2() as usize;
                let output_vars = wiring.num_vars - 2 * input_vars;
                assert_eq!(layer.num_vars, output_vars);
                for (k, _v) in &wiring.evaluations {
                    let output_gate = k % (1 << output_vars);
                    let k = k >> output_vars;
                    let input_left = previous_layer[k % (1 << input_vars)];
                    let k = k >> input_vars;
                    let input_right = previous_layer[k];
                    evaluations[output_gate] += gate.gate.evaluate(input_left, input_right);
                }
            }
            result.push(evaluations);
            previous_layer = result.last().unwrap();
        }
        result.reverse();
        result
    }
}

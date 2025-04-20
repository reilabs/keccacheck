//! Implementation of GKR algorithm as described in [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.3) (Section 3.3)
//!
//! GKR will use `gkr_round_sumcheck` as a subroutine.

use core::marker::PhantomData;

use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};

use crate::{
    gkr_round_sumcheck::{data_structures::GKRRoundProof, GKRFunction, GKRRound, GKRRoundSumcheck}, rng::FeedableRNG
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
    /// Takes a GKR Circuit and proves the output.
    pub fn prove<R: FeedableRNG>(rng: &mut R, circuit: &Circuit<F>) -> GKRProof<F> {
        let evaluations = Self::evaluate(circuit);
        let num_vars = Self::layer_sizes(circuit);
        assert_eq!(evaluations[0], circuit.outputs);

        let mut gkr_proof = GKRProof {
            rounds: Vec::with_capacity(circuit.layers.len()),
        };

        let mut u = Vec::new();
        let mut v = Vec::new();

        for (i, layer) in circuit.layers.iter().enumerate() {
            if i == 0 {
                let r_1 = vec![F::rand(rng)];
                let w_i = DenseMultilinearExtension::from_evaluations_slice(
                    num_vars[i + 1],
                    &evaluations[i + 1],
                );
                let functions = layer
                    .gates
                    .iter()
                    .map(|gate_type| {
                        // TODO: add support for other gate types
                        assert!(matches!(gate_type.gate, Gate::Mul));

                        GKRFunction {
                            f1_g: gate_type.wiring.fix_variables(&r_1),
                            f2: w_i.clone(),
                            f3: w_i.clone(),
                        }
                    })
                    .collect();

                let round = GKRRound {
                    functions,
                    layer: w_i,
                };
                let (proof, rand) = GKRRoundSumcheck::prove(rng, &round);
                (u, v) = rand;
                gkr_proof.rounds.push(proof);
            } else {
                let alpha = F::rand(rng);
                let beta = F::rand(rng);
                let w_i = DenseMultilinearExtension::from_evaluations_slice(
                    num_vars[i + 1],
                    &evaluations[i + 1],
                );

                let functions = layer
                .gates
                .iter()
                .flat_map(|gate_type| {
                    // TODO: add support for other gate types
                    assert!(matches!(gate_type.gate, Gate::Mul));

                    vec![
                        GKRFunction {
                            f1_g: scale_and_fix(&gate_type.wiring, alpha, &u),
                            f2: w_i.clone(),
                            f3: w_i.clone(),
                        },
                        GKRFunction {
                            f1_g: scale_and_fix(&gate_type.wiring, beta, &v),
                            f2: w_i.clone(),
                            f3: w_i.clone(),
                        },
                    ]
                })
                .collect();


                let round = GKRRound {
                    functions,
                    layer: w_i,
                };
                let (proof, rand) = GKRRoundSumcheck::prove(rng, &round);
                (u, v) = rand;
                gkr_proof.rounds.push(proof);            
            }
        }

        gkr_proof
    }

    /// Takes a GKR circuit definition and returns value assignments
    /// in all intermediate layers
    pub fn layer_sizes(circuit: &Circuit<F>) -> Vec<usize> {
        let mut result = Vec::with_capacity(circuit.layers.len() + 1);
        let mut previous_layer = circuit.outputs.len().ilog2() as usize;
        result.push(previous_layer);
        for layer in &circuit.layers {
            let wiring = &layer.gates.first().expect("at least one gate type").wiring;
            previous_layer = (wiring.num_vars - previous_layer) / 2;
            result.push(previous_layer);
        }
        result
    }


    /// Takes a GKR circuit definition and returns value assignments
    /// in all intermediate layers
    pub fn evaluate(circuit: &Circuit<F>) -> Vec<Vec<F>> {
        let mut result = Vec::with_capacity(circuit.layers.len());
        let mut previous_layer = &circuit.inputs;
        result.push(previous_layer.clone());
        for layer in circuit.layers.iter().rev() {
            let input_vars = previous_layer.len().ilog2() as usize;
            let output_vars = layer
                .gates
                .first()
                .expect("at least one gate type")
                .wiring
                .num_vars
                - 2 * input_vars;
            let mut evaluations = vec![F::ZERO; 1 << output_vars];

            for gate in &layer.gates {
                let wiring = &gate.wiring;
                let gate_output = wiring.num_vars - 2 * input_vars;

                assert_eq!(gate_output, output_vars);
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

/// Scale and fix variables in SparseMLE
pub fn scale_and_fix<F: Field>(
    mle: &SparseMultilinearExtension<F>,
    scalar: F,
    g: &[F],
) -> SparseMultilinearExtension<F> {
    let evaluations = mle
        .evaluations
        .iter()
        .map(|(i, v)| (*i, *v * scalar))
        .collect::<Vec<_>>();
    SparseMultilinearExtension::from_evaluations(mle.num_vars, &evaluations).fix_variables(g)
}

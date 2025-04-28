//! Implementation of GKR algorithm as described in [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.3) (Section 3.3)
//!
//! GKR will use `gkr_round_sumcheck` as a subroutine.

use core::{marker::PhantomData, usize};
use std::collections::HashMap;

use ark_ff::Field;
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, Polynomial, SparseMultilinearExtension,
};
use predicate::{Predicate, PredicateSum, SparseEvaluationPredicate};
use util::bits_to_u64;

use crate::{
    gkr_round_sumcheck::{data_structures::GKRRoundProof, GKRFunction, GKRRound, GKRRoundSumcheck},
    rng::FeedableRNG,
};

pub mod predicate;
pub mod util;

/// GKR circuit definition
pub struct Circuit<F: Field> {
    /// GKR input data
    pub inputs: Vec<F>,
    /// GKR output data
    pub outputs: Vec<F>,
    /// GKR circuit layers
    pub layers: Vec<Layer>,
}

/// Single GKR layer (round)
pub struct Layer {
    /// all gate types in a layer
    pub gates: Vec<LayerGate>,
}

impl Layer {
    /// Create a layer
    pub fn with_builder<B>(output_vars: usize, input_vars: usize, builder: B) -> Self
    where
        B: Fn(usize) -> (Gate, usize, usize),
    {
        let mut result = HashMap::<Gate, HashMap<usize, usize>>::new();

        for out in 0..(1 << output_vars) {
            let (gate, left, right) = builder(out);
            let input = (right << input_vars) + left;
            if let Some(entry) = result.get_mut(&gate) {
                entry.insert(out, input);
            } else {
                let mut hashmap = HashMap::new();
                hashmap.insert(out, input);
                result.insert(gate, hashmap);
            }
        }

        let gates = result
            .into_iter()
            .map(|(k, v)| LayerGate {
                wiring: PredicateSum {
                    predicates: vec![Predicate {
                        eq_predicates: vec![],
                        sparse_predicates: vec![SparseEvaluationPredicate {
                            vars: (0..(output_vars + 2 * input_vars) as u8).collect(),
                            mle: v,
                        }],
                    }],
                    inputs: input_vars,
                    outputs: output_vars,
                },
                gate: k,
            })
            .collect::<Vec<_>>();

        Self { gates }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
/// Supported gate types
pub enum Gate {
    /// Add gate
    Add,
    /// Mul gate
    Mul,
    /// Xor gate
    Xor,
    /// left child gate
    Left,
    /// empty value
    Null,
}

impl Gate {
    /// Evaluate gate value
    pub fn evaluate<F: Field>(&self, left: F, right: F) -> F {
        match self {
            Gate::Add => left + right,
            Gate::Mul => left * right,
            Gate::Xor => left + right - left * right * F::from(2),
            Gate::Left => left,
            Gate::Null => F::zero(),
        }
    }

    /// Gate definitions on lower layers
    pub fn to_gkr_combination<F: Field>(
        &self,
        wiring: &[SparseMultilinearExtension<F>],
        values: &DenseMultilinearExtension<F>,
        combination: &[(F, &[F])],
    ) -> Vec<GKRFunction<F>> {
        match self {
            Gate::Add => {
                let const_one = DenseMultilinearExtension::from_evaluations_vec(
                    values.num_vars,
                    vec![F::ONE; 1 << values.num_vars],
                );

                combination
                    .into_iter()
                    .flat_map(|(coeff, partial_point)| {
                        wiring
                            .fix_variables(partial_point)
                            .into_iter()
                            .flat_map(|predicate| {
                                vec![
                                    GKRFunction {
                                        f1_g: scale(&predicate, coeff),
                                        f2: const_one.clone(),
                                        f3: values.clone(),
                                    },
                                    GKRFunction {
                                        f1_g: scale(&predicate, coeff),
                                        f2: values.clone(),
                                        f3: const_one.clone(),
                                    },
                                ]
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect()
            }
            Gate::Mul => combination
                .into_iter()
                .flat_map(|(coeff, partial_point)| {
                    wiring
                        .fix_variables(partial_point)
                        .into_iter()
                        .flat_map(|predicate| {
                            vec![GKRFunction {
                                f1_g: scale(&predicate, coeff),
                                f2: values.clone(),
                                f3: values.clone(),
                            }]
                        })
                        .collect::<Vec<_>>()
                })
                .collect(),
            Gate::Xor => {
                let const_one = DenseMultilinearExtension::from_evaluations_vec(
                    values.num_vars,
                    vec![F::ONE; 1 << values.num_vars],
                );
                combination
                    .into_iter()
                    .flat_map(|(coeff, partial_point)| {
                        wiring
                            .fix_variables(partial_point)
                            .into_iter()
                            .flat_map(|predicate| {
                                vec![
                                    GKRFunction {
                                        f1_g: scale(&predicate, coeff),
                                        f2: const_one.clone(),
                                        f3: values.clone(),
                                    },
                                    GKRFunction {
                                        f1_g: scale(&predicate, coeff),
                                        f2: values.clone(),
                                        f3: const_one.clone(),
                                    },
                                    GKRFunction {
                                        f1_g: scale(&predicate, &(*coeff * Into::<F>::into(-2))),
                                        f2: values.clone(),
                                        f3: values.clone(),
                                    },
                                ]
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect()
            }
            Gate::Left => {
                let const_one = DenseMultilinearExtension::from_evaluations_vec(
                    values.num_vars,
                    vec![F::ONE; 1 << values.num_vars],
                );
                combination
                    .into_iter()
                    .flat_map(|(coeff, partial_point)| {
                        wiring
                            .fix_variables(partial_point)
                            .into_iter()
                            .flat_map(|predicate| {
                                vec![GKRFunction {
                                    f1_g: scale(&predicate, coeff),
                                    f2: values.clone(),
                                    f3: const_one.clone(),
                                }]
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect()
            }
            Gate::Null => {
                vec![]
            }
        }
    }
}

#[derive(Debug)]
/// wiring for a single gate type in a layer
pub struct LayerGate {
    /// GKR predicate
    pub wiring: PredicateSum,
    /// Gate type
    pub gate: Gate,
}

impl LayerGate {
    pub fn new(
        outputs: usize,
        inputs: usize,
        gate: Gate,
        wiring: Vec<(usize, usize, usize)>,
    ) -> Self {
        let num_vars = outputs + 2 * inputs;
        Self {
            wiring: PredicateSum {
                predicates: vec![Predicate {
                    eq_predicates: Default::default(),
                    sparse_predicates: vec![SparseEvaluationPredicate {
                        vars: (0..num_vars as u8).collect(),
                        mle: wiring
                            .into_iter()
                            .map(|(out, in1, in2)| (out, (in2 << inputs) + in1))
                            .collect(),
                    }],
                }],
                inputs,
                outputs,
            },
            gate,
        }
    }
}

/// GKR algorithm
pub struct GKR<F: Field> {
    _marker: PhantomData<F>,
}

#[derive(Debug)]
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

        if evaluations[0] != circuit.outputs {
            println!("expect {:x?}", bits_to_u64(&circuit.outputs));
            println!("actual {:x?}", bits_to_u64(&evaluations[0]));
            panic!("evaluation failed");

            //assert_eq!(evaluations[0], circuit.outputs);
        }

        let mut gkr_proof = GKRProof {
            rounds: Vec::with_capacity(circuit.layers.len()),
        };

        let mut u = Vec::new();
        let mut v = Vec::new();

        for (i, layer) in circuit.layers.iter().enumerate() {
            if i == 0 {
                let r_1 = (0..num_vars[0]).map(|_| F::rand(rng)).collect::<Vec<_>>();
                let w_i = DenseMultilinearExtension::from_evaluations_slice(
                    num_vars[i + 1],
                    &evaluations[i + 1],
                );
                let functions = layer
                    .gates
                    .iter()
                    .flat_map(|gate_type| {
                        gate_type.gate.to_gkr_combination(
                            &gate_type.wiring.sparse_mle(),
                            &w_i,
                            &[(F::ONE, &r_1)],
                        )
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
                        gate_type.gate.to_gkr_combination(
                            &gate_type.wiring.sparse_mle(),
                            &w_i,
                            &[(alpha, &u), (beta, &v)],
                        )
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

    /// Verifies a proof of a GKR circuit execution.
    pub fn verify<R: FeedableRNG>(rng: &mut R, circuit: &Circuit<F>, gkr_proof: &GKRProof<F>) {
        let num_vars = Self::layer_sizes(circuit);

        let (mut u, mut v) = Default::default();
        let (mut w_u, mut w_v) = Default::default();

        for (i, layer) in circuit.layers.iter().enumerate() {
            if i == 0 {
                let r_1 = (0..num_vars[0]).map(|_| F::rand(rng)).collect::<Vec<_>>();
                let w_0 = DenseMultilinearExtension::from_evaluations_slice(
                    circuit.outputs.len().ilog2() as usize,
                    &circuit.outputs,
                );
                let expected_sum = w_0.evaluate(&r_1);
                let proof = &gkr_proof.rounds[i];
                let subclaim =
                    GKRRoundSumcheck::verify(rng, num_vars[i + 1], proof, expected_sum).unwrap();
                (w_u, w_v) = (subclaim.w_u, subclaim.w_v);

                let mut wiring_res = F::ZERO;
                for gate_type in &layer.gates {
                    let ruv: Vec<_> = r_1
                        .iter()
                        .chain(subclaim.u.iter())
                        .chain(subclaim.v.iter())
                        .copied()
                        .collect();

                    let wiring = gate_type.wiring.evaluate(&ruv);
                    wiring_res += wiring * gate_type.gate.evaluate(w_u, w_v)
                }
                assert_eq!(wiring_res, proof.check_sum(subclaim.v.last().unwrap()));
                (u, v) = (subclaim.u, subclaim.v);
            } else if i == circuit.layers.len() - 1 {
                let alpha = F::rand(rng);
                let beta = F::rand(rng);
                let expected_sum = alpha * w_u + beta * w_v;
                let proof = &gkr_proof.rounds[i];
                let subclaim =
                    GKRRoundSumcheck::verify(rng, num_vars[i + 1], proof, expected_sum).unwrap();

                // verify last round matches actual inputs
                let w_n = DenseMultilinearExtension::from_evaluations_slice(
                    circuit.inputs.len().ilog2() as usize,
                    &circuit.inputs,
                );
                assert_eq!(w_n.evaluate(&subclaim.u), subclaim.w_u);
                assert_eq!(w_n.evaluate(&subclaim.v), subclaim.w_v);
            } else {
                let alpha = F::rand(rng);
                let beta = F::rand(rng);
                let expected_sum = alpha * w_u + beta * w_v;
                let proof = &gkr_proof.rounds[i];
                let subclaim =
                    GKRRoundSumcheck::verify(rng, num_vars[i + 1], proof, expected_sum).unwrap();
                (w_u, w_v) = (subclaim.w_u, subclaim.w_v);

                let mut wiring_res = F::ZERO;
                for gate_type in &layer.gates {
                    let uuv: Vec<_> = u
                        .iter()
                        .chain(subclaim.u.iter())
                        .chain(subclaim.v.iter())
                        .copied()
                        .collect();
                    let vuv: Vec<_> = v
                        .iter()
                        .chain(subclaim.u.iter())
                        .chain(subclaim.v.iter())
                        .copied()
                        .collect();

                    let wiring = &gate_type.wiring;
                    let wiring_u = wiring.evaluate(&uuv);
                    let wiring_v = wiring.evaluate(&vuv);
                    wiring_res +=
                        (alpha * wiring_u + beta * wiring_v) * gate_type.gate.evaluate(w_u, w_v);
                }
                assert_eq!(wiring_res, proof.check_sum(subclaim.v.last().unwrap()));
                (u, v) = (subclaim.u, subclaim.v);
            }
        }
    }

    /// Takes a GKR circuit definition and returns value assignments
    /// in all intermediate layers
    pub fn layer_sizes(circuit: &Circuit<F>) -> Vec<usize> {
        let mut result = Vec::with_capacity(circuit.layers.len() + 1);
        let mut previous_layer = circuit.outputs.len().ilog2() as usize;
        result.push(previous_layer);
        for layer in &circuit.layers {
            let wiring = &layer.gates.first().expect("at least one gate type").wiring;
            previous_layer = (wiring.num_vars() - previous_layer) / 2;
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
            let output_vars = layer
                .gates
                .first()
                .expect("at least one gate type")
                .wiring
                .outputs;
            let mut evaluations = vec![F::ZERO; 1 << output_vars];

            for gate in &layer.gates {
                let wiring = &gate.wiring;
                let gate_output = wiring.outputs;

                assert_eq!(gate_output, output_vars);
                for (out_gate, left_gate, right_gate) in &wiring.evaluations() {
                    let input_left = previous_layer[*left_gate];
                    let input_right = previous_layer[*right_gate];
                    evaluations[*out_gate] += gate.gate.evaluate(input_left, input_right);
                }
            }
            result.push(evaluations);
            previous_layer = result.last().unwrap();
        }
        result.reverse();
        result
    }
}

/// Scale SparseMLE
pub fn scale<F: Field>(
    mle: &SparseMultilinearExtension<F>,
    scalar: &F,
) -> SparseMultilinearExtension<F> {
    let evaluations = mle
        .evaluations
        .iter()
        .map(|(i, v)| (*i, *v * scalar))
        .collect::<Vec<_>>();
    SparseMultilinearExtension::from_evaluations(mle.num_vars, &evaluations)
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

trait EvaluateSparseSum<F: Field> {
    fn fix_variables(&self, partial_point: &[F]) -> Vec<SparseMultilinearExtension<F>>;
}

impl<F: Field> EvaluateSparseSum<F> for [SparseMultilinearExtension<F>] {
    fn fix_variables(&self, partial_point: &[F]) -> Vec<SparseMultilinearExtension<F>> {
        self.iter()
            .map(|x| x.fix_variables(partial_point))
            .collect()
    }
}

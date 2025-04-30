use core::{marker::PhantomData, usize};
use std::collections::HashMap;

use ark_ff::Field;
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, Polynomial, SparseMultilinearExtension,
};
pub use gate::Gate;
use predicate::{BasePredicate, PredicateExpr, SparseEvaluationPredicate};
use util::bits_to_u64;

use crate::{
    gkr_round_sumcheck::{data_structures::GKRRoundProof, GKRFunction, GKRRound, GKRRoundSumcheck},
    rng::FeedableRNG,
};

pub mod circuit;
pub mod compiled;
pub mod gate;
pub mod graph;
pub mod predicate;
pub mod util;

/// GKR problem instance
pub struct Instance<F: Field> {
    /// GKR input data
    pub inputs: Vec<F>,
    /// GKR output data
    pub outputs: Vec<F>,
}

/// GKR circuit definition
pub struct Circuit {
    /// GKR input size
    pub input_bits: usize,
    /// GKR output size
    pub output_bits: usize,
    /// GKR circuit layers
    pub layers: Vec<Layer>,
}

impl Circuit {
    pub fn to_evaluation_graph(&self) -> EvaluationGraph {
        let mut input_bits = self.input_bits;

        let mut layers = Vec::with_capacity(self.layers.len());
        for layer in self.layers.iter().rev() {
            let layer_bits = layer.layer_bits;
            let gates = layer
                .gates
                .iter()
                .map(|gate| {
                    let wiring = &gate.wiring;
                    let graph = wiring.to_dnf().to_evaluation_graph(layer_bits, input_bits);

                    EvaluationGate {
                        gate: gate.gate,
                        graph,
                    }
                })
                .collect();

            input_bits = layer_bits;

            layers.push(EvaluationLayer { layer_bits, gates });
        }
        layers.reverse();
        EvaluationGraph { layers }
    }
}

#[derive(Debug)]
pub struct EvaluationGraph {
    pub layers: Vec<EvaluationLayer>,
}

#[derive(Debug)]
pub struct EvaluationLayer {
    /// number of variables in the layer
    pub layer_bits: usize,
    /// all gate types in a layer    
    pub gates: Vec<EvaluationGate>,
}

#[derive(Debug)]
pub struct EvaluationGate {
    pub gate: Gate,
    pub graph: Vec<Option<(usize, usize)>>,
}

/// Single GKR layer (round)
pub struct Layer {
    /// number of variables in the layer
    pub layer_bits: usize,
    /// all gate types in a layer
    pub gates: Vec<LayerGate>,
}

impl Layer {
    /// Create a layer
    pub fn with_builder<B>(output_bits: usize, input_bits: usize, builder: B) -> Self
    where
        B: Fn(usize) -> (Gate, usize, usize),
    {
        let mut result = HashMap::<Gate, HashMap<usize, usize>>::new();

        for out in 0..(1 << output_bits) {
            let (gate, left, right) = builder(out);
            let input = (right << input_bits) + left;
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
                wiring: PredicateExpr::Base(BasePredicate::Sparse(SparseEvaluationPredicate {
                    var_mask: (1 << (output_bits + 2 * input_bits)) - 1,
                    out_len: output_bits,
                    mle: v,
                })),
                gate: k,
            })
            .collect::<Vec<_>>();

        println!("layer with bits {output_bits}");
        Self {
            layer_bits: output_bits,
            gates,
        }
    }
}

#[derive(Debug)]
/// wiring for a single gate type in a layer
pub struct LayerGate {
    /// Gate type
    pub gate: Gate,
    /// GKR predicate
    pub wiring: PredicateExpr,
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
            wiring: PredicateExpr::Base(BasePredicate::Sparse(SparseEvaluationPredicate {
                var_mask: (1 << num_vars) - 1,
                out_len: outputs,
                mle: wiring
                    .into_iter()
                    .map(|(out, in1, in2)| (out, (in2 << inputs) + in1))
                    .collect(),
            })),
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
    pub fn prove<R: FeedableRNG>(
        rng: &mut R,
        circuit: &Circuit,
        instances: &[&Instance<F>],
    ) -> GKRProof<F> {
        assert_eq!(instances.len(), 1, "currently only one instance supported");
        let instance = &instances[0];

        let eval_graph = circuit.to_evaluation_graph();
        let evaluations = Self::evaluate(&eval_graph, instance);
        let num_vars = Self::layer_sizes(circuit);

        if evaluations[0] != instance.outputs {
            println!("expect {:x?}", bits_to_u64(&instance.outputs));
            println!("actual {:x?}", bits_to_u64(&evaluations[0]));
            panic!("evaluation failed");

            //assert_eq!(evaluations[0], circuit.outputs);
        }

        let mut gkr_proof = GKRProof {
            rounds: Vec::with_capacity(circuit.layers.len()),
        };

        let mut u = Vec::new();
        let mut v = Vec::new();
        let r_1 = (0..num_vars[0]).map(|_| F::rand(rng)).collect::<Vec<_>>();

        for (i, layer) in circuit.layers.iter().enumerate() {
            let combination: &[(F, &[F])] = if i == 0 {
                &[(F::ONE, &r_1)]
            } else {
                let alpha = F::rand(rng);
                let beta = F::rand(rng);
                &[(alpha, &u), (beta, &v)]
            };

            let w_i = DenseMultilinearExtension::from_evaluations_slice(
                num_vars[i + 1],
                &evaluations[i + 1],
            );

            let functions = layer
                .gates
                .iter()
                .flat_map(|gate_type| {
                    gate_type.gate.to_gkr_combination(
                        &gate_type
                            .wiring
                            .to_dnf()
                            .to_sum_of_sparse_mle(num_vars[i], num_vars[i + 1]),
                        &w_i,
                        combination,
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

        gkr_proof
    }

    /// Verifies a proof of a GKR circuit execution.
    pub fn verify<R: FeedableRNG>(
        rng: &mut R,
        circuit: &Circuit,
        instances: &[&Instance<F>],
        gkr_proof: &GKRProof<F>,
    ) {
        assert_eq!(instances.len(), 1, "currently only one instance supported");
        let instance = instances[0];

        let num_vars = Self::layer_sizes(circuit);

        let (mut u, mut v) = Default::default();
        let (mut w_u, mut w_v) = Default::default();

        for (i, layer) in circuit.layers.iter().enumerate() {
            if i == 0 {
                let r_1 = (0..num_vars[0]).map(|_| F::rand(rng)).collect::<Vec<_>>();
                let w_0 = DenseMultilinearExtension::from_evaluations_slice(
                    circuit.output_bits,
                    &instance.outputs,
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
                    circuit.input_bits,
                    &instance.inputs,
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
    pub fn layer_sizes(circuit: &Circuit) -> Vec<usize> {
        let mut result = Vec::with_capacity(circuit.layers.len() + 1);
        for layer in &circuit.layers {
            result.push(layer.layer_bits);
        }
        result.push(circuit.input_bits);
        result
    }

    /// Takes a GKR circuit definition and returns value assignments
    /// in all intermediate layers
    pub fn evaluate(graph: &EvaluationGraph, instance: &Instance<F>) -> Vec<Vec<F>> {
        let mut result = Vec::with_capacity(graph.layers.len() + 1);
        let mut previous_layer = &instance.inputs;
        result.push(previous_layer.clone());
        for layer in graph.layers.iter().rev() {
            let output_vars = layer.layer_bits;
            let mut evaluations = vec![F::ZERO; 1 << output_vars];

            for gate in &layer.gates {
                for (out_gate, maybe_gates) in gate.graph.iter().enumerate() {
                    if let Some((left_gate, right_gate)) = maybe_gates {
                        let input_left = previous_layer[*left_gate];
                        let input_right = previous_layer[*right_gate];
                        evaluations[out_gate] += gate.gate.evaluate(input_left, input_right);
                    }
                }
            }
            result.push(evaluations);
            previous_layer = result.last().unwrap();
        }
        result.reverse();
        result
    }
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

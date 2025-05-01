use core::marker::PhantomData;

use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, Polynomial};
pub use circuit::{Circuit, Layer, LayerGate};
use compiled::CompiledCircuit;
pub use gate::Gate;
use util::{bits_to_u64, ilog2_ceil};

use crate::{
    gkr_round_sumcheck::{data_structures::GKRRoundProof, GKRRound, GKRRoundSumcheck},
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
        circuit: &CompiledCircuit<F>,
        instances: &[Instance<F>],
    ) -> GKRProof<F> {
        let evaluations_by_instance = instances
            .iter()
            .map(|instance| circuit.evaluate(instance))
            .collect::<Vec<_>>();
        let evaluations = (0..=circuit.layers.len())
            .map(|layer| {
                (0..instances.len())
                    .flat_map(|instance| evaluations_by_instance[instance][layer].clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let instance_bits = ilog2_ceil(instances.len());
        let num_vars = circuit.layer_sizes();

        for i in 0..instances.len() {
            for j in 0..instances[i].outputs.len() {
                assert_eq!(evaluations[0][i * instances[i].outputs.len() + j], instances[i].outputs[j]);
            }
        }

        for (eval, instance) in evaluations_by_instance.iter().zip(instances) {
            if eval[0] != instance.outputs {
                println!("expect {:x?}", bits_to_u64(&instance.outputs));
                println!("actual {:x?}", bits_to_u64(&eval[0]));
                panic!("evaluation failed");
            }
        }

        let mut gkr_proof = GKRProof {
            rounds: Vec::with_capacity(circuit.layers.len()),
        };

        let mut u = Vec::new();
        let mut v = Vec::new();
        let r_1 = (0..(instance_bits + num_vars[0])).map(|_| F::rand(rng)).collect::<Vec<_>>();

        for (i, layer) in circuit.layers.iter().enumerate() {
            let combination: &[(F, &[F])] = if i == 0 {
                &[(F::ONE, &r_1)]
            } else {
                let alpha = F::rand(rng);
                let beta = F::rand(rng);
                &[(alpha, &u), (beta, &v)]
            };

            println!("\nproving layer {i}: {combination:?}");

            let w_i = DenseMultilinearExtension::from_evaluations_slice(
                instance_bits + num_vars[i + 1],
                &evaluations[i + 1],
            );

            let functions = layer
                .gates
                .iter()
                .flat_map(|gate_type| {
                    println!("mle {:?}", gate_type.sum_of_sparse_mle);
                    let result = gate_type.gate.to_gkr_combination(
                        &gate_type.sum_of_sparse_mle,
                        &w_i,
                        combination,
                    );
                    println!("gkr_combination {:?}", result);
                    result
                })
                .collect();

            let round = GKRRound {
                functions,
                layer: w_i,
                instance_bits
            };

            println!("polynomials {round:?}");

            let (proof, rand) = GKRRoundSumcheck::prove(rng, &round);            
            (u, v) = rand;
            println!("proof points {u:?}, {v:?}");
            gkr_proof.rounds.push(proof);
        }

        gkr_proof
    }

    /// Verifies a proof of a GKR circuit execution.
    pub fn verify<R: FeedableRNG>(
        rng: &mut R,
        circuit: &Circuit,
        instances: &[Instance<F>],
        gkr_proof: &GKRProof<F>,
    ) {
        println!("\n\nVERIFIACTION\n");
        let instance_bits = ilog2_ceil(instances.len());
        let num_vars = circuit.layer_sizes();

        let (mut u, mut v) = Default::default();
        let (mut w_u, mut w_v) = Default::default();

        // TODO: this allocates too much
        let inputs = instances.iter().flat_map(|instance| instance.inputs.clone()).collect::<Vec<_>>();
        let outputs = instances.iter().flat_map(|instance| instance.outputs.clone()).collect::<Vec<_>>();

        println!("INPUTS {inputs:?}");
        println!("OUTPUTS {outputs:?}");

        for (i, layer) in circuit.layers.iter().enumerate() {
            println!("\nVERIFYING LAYER {i}");
            if i == 0 {
                let r_1 = (0..(instance_bits + num_vars[0])).map(|_| F::rand(rng)).collect::<Vec<_>>();
                let w_0 = DenseMultilinearExtension::from_evaluations_slice(
                    instance_bits + circuit.output_bits,
                    &outputs,
                );
                let expected_sum = w_0.evaluate(&r_1);
                println!("EXPECTED {expected_sum:?}");

                let proof = &gkr_proof.rounds[i];
                let subclaim =
                    GKRRoundSumcheck::verify(rng, instance_bits, num_vars[i + 1], proof, expected_sum).unwrap();
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
                println!("EXPECTED {expected_sum:?}");

                let proof = &gkr_proof.rounds[i];
                let subclaim =
                    GKRRoundSumcheck::verify(rng, instance_bits, num_vars[i + 1], proof, expected_sum).unwrap();

                // verify last round matches actual inputs
                let w_n = DenseMultilinearExtension::from_evaluations_slice(
                    instance_bits + circuit.input_bits,
                    &inputs,
                );
                println!("vars {} {} {}", w_n.num_vars, subclaim.u.len(), subclaim.v.len());
                assert_eq!(w_n.evaluate(&subclaim.u), subclaim.w_u);
                assert_eq!(w_n.evaluate(&subclaim.v), subclaim.w_v);
            } else {
                let alpha = F::rand(rng);
                let beta = F::rand(rng);
                let expected_sum = alpha * w_u + beta * w_v;
                println!("EXPECTED {expected_sum:?}");

                let proof = &gkr_proof.rounds[i];
                let subclaim =
                    GKRRoundSumcheck::verify(rng, instance_bits, num_vars[i + 1], proof, expected_sum).unwrap();
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
}

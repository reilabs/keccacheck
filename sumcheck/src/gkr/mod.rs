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

#[derive(Debug)]
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

        // for i in 0..instances.len() {
        //     for j in 0..instances[i].outputs.len() {
        //         assert_eq!(
        //             evaluations[0][i * instances[i].outputs.len() + j],
        //             instances[i].outputs[j]
        //         );
        //     }
        // }

        for (eval, instance) in evaluations_by_instance.iter().zip(instances) {
            if eval[0] != instance.outputs {
                println!("expect {:x?}", &instance.outputs);
                println!("actual {:x?}", &eval[0]);
                panic!("evaluation failed");
            }
        }

        let mut gkr_proof = GKRProof {
            rounds: Vec::with_capacity(circuit.layers.len()),
        };

        let mut uc = Vec::new();
        let mut vc = Vec::new();
        let r_1 = (0..(instance_bits + num_vars[0]))
            .map(|_| F::rand(rng))
            .collect::<Vec<_>>();

        for (i, layer) in circuit.layers.iter().enumerate() {
            let combination: &[(F, &[F])] = if i == 0 {
                &[(F::ONE, &r_1)]
            } else {
                let alpha = F::rand(rng);
                let beta = F::rand(rng);
                &[(alpha, &uc), (beta, &vc)]
            };

            // println!("\nproving layer {i}: {combination:?}");

            let w_i = DenseMultilinearExtension::from_evaluations_slice(
                instance_bits + num_vars[i + 1],
                &evaluations[i + 1],
            );

            let functions = layer
                .gates
                .iter()
                .flat_map(|gate_type| {
                    let result = gate_type.gate.to_gkr_combination(
                        &gate_type.sum_of_sparse_mle,
                        &w_i,
                        combination,
                    );
                    // TODO: remove
                    // assert_eq!(result.len(), 1);
                    // println!("gkr_combination");
                    // println!("  f1_g (dim {}): {:?}", result[0].f1_g.num_vars, result[0].f1_g.evaluations);
                    // println!("  f2 (dim {}): {:?}", result[0].f2.num_vars, result[0].f2.evaluations);
                    // println!("  f3 (dim {}): {:?}", result[0].f3.num_vars, result[0].f3.evaluations);

                    result
                })
                .collect();

            // println!("  layer (dim {}): {:?}", w_i.num_vars, w_i.evaluations);

            let round = GKRRound {
                functions,
                layer: w_i,
                instance_bits,
            };

            let (proof, rand) = GKRRoundSumcheck::prove(rng, &round);
            (uc, vc) = rand;
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
        // println!("\nVERIFIACTION");
        let instance_bits = ilog2_ceil(instances.len());
        let num_vars = circuit.layer_sizes();

        let (mut c, mut u, mut v) = Default::default();
        let (mut w_uc, mut w_vc) = Default::default();

        // TODO: this allocates too much
        let inputs = instances
            .iter()
            .flat_map(|instance| instance.inputs.clone())
            .collect::<Vec<_>>();
        let outputs = instances
            .iter()
            .flat_map(|instance| instance.outputs.clone())
            .collect::<Vec<_>>();

        // println!("INPUTS {inputs:?}");
        // println!("OUTPUTS {outputs:?}");

        for (i, layer) in circuit.layers.iter().enumerate() {
            // println!("verifying layer {i}");
            if i == 0 {
                let r_1 = (0..(instance_bits + num_vars[0]))
                    .map(|_| F::rand(rng))
                    .collect::<Vec<_>>();
                let w_0 = DenseMultilinearExtension::from_evaluations_slice(
                    instance_bits + circuit.output_bits,
                    &outputs,
                );
                let expected_sum = w_0.evaluate(&r_1);
                // println!("EXPECTED 0 {expected_sum:?}");

                let proof = &gkr_proof.rounds[i];
                let subclaim = GKRRoundSumcheck::verify(
                    rng,
                    instance_bits,
                    num_vars[i + 1],
                    proof,
                    expected_sum,
                )
                .unwrap();
                (w_uc, w_vc) = (subclaim.w_uc, subclaim.w_vc);

                let mut wiring_res = F::ZERO;
                for gate_type in &layer.gates {
                    let rcuv: Vec<_> = r_1
                        .iter()
                        .chain(subclaim.c.iter())
                        .chain(subclaim.u.iter())
                        .chain(subclaim.v.iter())
                        .copied()
                        .collect();

                    // println!("evaluate len {}", rcuv.len());
                    // TODO: don't rewire within the verifier!
                    let instance_wiring = gate_type.wiring.rewire_with_instances(
                        instance_bits,
                        num_vars[i],
                        num_vars[i + 1],
                    );
                    // println!(
                    //     "wiring mask {:b} then {:b}",
                    //     gate_type.wiring.mask(),
                    //     instance_wiring.mask()
                    // );

                    let wiring = instance_wiring.evaluate(&rcuv);
                    wiring_res += wiring * gate_type.gate.evaluate(w_uc, w_vc)
                }
                assert_eq!(wiring_res, proof.check_sum(subclaim.v.last().unwrap()));
                (c, u, v) = (subclaim.c, subclaim.u, subclaim.v);
            } else if i == circuit.layers.len() - 1 {
                let alpha = F::rand(rng);
                let beta = F::rand(rng);
                let expected_sum = alpha * w_uc + beta * w_vc;
                // println!("EXPECTED n-1 {expected_sum:?}");

                let proof = &gkr_proof.rounds[i];
                let subclaim = GKRRoundSumcheck::verify(
                    rng,
                    instance_bits,
                    num_vars[i + 1],
                    proof,
                    expected_sum,
                )
                .unwrap();

                // verify last round matches actual inputs
                let w_n = DenseMultilinearExtension::from_evaluations_slice(
                    instance_bits + circuit.input_bits,
                    &inputs,
                );

                let sub_uc: Vec<_> = subclaim
                    .u
                    .iter()
                    .chain(subclaim.c.iter())
                    .copied()
                    .collect();
                let sub_vc: Vec<_> = subclaim.v.iter().chain(&subclaim.c).copied().collect();

                // println!("vars {} {} {}", w_n.num_vars, sub_uc.len(), sub_vc.len());
                assert_eq!(w_n.evaluate(&sub_uc), subclaim.w_uc);
                assert_eq!(w_n.evaluate(&sub_vc), subclaim.w_vc);
            } else {
                let alpha = F::rand(rng);
                let beta = F::rand(rng);
                let expected_sum = alpha * w_uc + beta * w_vc;
                // println!("EXPECTED {i} {expected_sum:?}");

                let proof = &gkr_proof.rounds[i];
                let subclaim = GKRRoundSumcheck::verify(
                    rng,
                    instance_bits,
                    num_vars[i + 1],
                    proof,
                    expected_sum,
                )
                .unwrap();
                (w_uc, w_vc) = (subclaim.w_uc, subclaim.w_vc);

                let mut wiring_res = F::ZERO;
                for gate_type in &layer.gates {
                    let uuv: Vec<_> = u
                        .iter()
                        .chain(c.iter())
                        .chain(subclaim.c.iter())
                        .chain(subclaim.u.iter())
                        .chain(subclaim.v.iter())
                        .copied()
                        .collect();
                    let vuv: Vec<_> = v
                        .iter()
                        .chain(c.iter())
                        .chain(subclaim.c.iter())
                        .chain(subclaim.u.iter())
                        .chain(subclaim.v.iter())
                        .copied()
                        .collect();

                    // println!("evaluate len {} {}", uuv.len(), vuv.len());

                    // TODO: don't rewire within the verifier!
                    let wiring = gate_type.wiring.rewire_with_instances(
                        instance_bits,
                        num_vars[i],
                        num_vars[i + 1],
                    );
                    // println!(
                    //     "wiring mask {:b} then {:b}",
                    //     gate_type.wiring.mask(),
                    //     wiring.mask()
                    // );

                    let wiring_u = wiring.evaluate(&uuv);
                    let wiring_v = wiring.evaluate(&vuv);
                    wiring_res +=
                        (alpha * wiring_u + beta * wiring_v) * gate_type.gate.evaluate(w_uc, w_vc);
                }
                assert_eq!(wiring_res, proof.check_sum(subclaim.v.last().unwrap()));
                (c, u, v) = (subclaim.c, subclaim.u, subclaim.v);
            }
        }
    }
}

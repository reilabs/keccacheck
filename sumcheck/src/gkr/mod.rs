use core::marker::PhantomData;

use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, Polynomial};
pub use circuit::{Circuit, Layer, LayerGate};
use compiled::CompiledCircuit;
pub use gate::Gate;
use util::bits_to_u64;

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
        assert_eq!(instances.len(), 1, "currently only one instance supported");
        let instance = &instances[0];

        let evaluations = circuit.evaluate(instance);
        let num_vars = circuit.layer_sizes();

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
                        &gate_type.sum_of_sparse_mle,
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
        instances: &[Instance<F>],
        gkr_proof: &GKRProof<F>,
    ) {
        assert_eq!(instances.len(), 1, "currently only one instance supported");
        let instance = &instances[0];

        let num_vars = circuit.layer_sizes();

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
}

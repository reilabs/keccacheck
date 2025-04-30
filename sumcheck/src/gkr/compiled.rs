use ark_ff::Field;
use ark_poly::SparseMultilinearExtension;

use super::{circuit::Circuit, Gate};

#[derive(Debug)]
pub struct EvaluationGraph<F: Field> {
    pub layers: Vec<EvaluationLayer<F>>,
}

#[derive(Debug)]
pub struct EvaluationLayer<F: Field> {
    /// number of variables in the layer
    pub layer_bits: usize,
    /// all gate types in a layer    
    pub gates: Vec<EvaluationGate<F>>,
}

#[derive(Debug)]
pub struct EvaluationGate<F: Field> {
    pub gate: Gate,
    pub graph: Vec<Option<(usize, usize)>>,
    pub sum_of_sparse_mle: Vec<SparseMultilinearExtension<F>>,
}

impl<F: Field> EvaluationGraph<F> {
    pub fn from_circuit(circuit: &Circuit) -> Self {
        let mut input_bits = circuit.input_bits;

        let mut layers = Vec::with_capacity(circuit.layers.len());
        for layer in circuit.layers.iter().rev() {
            let layer_bits = layer.layer_bits;
            let gates = layer
                .gates
                .iter()
                .map(|gate| {
                    let wiring = &gate.wiring;
                    let dnf = wiring.to_dnf();
                    let graph = dnf.to_evaluation_graph(layer_bits, input_bits);
                    let sum_of_sparse_mle = dnf.to_sum_of_sparse_mle(layer_bits, input_bits);

                    EvaluationGate {
                        gate: gate.gate,
                        graph,
                        sum_of_sparse_mle,
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

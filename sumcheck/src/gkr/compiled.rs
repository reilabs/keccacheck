use ark_ff::Field;
use ark_poly::SparseMultilinearExtension;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::{circuit::Circuit, graph::EvaluationEdge, util::ilog2_ceil, Gate, Instance};

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompiledCircuit<F: Field> {
    pub input_bits: usize,
    pub layers: Vec<CompiledLayer<F>>,
}

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompiledLayer<F: Field> {
    /// number of variables in the layer
    pub layer_bits: usize,
    /// all gate types in a layer    
    pub gates: Vec<CompiledLayerGate<F>>,
}

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompiledLayerGate<F: Field> {
    pub gate: Gate,
    /// compiled for a single circuit instance
    pub graph: Vec<Option<EvaluationEdge>>,
    /// compiled for all instances
    pub sum_of_sparse_mle: Vec<SparseMultilinearExtension<F>>,
}

impl<F: Field> CompiledCircuit<F> {
    pub fn from_circuit(circuit: &Circuit) -> Self {
        Self::from_circuit_batched(circuit, 1)
    }

    pub fn from_circuit_batched(circuit: &Circuit, instances: usize) -> Self {
        let instance_bits = ilog2_ceil(instances);
        assert_eq!(instances, 1 << instance_bits, "must be a power of 2");

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
                    let sum_of_sparse_mle = dnf.to_sum_of_sparse_mle(layer_bits, input_bits, instance_bits);

                    CompiledLayerGate {
                        gate: gate.gate,
                        graph,
                        sum_of_sparse_mle,
                    }
                })
                .collect();

            input_bits = layer_bits;

            layers.push(CompiledLayer { layer_bits, gates });
        }
        layers.reverse();
        CompiledCircuit {
            input_bits: circuit.input_bits,
            layers,
        }
    }

    /// Takes a GKR circuit definition and returns value assignments
    /// in all intermediate layers
    pub fn layer_sizes(&self) -> Vec<usize> {
        let mut result = Vec::with_capacity(self.layers.len() + 1);
        for layer in &self.layers {
            result.push(layer.layer_bits);
        }
        result.push(self.input_bits);
        result
    }
    /// Takes a GKR circuit definition and returns value assignments
    /// in all intermediate layers
    pub fn evaluate(&self, instance: &Instance<F>) -> Vec<Vec<F>> {
        let mut result = Vec::with_capacity(self.layers.len() + 1);
        let mut previous_layer = &instance.inputs;
        result.push(previous_layer.clone());
        for layer in self.layers.iter().rev() {
            let output_vars = layer.layer_bits;
            let mut evaluations = vec![F::ZERO; 1 << output_vars];

            for gate in &layer.gates {
                for (out_gate, maybe_gates) in gate.graph.iter().enumerate() {
                    if let Some(EvaluationEdge { instance, left, right }) = maybe_gates {
                        assert_eq!(*instance, 0, "no instances when evaluating circuit");
                        let input_left = previous_layer[*left];
                        let input_right = previous_layer[*right];
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

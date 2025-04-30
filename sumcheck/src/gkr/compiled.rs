use super::{circuit::Circuit, Gate};

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

impl EvaluationGraph {
    pub fn from_circuit(circuit: &Circuit) -> EvaluationGraph {
        let mut input_bits = circuit.input_bits;

        let mut layers = Vec::with_capacity(circuit.layers.len());
        for layer in circuit.layers.iter().rev() {
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

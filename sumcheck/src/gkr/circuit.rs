use std::collections::HashMap;

use crate::gkr::predicate::{BasePredicate, PredicateExpr, SparseEvaluationPredicate};

use super::Gate;

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

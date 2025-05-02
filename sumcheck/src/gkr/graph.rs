use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use tracing::warn;

use crate::gkr::predicate::VarMaskIterator;

use super::predicate::BasePredicate;

#[derive(Copy, Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct EvaluationEdge {
    pub instance: usize,
    pub left: usize,
    pub right: usize,
}

pub fn to_evaluation_graph(
    predicate_product: &[BasePredicate],
    outputs: usize,
    inputs: usize,
    instance_bits: usize,
) -> Vec<Option<EvaluationEdge>> {
    fn set_vars(
        vars: usize,
        is_on: bool,
        constraints: &mut [Option<bool>],
        changes: &mut bool,
    ) -> bool {
        for var in VarMaskIterator(vars) {
            match constraints[var] {
                Some(x) if x == is_on => {}
                Some(_) => return false, //panic!("conflicting constraints on var {}", *var),
                None => {
                    constraints[var] = Some(is_on);
                    *changes = true;
                }
            }
        }

        true
    }
    let num_vars = outputs + 2 * inputs;

    (0..(1 << (outputs + instance_bits)))
        .map(|output| {
            let instance = output >> outputs;

            let mut output = output;
            let mut constraints = vec![None; num_vars];

            for i in 0..(outputs) {
                constraints[i] = Some(output % 2 == 1);
                output >>= 1;
            }

            let mut changes = true;
            while changes {
                changes = false;

                for predicate in predicate_product {
                    match predicate {
                        BasePredicate::Eq(eq) => {
                            if let Some(is_on) = eq.is_on {
                                if !set_vars(eq.var_mask, is_on, &mut constraints, &mut changes) {
                                    return None;
                                }
                            } else {
                                let constrained = VarMaskIterator(eq.var_mask)
                                    .filter_map(|x| constraints[x])
                                    .collect::<Vec<_>>();
                                if constrained.len() == 0 {
                                    continue;
                                }
                                if !all_equal(&constrained) {
                                    return None;
                                }
                                set_vars(
                                    eq.var_mask,
                                    constrained[0],
                                    &mut constraints,
                                    &mut changes,
                                );
                            }
                        }
                        BasePredicate::Sparse(sparse) => {
                            let output_vars = VarMaskIterator(sparse.var_mask)
                                .filter(|x| *x < outputs)
                                .collect::<Vec<_>>();
                            let input_vars = VarMaskIterator(sparse.var_mask)
                                .filter(|x| *x >= outputs)
                                .collect::<Vec<_>>();

                            if output_vars.iter().any(|x| constraints[*x].is_none()) {
                                continue;
                            }

                            let mut output = 0;
                            for (bit, var) in output_vars.into_iter().enumerate() {
                                if constraints[var] == Some(true) {
                                    output += 1 << bit;
                                }
                            }

                            let Some(mut input) = sparse.mle.get(&output).cloned() else {
                                continue;
                            };

                            for var in input_vars {
                                let is_on = input % 2 != 0;
                                input >>= 1;
                                match constraints[var] {
                                    Some(x) if x == is_on => {}
                                    Some(_) => return None, //panic!("conflicting constraints on var {}", *var),
                                    None => {
                                        constraints[var] = Some(is_on);
                                        changes = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let mut out = 0;
            let mut in1 = 0;
            let mut in2 = 0;

            for bit in 0..outputs {
                if constraints[bit] == Some(true) {
                    out += 1 << bit;
                }
            }

            if constraints.iter().any(|x| x.is_none()) {
                //debug_constraints(&constraints, outputs, inputs);
                warn!("underconstrained predicate for out {out:x?}, all variables should be set");
                return None;
            }

            for bit in 0..inputs {
                if constraints[bit + outputs] == Some(true) {
                    in1 += 1 << bit;
                }
                if constraints[bit + outputs + inputs] == Some(true) {
                    in2 += 1 << bit;
                }
            }

            Some(EvaluationEdge {
                instance,
                left: in1,
                right: in2,
            })
        })
        .collect()
}

fn all_equal<T: PartialEq>(slice: &[T]) -> bool {
    slice.windows(2).all(|w| w[0] == w[1])
}

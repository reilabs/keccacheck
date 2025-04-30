use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};

use crate::gkr_round_sumcheck::GKRFunction;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Supported gate types
pub enum Gate {
    /// Add gate
    Add,
    /// Mul gate
    Mul,
    /// Xor gate: xor(a, b) = a + b - 2ab
    Xor,
    /// Xor gate when the right input is already in the destination
    /// register: xor_left(a, b) = a - 2ab
    XorLeft,
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
            Gate::XorLeft => left - left * right * F::from(2),
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
            Gate::XorLeft => {
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
                                    // GKRFunction {
                                    //     f1_g: scale(&predicate, coeff),
                                    //     f2: const_one.clone(),
                                    //     f3: values.clone(),
                                    // },
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

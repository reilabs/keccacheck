use std::rc::Rc;

use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use tracing::info;

use crate::gkr_round_sumcheck::function::{GKRFunction, GKROperand};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
/// Supported gate types
/// NOTE: Remember to update deserialization cases at the bottom of this file
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
        values: Rc<DenseMultilinearExtension<F>>,
        combination: &[(F, &[F])],
    ) -> Vec<GKRFunction<F>> {
        info!(
            "gate {self:?} combination {} wiring len {}",
            combination.len(),
            wiring.len()
        );
        match self {
            Gate::Add => combination
                .into_iter()
                .flat_map(|(coeff, partial_point)| {
                    wiring
                        .fix_variables(partial_point)
                        .into_iter()
                        .flat_map(|predicate| {
                            vec![
                                GKRFunction {
                                    coefficient: *coeff,
                                    f1_g: predicate.clone(),
                                    f2: GKROperand::new_const(values.num_vars, F::ONE),
                                    f3: GKROperand::from_values(values.clone()),
                                },
                                GKRFunction {
                                    coefficient: *coeff,
                                    f1_g: predicate,
                                    f2: GKROperand::from_values(values.clone()),
                                    f3: GKROperand::new_const(values.num_vars, F::ONE),
                                },
                            ]
                        })
                        .collect::<Vec<_>>()
                })
                .collect(),
            Gate::Mul => combination
                .into_iter()
                .flat_map(|(coeff, partial_point)| {
                    wiring
                        .fix_variables(partial_point)
                        .into_iter()
                        .flat_map(|predicate| {
                            vec![GKRFunction {
                                coefficient: *coeff,
                                f1_g: predicate,
                                f2: GKROperand::from_values(values.clone()),
                                f3: GKROperand::from_values(values.clone()),
                            }]
                        })
                        .collect::<Vec<_>>()
                })
                .collect(),
            Gate::Xor => combination
                .into_iter()
                .flat_map(|(coeff, partial_point)| {
                    wiring
                        .fix_variables(partial_point)
                        .into_iter()
                        .flat_map(|predicate| {
                            vec![
                                GKRFunction {
                                    coefficient: *coeff,
                                    f1_g: predicate.clone(),
                                    f2: GKROperand::new_const(values.num_vars, F::ONE),
                                    f3: GKROperand::from_values(values.clone()),
                                },
                                GKRFunction {
                                    coefficient: *coeff,
                                    f1_g: predicate.clone(),
                                    f2: GKROperand::from_values(values.clone()),
                                    f3: GKROperand::new_const(values.num_vars, F::ONE),
                                },
                                GKRFunction {
                                    coefficient: *coeff * Into::<F>::into(-2),
                                    f1_g: predicate,
                                    f2: GKROperand::from_values(values.clone()),
                                    f3: GKROperand::from_values(values.clone()),
                                },
                            ]
                        })
                        .collect::<Vec<_>>()
                })
                .collect(),
            Gate::XorLeft => combination
                .into_iter()
                .flat_map(|(coeff, partial_point)| {
                    wiring
                        .fix_variables(partial_point)
                        .into_iter()
                        .flat_map(|predicate| {
                            vec![
                                GKRFunction {
                                    coefficient: *coeff,
                                    f1_g: predicate.clone(),
                                    f2: GKROperand::from_values(values.clone()),
                                    f3: GKROperand::new_const(values.num_vars, F::ONE),
                                },
                                GKRFunction {
                                    coefficient: *coeff * Into::<F>::into(-2),
                                    f1_g: predicate,
                                    f2: GKROperand::from_values(values.clone()),
                                    f3: GKROperand::from_values(values.clone()),
                                },
                            ]
                        })
                        .collect::<Vec<_>>()
                })
                .collect(),
            Gate::Left => combination
                .into_iter()
                .flat_map(|(coeff, partial_point)| {
                    wiring
                        .fix_variables(partial_point)
                        .into_iter()
                        .flat_map(|predicate| {
                            vec![GKRFunction {
                                coefficient: *coeff,
                                f1_g: predicate,
                                f2: GKROperand::from_values(values.clone()),
                                f3: GKROperand::new_const(values.num_vars, F::ONE),
                            }]
                        })
                        .collect::<Vec<_>>()
                })
                .collect(),
            Gate::Null => {
                vec![]
            }
        }
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

// SERIALIZATION

impl Valid for Gate {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for Gate {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let value = *self as u8;
        value.serialize_with_mode(writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let value = *self as u8;
        value.serialized_size(compress)
    }
}

impl CanonicalDeserialize for Gate {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let value = u8::deserialize_with_mode(reader, compress, validate)?;
        match value {
            0 => Ok(Self::Add),
            1 => Ok(Self::Mul),
            2 => Ok(Self::Xor),
            3 => Ok(Self::XorLeft),
            4 => Ok(Self::Left),
            6 => Ok(Self::Null),
            _ => Err(ark_serialize::SerializationError::InvalidData),
        }
    }
}

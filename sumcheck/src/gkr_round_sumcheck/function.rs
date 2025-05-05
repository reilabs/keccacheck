use core::ops::Index;
use std::rc::Rc;

use ark_ff::Field;
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, Polynomial, SparseMultilinearExtension,
};

#[derive(Debug)]
/// GKR function in a form of f1(r, u, v) * f2(u) * f3(v) where r is const.
pub struct GKRFunction<F: Field> {
    /// coefficient
    pub coefficient: F,
    /// sparse wiring polynomial evaluated at random output r
    pub f1_g: SparseMultilinearExtension<F>,
    /// gate evaluation, left operand
    pub f2: GKROperand<F>,
    /// gate evaluation, right operand
    pub f3: GKROperand<F>,
}

#[derive(Debug)]
/// A sum of multiple GKR functions
pub struct GKRRound<F: Field> {
    /// List of functions under sum
    pub functions: Vec<GKRFunction<F>>,
    /// Layer evaluations
    pub layer: GKROperand<F>,
    /// Number of vars used to describe the instance number
    pub instance_bits: usize,
}

impl<F: Field> GKRRound<F> {
    /// Number of variables in each GKR function
    pub fn num_variables(&self, phase: usize) -> usize {
        match phase {
            0 => self.functions[0].f2.num_vars() - self.instance_bits,
            1 => self.instance_bits,
            2 => self.functions[0].f3.num_vars() - self.instance_bits,
            _ => panic!("only functions in the form of f1(...)f2(...)f3(...) supported"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum GKROperand<F: Field> {
    Const {
        num_vars: usize,
        val: F,
    },
    Values {
        mle: Rc<DenseMultilinearExtension<F>>,
    },
}

impl<F: Field> GKROperand<F> {
    pub fn new_const(num_vars: usize, val: F) -> Self {
        Self::Const { num_vars, val }
    }

    pub fn from_values(mle: Rc<DenseMultilinearExtension<F>>) -> Self {
        Self::Values { mle }
    }

    pub fn num_vars(&self) -> usize {
        match self {
            GKROperand::Const { num_vars, .. } => *num_vars,
            GKROperand::Values { mle, .. } => mle.num_vars,
        }
    }

    pub fn fix_variables(&self, partial_point: &[F]) -> GKROperand<F> {
        match self {
            GKROperand::Const { num_vars, val: one } => GKROperand::Const {
                num_vars: num_vars - partial_point.len(),
                val: *one,
            },
            GKROperand::Values { mle } => {
                //println!("fixing {id} on {partial_point:?}\n");
                GKROperand::Values {
                    mle: Rc::new(mle.fix_variables(partial_point)),
                }
            }
        }
    }

    pub fn evaluate(&self, point: &Vec<F>) -> F {
        match self {
            GKROperand::Const { val: one, .. } => *one,
            GKROperand::Values { mle } => {
                //println!("evaluating {id} on {point:?}\n");
                mle.evaluate(point)
            }
        }
    }

    pub fn add_empty_variables(&self, new_vars: usize) -> GKROperand<F> {
        match self {
            GKROperand::Const {
                num_vars, val: one, ..
            } => GKROperand::Const {
                num_vars: num_vars + new_vars,
                val: *one,
            },
            GKROperand::Values { mle } => {
                let dim: usize = mle.num_vars + new_vars;
                let evaluations = (0..(1 << dim))
                    .map(|out| {
                        let k = out & (1 << mle.num_vars) - 1;
                        mle.evaluations[k]
                    })
                    .collect();
                GKROperand::Values {
                    mle: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                        dim,
                        evaluations,
                    )),
                }
            }
        }
    }

    pub fn shift_variables_to_end(&self, b_dim: usize) -> GKROperand<F> {
        match self {
            GKROperand::Const {
                num_vars, val: one, ..
            } => GKROperand::Const {
                num_vars: *num_vars,
                val: *one,
            },
            GKROperand::Values { mle } => {
                let dim = mle.num_vars;
                let c_dim = dim - b_dim;
                let evaluations = (0..(1 << dim))
                    .map(|cb| {
                        let c = cb & ((1 << c_dim) - 1);
                        let b = cb >> c_dim;
                        mle.evaluations[(c << b_dim) + b]
                    })
                    .collect();
                GKROperand::Values {
                    mle: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                        dim,
                        evaluations,
                    )),
                }
            }
        }
    }
}

impl<F: Field> Index<usize> for GKROperand<F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            GKROperand::Const { val: one, .. } => one,
            GKROperand::Values { mle, .. } => &mle[index],
        }
    }
}

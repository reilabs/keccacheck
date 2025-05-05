use std::rc::Rc;

use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, SparseMultilinearExtension};

#[derive(Debug)]
/// GKR function in a form of f1(r, u, v) * f2(u) * f3(v) where r is const.
pub struct GKRFunction<F: Field> {
    /// coefficient
    pub coefficient: F,
    /// sparse wiring polynomial evaluated at random output r
    pub f1_g: SparseMultilinearExtension<F>,
    /// gate evaluation, left operand
    pub f2: Rc<DenseMultilinearExtension<F>>,
    /// gate evaluation, right operand
    pub f3: Rc<DenseMultilinearExtension<F>>,
}

#[derive(Debug)]
/// A sum of multiple GKR functions
pub struct GKRRound<F: Field> {
    /// List of functions under sum
    pub functions: Vec<GKRFunction<F>>,
    /// Layer evaluations
    pub layer: Rc<DenseMultilinearExtension<F>>,
    /// Number of vars used to describe the instance number
    pub instance_bits: usize,
}

impl<F: Field> GKRRound<F> {
    /// Number of variables in each GKR function
    pub fn num_variables(&self, phase: usize) -> usize {
        match phase {
            0 => self.functions[0].f2.num_vars - self.instance_bits,
            1 => self.instance_bits,
            2 => self.functions[0].f3.num_vars - self.instance_bits,
            _ => panic!("only functions in the form of f1(...)f2(...)f3(...) supported"),
        }
    }
}

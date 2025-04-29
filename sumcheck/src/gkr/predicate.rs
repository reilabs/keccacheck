use core::{
    ops::{Add, AddAssign, Mul, MulAssign, RangeInclusive},
    usize,
};
use std::collections::HashMap;

use ark_ff::Field;
use ark_poly::{Polynomial, SparseMultilinearExtension};
use tracing::warn;

struct VarMaskIterator(usize);

impl Iterator for VarMaskIterator {
    type Item = usize;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let zeros = self.0.trailing_zeros();

        if zeros == usize::BITS {
            None
        } else {
            let bit_position = zeros;
            let mask = 1 << bit_position;
            self.0 ^= mask;
            Some(bit_position as usize)
        }
    }
}

#[derive(Clone, Debug)]
/// a predicate that the verifier will evaluate by interpolation
pub struct SparseEvaluationPredicate {
    pub var_mask: usize,
    pub out_len: usize,
    pub mle: HashMap<usize, usize>,
}

impl SparseEvaluationPredicate {
    pub fn evaluate<F: Field>(&self, point: &[F]) -> F {
        let evaluations = self
            .mle
            .iter()
            .map(|(out, inp)| (out + (inp << self.out_len), F::ONE))
            .collect::<Vec<_>>();

        let point = VarMaskIterator(self.var_mask)
            .map(|var| point[var])
            .collect::<Vec<_>>();

        SparseMultilinearExtension::from_evaluations(
            self.var_mask.count_ones() as usize,
            &evaluations,
        )
        .evaluate(&point)
    }
}

#[derive(Clone, Debug)]
pub struct EqPredicate {
    pub var_mask: usize,
    pub is_on: Option<bool>,
}

impl EqPredicate {
    pub fn evaluate<F: Field>(&self, point: &[F]) -> F {
        let var_values = VarMaskIterator(self.var_mask)
            .map(|var| point[var])
            .collect::<Vec<_>>();
        let neg_values = var_values.iter().map(|v| F::ONE - v).collect::<Vec<_>>();
        if let Some(is_on) = self.is_on {
            if is_on {
                var_values.iter().fold(F::ONE, |acc, e| acc * *e)
            } else {
                neg_values.iter().fold(F::ONE, |acc, e| acc * *e)
            }
        } else {
            let a = var_values.iter().fold(F::ONE, |acc, e| acc * *e);
            let b = neg_values.iter().fold(F::ONE, |acc, e| acc * *e);
            a + b
        }
    }
}

pub fn eq_const(var: u8, on: usize) -> PredicateExpr {
    PredicateExpr::Base(BasePredicate::Eq(EqPredicate {
        var_mask: 1 << var,
        is_on: Some(on == 1),
    }))
}

pub fn eq(vars: &[u8]) -> PredicateExpr {
    let mut var_mask = 0;
    for var in vars {
        let var = 1 << var;
        assert_eq!(var_mask & var, 0);
        var_mask |= var;
    }
    PredicateExpr::Base(BasePredicate::Eq(EqPredicate {
        var_mask,
        is_on: None,
    }))
}

pub fn eq_vec(vars: &[RangeInclusive<u8>]) -> PredicateExpr {
    let count = vars[0].len();
    let vars = vars
        .into_iter()
        .map(|range| range.clone().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut current_var: Vec<u8> = vars.iter().map(|x| x[0]).collect();
    let mut predicate = eq(&current_var);
    for i in 1..count {
        current_var = vars.iter().map(|x| x[i]).collect();
        predicate *= eq(&current_var)
    }
    predicate
}

type VarRotation = (RangeInclusive<u8>, usize, usize);

pub fn rot(out: VarRotation, in1: VarRotation, in2: VarRotation) -> PredicateExpr {
    let len = out.0.len();
    assert_eq!(in1.0.len(), len);
    assert_eq!(in2.0.len(), len);

    let (in1_vars, in1_add, in1_mod) = in1;
    let (in2_vars, in2_add, in2_mod) = in2;

    let vars = out.0.chain(in1_vars).chain(in2_vars).collect::<Vec<_>>();
    let mut var_mask = 0;
    for var in vars {
        let var = 1 << var;
        assert_eq!(var_mask & var, 0);
        var_mask |= var;
    }

    let evaluations = (0..(1 << len))
        .filter_map(|out_label| {
            let in1_label = (out_label + in1_add) % in1_mod;
            let in2_label = (out_label + in2_add) % in2_mod;
            let in_label = (in2_label << len) + in1_label;
            Some((out_label, in_label))
        })
        .collect::<Vec<_>>();

    PredicateExpr::Base(BasePredicate::Sparse(SparseEvaluationPredicate {
        var_mask,
        out_len: len,
        mle: evaluations.into_iter().collect(),
    }))
}

#[derive(Clone, Debug)]
pub enum BasePredicate {
    Eq(EqPredicate),
    Sparse(SparseEvaluationPredicate),
}

impl BasePredicate {
    pub fn evaluate<F: Field>(&self, point: &[F]) -> F {
        match self {
            BasePredicate::Eq(eq) => eq.evaluate(point),
            BasePredicate::Sparse(mle) => mle.evaluate(point),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PredicateDnf(Vec<Vec<BasePredicate>>);

impl PredicateDnf {
    pub fn to_sum_of_sparse_mle<F: Field>(
        &self,
        outputs: usize,
        inputs: usize,
    ) -> Vec<SparseMultilinearExtension<F>> {
        // TODO this is OK for now, we have only single product
        assert_eq!(self.0.len(), 1);
        let evaluations = self
            .to_evaluation_graph(outputs, inputs)
            .into_iter()
            .enumerate()
            .filter_map(|(out, pred)| {
                let Some((in1, in2)) = pred else {
                    return None;
                };
                Some((out + (in1 << outputs) + (in2 << (outputs + inputs)), F::ONE))
            })
            .collect::<Vec<_>>();

        vec![SparseMultilinearExtension::from_evaluations(
            outputs + 2 * inputs,
            &evaluations,
        )]
    }

    pub fn to_evaluation_graph(
        &self,
        outputs: usize,
        inputs: usize,
    ) -> Vec<Option<(usize, usize)>> {
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

        assert_eq!(self.0.len(), 1, "only one product supported");
        let predicate_product = &self.0[0];

        (0..(1 << outputs))
            .map(|output| {
                let mut output = output;
                let mut constraints = vec![None; num_vars];

                for i in 0..outputs {
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
                                    if !set_vars(eq.var_mask, is_on, &mut constraints, &mut changes)
                                    {
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
                    warn!(
                        "underconstrained predicate for out {out:x?}, all variables should be set"
                    );
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

                Some((in1, in2))
            })
            .collect()
    }
}

#[allow(variant_size_differences)]
#[derive(Clone, Debug)]
pub enum PredicateExpr {
    Mul(Box<PredicateExpr>, Box<PredicateExpr>),
    Add(Box<PredicateExpr>, Box<PredicateExpr>),
    Base(BasePredicate),
}

impl PredicateExpr {
    pub fn to_dnf(&self) -> PredicateDnf {
        match self {
            PredicateExpr::Mul(left, right) => {
                let mut left = left.to_dnf().0;
                let right = right.to_dnf().0;
                assert_eq!(left.len(), 1);
                assert_eq!(right.len(), 1);
                left[0].extend_from_slice(&right[0]);
                PredicateDnf(left)
            }
            PredicateExpr::Add(_l, _r) => todo!(),
            PredicateExpr::Base(base) => PredicateDnf(vec![vec![base.clone()]]),
        }
    }

    pub fn evaluate<F: Field>(&self, point: &[F]) -> F {
        match self {
            PredicateExpr::Mul(left, right) => left.evaluate(point) * right.evaluate(point),
            PredicateExpr::Add(left, right) => left.evaluate(point) * right.evaluate(point),
            PredicateExpr::Base(predicate) => predicate.evaluate(point),
        }
    }
}

impl Add for PredicateExpr {
    type Output = PredicateExpr;

    fn add(self, rhs: Self) -> Self::Output {
        PredicateExpr::Add(Box::new(self), Box::new(rhs))
    }
}

impl AddAssign for PredicateExpr {
    fn add_assign(&mut self, rhs: Self) {
        *self = PredicateExpr::Add(Box::new(self.clone()), Box::new(rhs))
    }
}

impl Mul for PredicateExpr {
    type Output = PredicateExpr;

    fn mul(self, rhs: Self) -> Self::Output {
        PredicateExpr::Mul(Box::new(self), Box::new(rhs))
    }
}

impl MulAssign for PredicateExpr {
    fn mul_assign(&mut self, rhs: Self) {
        *self = PredicateExpr::Mul(Box::new(self.clone()), Box::new(rhs))
    }
}

fn all_equal<T: PartialEq>(slice: &[T]) -> bool {
    slice.windows(2).all(|w| w[0] == w[1])
}

#[allow(unused)]
fn debug_constraints(constraints: &[Option<bool>], outputs: usize, inputs: usize) {
    print!("out: ");
    constraints[0..outputs].iter().for_each(|x| match x {
        Some(true) => print!("1"),
        Some(false) => print!("0"),
        None => print!("_"),
    });
    println!();
    print!("in1: ");
    constraints[outputs..(outputs + inputs)]
        .iter()
        .for_each(|x| match x {
            Some(true) => print!("1"),
            Some(false) => print!("0"),
            None => print!("_"),
        });
    println!();
    print!("in2: ");
    constraints[(outputs + inputs)..(outputs + inputs + inputs)]
        .iter()
        .for_each(|x| match x {
            Some(true) => print!("1"),
            Some(false) => print!("0"),
            None => print!("_"),
        });
    println!("");
    println!("");
}

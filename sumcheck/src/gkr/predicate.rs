use core::{
    ops::{Add, AddAssign, Mul, MulAssign, RangeInclusive},
    usize,
};
use std::collections::HashMap;

use ark_ff::Field;
use ark_poly::{Polynomial, SparseMultilinearExtension};

use super::graph::to_evaluation_graph;

pub struct VarMaskIterator(pub usize);

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

// TODO: maaaaaybe, just maybe, rethink the naming of these predicates :D
pub fn eq_c(vars: &[u8], c: usize) -> PredicateExpr {
    let mut var_mask = 0;
    for var in vars {
        let var = 1 << var;
        assert_eq!(var_mask & var, 0);
        var_mask |= var;
    }
    PredicateExpr::Base(BasePredicate::Eq(EqPredicate {
        var_mask,
        is_on: Some(c == 1),
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

pub fn cmp_leq(vars: &[RangeInclusive<u8>], consts: &[usize]) -> PredicateExpr {
    for range in vars {
        assert_eq!(
            range.len(),
            consts.len(),
            "all vectors must be of equal length"
        );
    }

    let vars = vars
        .iter()
        .map(|x| x.clone().collect::<Vec<_>>())
        .collect::<Vec<_>>();

    // e.g. <= 1 0 1
    // if top bit 0, done
    // if top bit 1, continue recursively

    // e.g. <= 0 1 1
    // top bit must be zero. NO MORE CHECKS ARE NEEDED
    // if second bit 0, done
    // if second bit 1, continue recursively

    // e.g. <= 1 0 1 0
    // if top bit 0, done
    // if top bit 1, continue recursively
    // next bit must be zero
    // if next bit 0, done
    // if next bit 1, the next must be zero

    // e.g. <= 0 1 1 0 0 1
    // top bit must be zero
    // if second bit 0, done, check equality
    // if second bit 1, continue recursively

    let mut checked_true: Vec<PredicateExpr> = Vec::new();
    let mut current: Option<PredicateExpr> = None;

    // loops from the most significant bit (the last one first)
    // TODO: trailing ones don't need to add new predicates
    for (index, &c) in consts.iter().enumerate().rev() {
        assert!(c == 0 || c == 1);
        let vars_at_index = vars.iter().map(|v| v[index]).collect::<Vec<_>>();

        for already_true in checked_true.iter_mut() {
            *already_true *= eq(&vars_at_index);
        }

        if c == 0 {
            current = mul_optional(current, eq_c(&vars_at_index, 0));
        } else if c == 1 {
            checked_true.push(mul_optional(current.clone(), eq_c(&vars_at_index, 0)).unwrap());
            current = mul_optional(current, eq_c(&vars_at_index, 1));
        }
    }

    if let Some(current) = current {
        checked_true.push(current);
    }

    let mut iter = checked_true.into_iter();
    let mut result = iter.next().unwrap();
    while let Some(predicate) = iter.next() {
        result += predicate;
    }

    println!("cmp result {result:?}");

    result
}

fn mul_optional(current: Option<PredicateExpr>, predicate: PredicateExpr) -> Option<PredicateExpr> {
    current.map(|x| x * predicate.clone()).or(Some(predicate))
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

    pub fn mask(&self) -> usize {
        match self {
            BasePredicate::Eq(eq) => eq.var_mask,
            BasePredicate::Sparse(sparse) => sparse.var_mask,
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
        self.0
            .iter()
            .map(|product| {
                let evaluations = to_evaluation_graph(product, outputs, inputs)
                    .into_iter()
                    .enumerate()
                    .filter_map(|(out, pred)| {
                        let Some((in1, in2)) = pred else {
                            return None;
                        };
                        Some((out + (in1 << outputs) + (in2 << (outputs + inputs)), F::ONE))
                    })
                    .collect::<Vec<_>>();

                SparseMultilinearExtension::from_evaluations(outputs + 2 * inputs, &evaluations)
            })
            .collect()
    }

    pub fn to_evaluation_graph(
        &self,
        outputs: usize,
        inputs: usize,
    ) -> Vec<Option<(usize, usize)>> {
        let mut result = vec![None; 1 << outputs];
        for product in &self.0 {
            let addend = to_evaluation_graph(product, outputs, inputs);
            for (i, val) in addend.iter().enumerate() {
                if result[i].is_some() && val.is_some() {
                    panic!(
                        "addends not exclusive for out {}: {:?} and {:?}",
                        i,
                        result[i].unwrap(),
                        val.unwrap()
                    );
                }
                if result[i].is_none() {
                    result[i] = *val;
                }
            }
        }
        result
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
                let mut result = vec![];
                let left = left.to_dnf().0;
                let right = right.to_dnf().0;
                for left_vec in &left {
                    for right_vec in &right {
                        let mut concat = left_vec.clone();
                        concat.extend(right_vec.iter().cloned());
                        result.push(concat);
                    }
                }
                PredicateDnf(result)
            }
            PredicateExpr::Add(left, right) => {
                let mut left = left.to_dnf().0;
                let right = right.to_dnf().0;
                left.extend(right);
                PredicateDnf(left)
            }
            PredicateExpr::Base(base) => PredicateDnf(vec![vec![base.clone()]]),
        }
    }

    pub fn evaluate<F: Field>(&self, point: &[F]) -> F {
        match self {
            PredicateExpr::Mul(left, right) => left.evaluate(point) * right.evaluate(point),
            PredicateExpr::Add(left, right) => left.evaluate(point) + right.evaluate(point),
            PredicateExpr::Base(predicate) => predicate.evaluate(point),
        }
    }

    pub fn mask(&self) -> usize {
        match self {
            PredicateExpr::Mul(left, right) => left.mask() | right.mask(),
            PredicateExpr::Add(left, right) => left.mask() | right.mask(),
            PredicateExpr::Base(base_predicate) => base_predicate.mask(),
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
        let lhs_mask = self.mask();
        let rhs_mask = rhs.mask();
        if lhs_mask & rhs_mask != 0 {
            panic!(
                "no longer multilinear. conflicting mask {:b}",
                lhs_mask & rhs_mask
            );
        }

        PredicateExpr::Mul(Box::new(self), Box::new(rhs))
    }
}

impl MulAssign for PredicateExpr {
    fn mul_assign(&mut self, rhs: Self) {
        let lhs_mask = self.mask();
        let rhs_mask = rhs.mask();
        if lhs_mask & rhs_mask != 0 {
            panic!(
                "no longer multilinear. conflicting mask {:b}",
                lhs_mask & rhs_mask
            );
        }

        *self = PredicateExpr::Mul(Box::new(self.clone()), Box::new(rhs))
    }
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

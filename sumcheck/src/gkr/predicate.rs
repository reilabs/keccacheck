use core::{
    ops::{Mul, MulAssign, RangeInclusive},
    usize,
};
use std::collections::{HashMap, HashSet};

use ark_ff::Field;
use ark_poly::{Polynomial, SparseMultilinearExtension};
use tracing::warn;

#[derive(Clone, Debug)]
/// a predicate that the verifier will evaluate by interpolation
pub struct SparseEvaluationPredicate {
    pub vars: Vec<u8>,
    pub mle: HashMap<usize, usize>,
}

impl SparseEvaluationPredicate {
    pub fn evaluate<F: Field>(&self, point: &[F], outputs: usize, inputs: usize) -> F {
        let evaluations = self
            .mle
            .iter()
            .map(|(out, inp)| (out + (inp << outputs), F::ONE))
            .collect::<Vec<_>>();

        let point = self
            .vars
            .iter()
            .map(|var| point[*var as usize])
            .collect::<Vec<_>>();

        SparseMultilinearExtension::from_evaluations(outputs + 2 * inputs, &evaluations)
            .evaluate(&point)
    }
}

#[derive(Clone, Debug)]
pub struct EqPredicate {
    pub vars: Vec<u8>,
    pub is_on: Option<bool>,
}

impl EqPredicate {
    pub fn evaluate<F: Field>(&self, point: &[F]) -> F {
        let var_values = self
            .vars
            .iter()
            .map(|var| point[*var as usize])
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

#[derive(Clone, Debug)]
// a product of predicates
pub struct Predicate {
    pub eq_predicates: Vec<EqPredicate>,
    pub sparse_predicates: Vec<SparseEvaluationPredicate>,
}

impl Predicate {
    pub fn evaluate<F: Field>(&self, point: &[F], outputs: usize, inputs: usize) -> F {
        let mut result = F::ONE;
        for pred in &self.eq_predicates {
            result *= pred.evaluate(point);
            if result.is_zero() {
                return result;
            }
        }
        for pred in &self.sparse_predicates {
            //todo!();
            result *= pred.evaluate(point, outputs, inputs);
            if result.is_zero() {
                return result;
            }
        }

        result
    }

    pub fn evaluations(&self, outputs: usize, inputs: usize) -> Vec<(usize, usize, usize)> {
        fn set_vars(
            vars: &[u8],
            is_on: bool,
            constraints: &mut [Option<bool>],
            changes: &mut bool,
        ) -> bool {
            for var in vars {
                match constraints[*var as usize] {
                    Some(x) if x == is_on => {}
                    Some(_) => return false, //panic!("conflicting constraints on var {}", *var),
                    None => {
                        constraints[*var as usize] = Some(is_on);
                        *changes = true;
                    }
                }
            }

            true
        }
        let num_vars = outputs + 2 * inputs;

        let evaluations: Vec<(usize, usize, usize)> = (0..(1 << outputs))
            .filter_map(|output| {
                let mut output = output;
                let mut constraints = vec![None; num_vars];

                for i in 0..outputs {
                    constraints[i] = Some(output % 2 == 1);
                    output >>= 1;
                }

                let mut changes = true;
                while changes {
                    changes = false;

                    for eq in &self.eq_predicates {
                        if let Some(is_on) = eq.is_on {
                            if !set_vars(&eq.vars, is_on, &mut constraints, &mut changes) {
                                return None;
                            }
                        } else {
                            let constrained = eq
                                .vars
                                .iter()
                                .filter_map(|x| constraints[*x as usize])
                                .collect::<Vec<_>>();
                            if constrained.len() == 0 {
                                continue;
                            }
                            if !all_equal(&constrained) {
                                return None;
                            }
                            set_vars(&eq.vars, constrained[0], &mut constraints, &mut changes);
                        }
                    }

                    for sparse in &self.sparse_predicates {
                        let output_vars = sparse
                            .vars
                            .iter()
                            .filter(|x| (**x as usize) < outputs)
                            .collect::<Vec<_>>();
                        let input_vars = sparse
                            .vars
                            .iter()
                            .filter(|x| (**x as usize) >= outputs)
                            .collect::<Vec<_>>();

                        if output_vars
                            .iter()
                            .any(|x| constraints[**x as usize].is_none())
                        {
                            continue;
                        }

                        let mut output = 0;
                        for (bit, var) in output_vars.into_iter().enumerate() {
                            if constraints[*var as usize] == Some(true) {
                                output += 1 << bit;
                            }
                        }

                        let Some(mut input) = sparse.mle.get(&output).cloned() else {
                            continue;
                        };

                        for var in input_vars {
                            let is_on = input % 2 != 0;
                            input >>= 1;
                            match constraints[*var as usize] {
                                Some(x) if x == is_on => {}
                                Some(_) => return None, //panic!("conflicting constraints on var {}", *var),
                                None => {
                                    constraints[*var as usize] = Some(is_on);
                                    changes = true;
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

                Some((out, in1, in2))
            })
            .collect();

        evaluations
    }

    fn var_labels(&self) -> HashSet<u8> {
        let mut result = HashSet::new();
        for predicate in &self.eq_predicates {
            for var in &predicate.vars {
                result.insert(*var);
            }
        }
        for predicate in &self.sparse_predicates {
            for var in &predicate.vars {
                result.insert(*var);
            }
        }
        result
    }
}

pub fn eq_const(var: u8, on: usize) -> Predicate {
    Predicate {
        eq_predicates: vec![EqPredicate {
            vars: vec![var],
            is_on: Some(on == 1),
        }],
        sparse_predicates: Default::default(),
    }
}

pub fn eq(vars: &[u8]) -> Predicate {
    Predicate {
        eq_predicates: vec![EqPredicate {
            vars: vars.to_vec(),
            is_on: None,
        }],
        sparse_predicates: Default::default(),
    }
}

pub fn eq_vec(vars: &[RangeInclusive<u8>]) -> Predicate {
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

pub fn rot<const N: u8>(out: RangeInclusive<u8>, input: RangeInclusive<u8>) -> Predicate {
    let len = out.len();
    assert_eq!(input.len(), len);

    let vars = out.chain(input).collect::<Vec<_>>();
    println!("rot inner vars {vars:?}");

    let evaluations = (0..(1 << len))
        .filter_map(|out_label| {
            let in_label = (out_label + N as usize) % (1 << len);
            Some((out_label, in_label))
        })
        .collect::<Vec<_>>();

    println!("rot evaluations {evaluations:x?}");

    Predicate {
        eq_predicates: Default::default(),
        sparse_predicates: vec![SparseEvaluationPredicate {
            vars,
            mle: evaluations.into_iter().collect(),
        }],
    }
}

impl MulAssign for Predicate {
    fn mul_assign(&mut self, mut rhs: Self) {
        let lft_vars = self.var_labels();
        let rhs_vars = rhs.var_labels();
        let intersection = lft_vars.intersection(&rhs_vars).collect::<Vec<_>>();
        if intersection.len() > 0 {
            panic!("predicate no longer linear in {:?}", intersection);
        }
        self.eq_predicates.append(&mut rhs.eq_predicates);
        self.sparse_predicates.append(&mut rhs.sparse_predicates);
    }
}

impl Mul for Predicate {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut lft = self.clone();
        lft *= rhs;
        lft
    }
}

#[derive(Debug)]
/// a chain of predicates
pub struct PredicateSum {
    pub predicates: Vec<Predicate>,
    pub inputs: usize,
    pub outputs: usize,
}

impl PredicateSum {
    // pub fn fix_variables<F: Field>(
    //     &self,
    //     partial_point: &[F],
    // ) -> Vec<SparseMultilinearExtension<F>> {
    //     self.predicates
    //         .iter()
    //         .map(|predicate| predicate.fix_variables(partial_point, self.outputs, self.inputs))
    //         .collect()
    // }

    pub fn evaluate<F: Field>(&self, point: &Vec<F>) -> F {
        self.predicates
            .iter()
            .map(|predicate| predicate.evaluate(point, self.outputs, self.inputs))
            .fold(F::ZERO, |acc, e| acc + e)
    }

    pub fn evaluations(&self) -> Vec<(usize, usize, usize)> {
        self.predicates
            .iter()
            .flat_map(|pred| pred.evaluations(self.outputs, self.inputs))
            .collect()
    }

    pub fn sparse_mle<F: Field>(&self) -> Vec<SparseMultilinearExtension<F>> {
        self.predicates
            .iter()
            .map(|pred| {
                let evals = pred.evaluations(self.outputs, self.inputs);
                let evaluations = evals
                    .into_iter()
                    .map(|(out, in1, in2)| {
                        (
                            out + (in1 << self.outputs) + (in2 << (self.outputs + self.inputs)),
                            F::ONE,
                        )
                    })
                    .collect::<Vec<_>>();
                //println!("building mle with {} vars: {evaluations:?}", self.num_vars());
                SparseMultilinearExtension::from_evaluations(self.num_vars(), &evaluations)
            })
            .collect()
    }

    pub fn num_vars(&self) -> usize {
        self.outputs + 2 * self.inputs
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

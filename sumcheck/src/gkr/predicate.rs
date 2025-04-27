use std::collections::BTreeMap;

use ark_ff::Field;
use ark_poly::{MultilinearExtension, SparseMultilinearExtension};

#[derive(Copy, Clone, Debug)]
pub struct VariableMask(pub usize);

#[derive(Clone)]
/// a predicate that the verifier will evaluate by interpolation
pub struct SparseEvaluationPredicate<F: Field> {
    pub var_mask: VariableMask,
    pub mle: SparseMultilinearExtension<F>,
}

#[derive(Clone, Debug)]
pub struct EqPredicate<F: Field> {
    pub var_masks: Vec<VariableMask>,
    pub consts: Option<Vec<F>>,
}

impl<F: Field> EqPredicate<F> {
    // TODO: this is crazy inefficient
    pub fn fix_variables(&self, partial_point: &[F]) -> SparseMultilinearExtension<F> {
        if let Some(_consts) = &self.consts {
            todo!();
        }
        let mut mask: usize = 0;
        let popcount = self.var_masks[0].0.count_ones() as usize;

        if partial_point.len() == self.var_masks.len() * popcount {
            // TODO: this is a closed form evaluation in the verifier, return early
        }

        for vars in &self.var_masks {
            assert_eq!(mask & vars.0, 0);
            assert_eq!(popcount, vars.0.count_ones() as usize);
            mask |= vars.0;
        }

        let mut evaluations = Vec::with_capacity(1 << popcount);
        for i in 0..(1 << popcount) {
            let mut index = 0;
            let mut masks = self.var_masks.iter().map(|x| x.0).collect::<Vec<_>>();
            for bit in 0..popcount {
                let is_on = i & (1 << bit);
                for var in masks.iter_mut() {
                    index += is_on * (1 << var.trailing_zeros());
                }
            }
            evaluations.push((index, F::ONE));
        }

        println!(
            "EqPredicate popcount {} partial count {} evaluations len {}",
            popcount,
            partial_point.len(),
            evaluations.len()
        );

        SparseMultilinearExtension::from_evaluations(mask.count_ones() as usize, &evaluations)
            .fix_variables(partial_point)
    }
}

#[derive(Clone)]
/// a single predicate type
pub enum PredicateType<F: Field> {
    /// a predicate that the verifier will evaluate by interpolation
    SparseEvaluation(SparseEvaluationPredicate<F>),
    /// eq(var_mask_1, var_mask_2, ... var_mask_n, consts)
    Eq(EqPredicate<F>),
}

// a product of predicates
pub struct Predicate<F: Field> {
    pub predicates: Vec<PredicateType<F>>,
}

impl<F: Field> Predicate<F> {
    pub fn fix_variables(&self, partial_point: &[F]) -> SparseMultilinearExtension<F> {
        assert_eq!(self.predicates.len(), 1);

        for predicate in &self.predicates {
            match predicate {
                PredicateType::SparseEvaluation(sparse_evaluation_predicate) => {
                    return sparse_evaluation_predicate.mle.fix_variables(partial_point)
                }
                PredicateType::Eq(eq_predicate) => {
                    return eq_predicate.fix_variables(partial_point)
                }
            }
        }
        todo!()
    }
}

/// a chain of predicates
pub struct PredicateSum<F: Field> {
    pub predicates: Vec<Predicate<F>>,
    pub num_vars: usize,
}

impl<F: Field> PredicateSum<F> {
    pub fn fix_variables(&self, partial_point: &[F]) -> Vec<SparseMultilinearExtension<F>> {
        self.predicates
            .iter()
            .map(|predicate| predicate.fix_variables(partial_point))
            .collect()
    }

    pub fn evaluate(&self, point: &[F]) -> F {
        let result = self.fix_variables(point);
        result.iter().fold(F::ZERO, |acc, e| acc + e[0])
    }

    pub fn evaluations(&self) -> BTreeMap<usize, F> {
        let mles = self.fix_variables(&[]);
        let mut result = BTreeMap::<usize, F>::new();
        for mle in mles {
            for (key, val) in mle.evaluations {
                result.insert(key, *result.get(&key).unwrap_or(&F::zero()) + val);
            }
        }
        result
    }
}

use core::marker::PhantomData;
use std::collections::BTreeMap;

use ark_ff::Field;
use ark_poly::{MultilinearExtension, SparseMultilinearExtension};

#[derive(Copy, Clone)]
pub struct VariableMask(pub usize);

#[derive(Clone)]
/// a predicate that the verifier will evaluate by interpolation
pub struct SparseEvaluationPredicate<F: Field> {
    pub var_mask: VariableMask,
    pub mle: SparseMultilinearExtension<F>,
}

#[derive(Clone)]
pub struct EqPredicate<F: Field> {
    pub var_masks: Vec<VariableMask>,
    pub consts: Vec<F>,
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
    pub _phantom: PhantomData<F>,
}

impl<F: Field> Predicate<F> {
    pub fn fix_variables(&self, partial_point: &[F]) -> SparseMultilinearExtension<F> {
        assert_eq!(self.predicates.len(), 1);
        for predicate in &self.predicates {
            match predicate {
                PredicateType::SparseEvaluation(sparse_evaluation_predicate) => {
                    return sparse_evaluation_predicate.mle.fix_variables(partial_point)
                }
                PredicateType::Eq(eq_predicate) => todo!(),
            }
        }
        todo!()
    }
}

/// a chain of predicates
pub struct PredicateSum<F: Field> {
    pub predicates: Vec<Predicate<F>>,
    pub num_vars: usize,
    pub _phantom: PhantomData<F>,
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

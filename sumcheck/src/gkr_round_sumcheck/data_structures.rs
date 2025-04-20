//! Data structures used by GKR Round Sumcheck

use crate::ml_sumcheck::protocol::{prover::ProverMsg, verifier::interpolate_uni_poly};
use ark_ff::Field;
use ark_poly::Polynomial;
use ark_std::vec::Vec;

use super::ListOfGKRFunctions;

#[derive(Debug)]
/// Proof for GKR Round Function
pub struct GKRProof<F: Field> {
    pub(crate) phase1_sumcheck_msgs: Vec<ProverMsg<F>>,
    pub(crate) phase2_sumcheck_msgs: Vec<ProverMsg<F>>,
    pub(crate) w_u: F,
    pub(crate) w_v: F,
}

impl<F: Field> GKRProof<F> {
    /// Extract the witness (i.e. the sum of GKR)
    pub fn extract_sum(&self) -> F {
        self.phase1_sumcheck_msgs[0].evaluations[0] + self.phase1_sumcheck_msgs[0].evaluations[1]
    }

    /// Extract the last message of sumcheck
    pub fn check_sum(&self, r: &F) -> F {
        interpolate_uni_poly(&self.phase2_sumcheck_msgs.last().unwrap().evaluations, *r)
    }
}

#[derive(Debug)]
/// Subclaim for GKR Round Function
pub struct GKRRoundSumcheckSubClaim<F: Field> {
    /// u
    pub u: Vec<F>,
    /// w(u)
    pub w_u: F,
    /// v
    pub v: Vec<F>,
    /// w(u)
    pub w_v: F,
    /// expected evaluation at f(g,u,v)
    pub expected_evaluation: F,
}

impl<F: Field> GKRRoundSumcheckSubClaim<F> {
    /// Verify that the subclaim is true by evaluating the GKR Round function.
    pub fn verify_subclaim(
        &self,
        round: &ListOfGKRFunctions<F>,
    ) -> bool {
        let mut actual_evaluation = F::zero();

        for (coeff, function, g) in &round.functions {
            let f1 = &function.f1;
            let f2 = &function.f2;
            let f3 = &function.f3;

            let dim = self.u.len();
            assert_eq!(self.v.len(), dim);
            assert_eq!(f1.num_vars - g.len(), 2 * dim);
            assert_eq!(f2.num_vars, dim);
            assert_eq!(f3.num_vars, dim);
    
            let guv: Vec<_> = g
                .iter()
                .chain(self.u.iter())
                .chain(self.v.iter())
                .copied()
                .collect();
            actual_evaluation += f1.evaluate(&guv) * f2.evaluate(&self.u) * f3.evaluate(&self.v);    
        }

        actual_evaluation == self.expected_evaluation
    }
}

//! Data structures used by GKR Round Sumcheck

use crate::ml_sumcheck::protocol::{prover::ProverMsg, verifier::interpolate_uni_poly};
use ark_ff::Field;
use ark_poly::Polynomial;
use ark_std::vec::Vec;

use super::function::GKRRound;

#[derive(Debug)]
/// Proof for GKR Round Function
pub struct GKRRoundProof<F: Field> {
    /// sumcheck messages for the first gate input
    pub phase0_sumcheck_msgs: Vec<ProverMsg<F>>,
    /// sumcheck messages for the instance number (higher degree)
    pub phase1_sumcheck_msgs: Vec<ProverMsg<F>>,
    /// sumcheck messages for the second gate input
    pub phase2_sumcheck_msgs: Vec<ProverMsg<F>>,
    /// w(u)
    pub w_u: F,
    /// w(v)
    pub w_v: F,
}

impl<F: Field> GKRRoundProof<F> {
    /// Extract the witness (i.e. the sum of GKR)
    pub fn extract_sum(&self) -> F {
        self.phase0_sumcheck_msgs[0].evaluations[0] + self.phase0_sumcheck_msgs[0].evaluations[1]
    }

    /// Extract the last message of sumcheck
    pub fn check_sum(&self, r: &F) -> F {
        interpolate_uni_poly(&self.phase2_sumcheck_msgs.last().unwrap().evaluations, *r)
    }
}

#[derive(Debug)]
/// Subclaim for GKR Round Function
pub struct GKRRoundSumcheckSubClaim<F: Field> {
    /// c
    pub c: Vec<F>,
    /// u
    pub u: Vec<F>,
    /// w(uc)
    pub w_uc: F,
    /// v
    pub v: Vec<F>,
    /// w(vc)
    pub w_vc: F,
    /// expected evaluation at f(g,u,v)
    pub expected_evaluation: F,
}

impl<F: Field> GKRRoundSumcheckSubClaim<F> {
    /// Verify that the subclaim is true by evaluating the GKR Round function.
    pub fn verify_subclaim(&self, round: &GKRRound<F>) -> bool {
        let mut actual_evaluation = F::zero();

        for function in &round.functions {
            let f1_g = &function.f1_g;
            let f2 = &function.f2;
            let f3 = &function.f3;

            let dim = self.u.len();
            assert_eq!(self.v.len(), dim);
            assert_eq!(f1_g.num_vars, 2 * dim);
            assert_eq!(f2.num_vars, dim);
            assert_eq!(f3.num_vars, dim);

            let uv: Vec<_> = self.u.iter().chain(self.v.iter()).copied().collect();
            actual_evaluation += f1_g.evaluate(&uv) * f2.evaluate(&self.u) * f3.evaluate(&self.v);
        }

        actual_evaluation == self.expected_evaluation
    }
}

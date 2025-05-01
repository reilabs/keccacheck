//! Implementation of GKR Round Sumcheck algorithm as described in [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.3) (Section 3.3)
//!
//! GKR Round Sumcheck will use `ml_sumcheck` as a subroutine.

pub mod data_structures;
#[cfg(test)]
mod test;

use crate::gkr_round_sumcheck::data_structures::{GKRRoundProof, GKRRoundSumcheckSubClaim};
use crate::ml_sumcheck::protocol::prover::ProverState;
use crate::ml_sumcheck::protocol::{IPForMLSumcheck, ListOfProductsOfPolynomials, PolynomialInfo};
use crate::rng::FeedableRNG;
use ark_ff::{Field, Zero};
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, Polynomial, SparseMultilinearExtension,
};
use ark_std::marker::PhantomData;
use ark_std::rc::Rc;
use ark_std::vec::Vec;

/// Takes multilinear f1, f3, and input g = g1,...,gl. Returns h_g, and f1 fixed at g.
pub fn initialize_phase_one<F: Field>(
    f1_at_g: &SparseMultilinearExtension<F>,
    f3: &DenseMultilinearExtension<F>,
    instance_bits: usize,
) -> DenseMultilinearExtension<F> {
    // dim contains instance_bits
    let instance_dim = f3.num_vars; // 'l` in paper
    let base_dim = instance_dim - instance_bits;

    assert_eq!(f1_at_g.num_vars + instance_bits, 2 * instance_dim);
    let mut a_hg: Vec<_> = (0..(1 << instance_dim)).map(|_| F::zero()).collect();

    // cxy - c uses the least significant bits (low variable names), y the most sig bits
    for (cxy, v) in f1_at_g.evaluations.iter() {
        println!("cxy {cxy:b} v {v:?}");

        if v != &F::zero() {
            // in f3 evaluations, instance id (c) is the most significant bit
            // so we need to swap things around
            let cx = cxy & ((1 << base_dim) - 1);
            let c = cxy & ((1 << instance_bits) - 1);
            let xy = cxy >> instance_bits;
            let y = xy >> base_dim;
            let x = cx >> instance_bits;


            let yc = (c << base_dim) + y;
            let xc = (c << base_dim) + x;

            let cy = c + (y << instance_bits);
            // let c = yc >> dim;
            // let xc = (c << instance_bits) + x;

            
            println!("c {c:b} x {x:b} y {y:b}");
            println!("a_hg[{xc:b}] += {} * f3[{yc:b}] = {} * {}", *v, *v, f3[yc]);

            a_hg[xc] += *v * f3[yc];
        }
    }

    let hg = DenseMultilinearExtension::from_evaluations_vec(instance_dim, a_hg);

    println!("returning hg {hg:?}");

    hg
}

/// Takes h_g and f2, returns a sumcheck state
pub fn start_phase1_sumcheck<F: Field>(
    instances: &[(&DenseMultilinearExtension<F>, &DenseMultilinearExtension<F>)],
) -> ProverState<F> {
    let dim = instances[0].0.num_vars;
    //assert_eq!(f2.num_vars, dim);
    let mut poly = ListOfProductsOfPolynomials::new(dim);
    for (h_g, f2) in instances {
        poly.add_product(
            vec![Rc::new((*h_g).clone()), Rc::new((*f2).clone())],
            F::one(),
        );
    }
    IPForMLSumcheck::prover_init(&poly)
}

/// Takes multilinear f1 fixed at g, phase one randomness u. Returns f1 fixed at g||u
pub fn initialize_phase_two<F: Field>(
    f1_g: &SparseMultilinearExtension<F>,
    u: &[F],
    instance_bits: usize,
) -> DenseMultilinearExtension<F> {
    assert_eq!(u.len() * 2, f1_g.num_vars + instance_bits);
    f1_g.fix_variables(u).to_dense_multilinear_extension()
}

/// Takes f1 fixed at g||u, f3, and f2 evaluated at u.
pub fn start_phase2_sumcheck<F: Field>(
    instances: &[(
        &DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
        F,
    )],
    instance_bits: usize,
) -> ProverState<F> {
    let first = &instances[0];
    let dim = first.0.num_vars;
    // assert_eq!(f3.num_vars, dim);
    let mut poly = ListOfProductsOfPolynomials::new(dim);
    for (f1_gu, f3, f2_u) in instances {
        let f3_f2u = {
            let mut zero = DenseMultilinearExtension::zero();
            zero += (*f2_u, f3);
            zero
        };

        poly.add_product(vec![Rc::new((*f1_gu).clone()), Rc::new(f3_f2u)], F::one());
    }
    IPForMLSumcheck::prover_init(&poly)
}

#[derive(Debug)]
/// GKR function in a form of f1(r, u, v) * f2(u) * f3(v) where r is const.
pub struct GKRFunction<F: Field> {
    /// sparse wiring polynomial evaluated at random output r
    pub f1_g: SparseMultilinearExtension<F>,
    /// gate evaluation, left operand
    pub f2: DenseMultilinearExtension<F>,
    /// gate evaluation, right operand
    pub f3: DenseMultilinearExtension<F>,
}

#[derive(Debug)]
/// A sum of multiple GKR functions
pub struct GKRRound<F: Field> {
    /// List of functions under sum
    pub functions: Vec<GKRFunction<F>>,
    /// Layer evaluations
    pub layer: DenseMultilinearExtension<F>,
    /// Number of vars used to describe the instance number
    pub instance_bits: usize,
}

impl<F: Field> GKRRound<F> {
    /// Number of variables in each GKR function
    pub fn num_variables(&self, phase: usize) -> usize {
        match phase {
            0 => self.functions[0].f2.num_vars,
            1 => self.functions[0].f3.num_vars - self.instance_bits,
            _ => panic!("only functions in the form of f1(...)f2(...)f3(...) supported"),
        }
    }
}

/// Sumcheck Argument for GKR Round Function
pub struct GKRRoundSumcheck<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> GKRRoundSumcheck<F> {
    /// Takes a GKR Round Function and input, prove the sum.
    /// * `f1`,`f2`,`f3`: represents the GKR round function
    /// * `g`: represents the fixed input.
    pub fn prove<R: FeedableRNG>(
        rng: &mut R,
        round: &GKRRound<F>,
    ) -> (GKRRoundProof<F>, (Vec<F>, Vec<F>)) {
        // assert_eq!(f1.num_vars - g.len(), 2 * f2.num_vars);
        // assert_eq!(f2.num_vars, f3.num_vars);

        let dim = round.num_variables(0);

        let mut h_g_vec = Vec::with_capacity(round.functions.len());
        let mut f1_g_vec = Vec::with_capacity(round.functions.len());
        for function in &round.functions {
            let f1_g = &function.f1_g;
            let f3 = &function.f3;
            let h_g = initialize_phase_one(f1_g, f3, round.instance_bits);
            h_g_vec.push(h_g);
            f1_g_vec.push(f1_g);
        }

        let f2 = round.functions.iter().map(|func| &func.f2);

        let instances = h_g_vec
            .iter()
            .zip(f2.clone())
            .map(|(a, b)| (a, b))
            .collect::<Vec<_>>();

        println!("sumcheck instances {instances:?}");

        let mut phase1_ps = start_phase1_sumcheck(instances.as_slice());
        let mut phase1_vm = None;
        let mut phase1_prover_msgs = Vec::with_capacity(dim);
        let mut u = Vec::with_capacity(dim);
        for i in 0..dim {
            let pm = IPForMLSumcheck::prove_round(&mut phase1_ps, &phase1_vm);

            if i == 0 {
                println!("prover sum {:?}", pm.evaluations[0] + pm.evaluations[1]);
            }
            rng.feed(&pm).unwrap();
            phase1_prover_msgs.push(pm);
            let vm = IPForMLSumcheck::sample_round(rng);
            phase1_vm = Some(vm.clone());
            u.push(vm.randomness);
        }

        let dim = round.num_variables(1);

        let mut f1_gu_vec = Vec::with_capacity(round.functions.len());
        for f1_g in f1_g_vec {
            let f1_gu = initialize_phase_two(&f1_g, &u, round.instance_bits);
            f1_gu_vec.push(f1_gu);
        }

        let f3 = round.functions.iter().map(|func| &func.f3);

        let u_instance_bits = u[u.len()-round.instance_bits..].to_vec();

        let instances = f1_gu_vec
            .iter()
            .zip(f3)
            .zip(f2)
            .map(|((a, b), c)| (a, b.fix_variables(&u_instance_bits), c.evaluate(&u)))
            .collect::<Vec<_>>();

        let mut phase2_ps = start_phase2_sumcheck(&instances, round.instance_bits);
        let mut phase2_vm = None;
        let mut phase2_prover_msgs = Vec::with_capacity(dim);
        let mut v = Vec::with_capacity(dim + round.instance_bits);
        v.extend_from_slice(&u_instance_bits);
        for _ in 0..dim {
            let pm = IPForMLSumcheck::prove_round(&mut phase2_ps, &phase2_vm);
            rng.feed(&pm).unwrap();
            phase2_prover_msgs.push(pm);
            let vm = IPForMLSumcheck::sample_round(rng);
            phase2_vm = Some(vm.clone());
            v.push(vm.randomness);
        }

        (
            GKRRoundProof {
                phase1_sumcheck_msgs: phase1_prover_msgs,
                phase2_sumcheck_msgs: phase2_prover_msgs,
                w_u: round.layer.evaluate(&u),
                w_v: round.layer.evaluate(&v),
            },
            (u, v),
        )
    }

    /// Takes a GKR Round Function, input, and proof, and returns a subclaim.
    ///
    /// If the `claimed_sum` is correct, then it is `subclaim.verify_subclaim` will return true.
    /// Otherwise, it is very likely that `subclaim.verify_subclaim` will return false.
    /// Larger field size guarantees smaller soundness error.
    /// * `f2_num_vars`: represents number of variables of f2
    pub fn verify<R: FeedableRNG>(
        rng: &mut R,
        instance_bits: usize,
        f2_num_vars: usize,
        proof: &GKRRoundProof<F>,
        claimed_sum: F,
    ) -> Result<GKRRoundSumcheckSubClaim<F>, crate::Error> {
        // verify first sumcheck
        let dim1 = instance_bits + f2_num_vars;

        let mut phase1_vs = IPForMLSumcheck::verifier_init(&PolynomialInfo {
            max_multiplicands: 2,
            num_variables: dim1,
        });

        println!("phase 1 verification dim {}", dim1);
        for i in 0..dim1 {
            let pm = &proof.phase1_sumcheck_msgs[i];
            rng.feed(pm).unwrap();
            let _result = IPForMLSumcheck::verify_round((*pm).clone(), &mut phase1_vs, rng);
        }
        let phase1_subclaim = IPForMLSumcheck::check_and_generate_subclaim(phase1_vs, claimed_sum)?;
        println!("phase 1 verified");

        let u = phase1_subclaim.point;

        let dim2 = f2_num_vars;

        let mut phase2_vs = IPForMLSumcheck::verifier_init(&PolynomialInfo {
            max_multiplicands: 2,
            num_variables: dim2,
        });

        println!("phase 2 verification dim {}", dim2);
        for i in 0..dim2 {
            let pm = &proof.phase2_sumcheck_msgs[i];
            rng.feed(pm).unwrap();
            let _result = IPForMLSumcheck::verify_round((*pm).clone(), &mut phase2_vs, rng);
        }
        println!("phase 2 verification");
        let phase2_subclaim = IPForMLSumcheck::check_and_generate_subclaim(
            phase2_vs,
            phase1_subclaim.expected_evaluation,
        )?;
        println!("phase 2 verified");

        let v = phase2_subclaim.point;

        let expected_evaluation = phase2_subclaim.expected_evaluation;

        Ok(GKRRoundSumcheckSubClaim {
            u,
            w_u: proof.w_u,
            v,
            w_v: proof.w_v,
            expected_evaluation,
        })
    }
}

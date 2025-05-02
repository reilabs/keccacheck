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

pub fn add_empty_variables<F: Field>(
    f2: &DenseMultilinearExtension<F>,
    num_vars: usize,
) -> DenseMultilinearExtension<F> {
    let dim: usize = f2.num_vars + num_vars;
    let evaluations = (0..(1 << dim))
        .map(|out| {
            let k = out & (1 << f2.num_vars) - 1;
            f2.evaluations[k]
        })
        .collect();
    DenseMultilinearExtension::from_evaluations_vec(dim, evaluations)
}

pub fn shift_variables_to_end<F: Field>(
    f3: &DenseMultilinearExtension<F>,
    b_dim: usize,
) -> DenseMultilinearExtension<F> {
    let dim = f3.num_vars;
    let c_dim = dim - b_dim;
    let evaluations = (0..(1 << dim))
        .map(|cb| {
            let c = cb & ((1 << c_dim) - 1);
            let b = cb >> c_dim;
            f3.evaluations[(c << b_dim) + b]
        })
        .collect();
    DenseMultilinearExtension::from_evaluations_vec(dim, evaluations)
}

pub fn initialize_f1_gu<F: Field>(
    f1_g: &SparseMultilinearExtension<F>,
    u: &[F],
    c_dim: usize,
) -> DenseMultilinearExtension<F> {
    let ab_dim = f1_g.num_vars - c_dim;
    assert_eq!(ab_dim % 2, 0, "a, b inputs must have the same length");
    let a_dim = ab_dim / 2;

    let evaluations = f1_g
        .evaluations
        .iter()
        .filter_map(|(cxy, v)| {
            if v.is_zero() {
                return None;
            }
            let xy = cxy >> c_dim;
            let y = xy >> a_dim;
            let c = cxy & ((1 << c_dim) - 1);
            let x = xy & ((1 << a_dim) - 1);
            let xcy = (((y << c_dim) + c) << a_dim) + x;

            Some((xcy, *v))
        })
        .collect::<Vec<_>>();
    let f1_g_swapped = SparseMultilinearExtension::from_evaluations(f1_g.num_vars, &evaluations);

    let f1_gu = f1_g_swapped
        .fix_variables(&u)
        .to_dense_multilinear_extension();

    f1_gu
}

/// Takes multilinear f1 fixed at g (output), and f3. Returns h_g.
pub fn initialize_phased_sumcheck<F: Field>(
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
        if v != &F::zero() {
            // in f3 evaluations, instance id (c) is the most significant bit
            // so we need to swap things around
            let cx = cxy & ((1 << instance_dim) - 1);
            let c = cxy & ((1 << instance_bits) - 1);
            let xy = cxy >> instance_bits;
            let y = xy >> base_dim;
            let x = cx >> instance_bits;

            let yc = (c << base_dim) + y;
            let xc = (c << base_dim) + x;

            a_hg[xc] += *v * f3[yc];
        }
    }

    DenseMultilinearExtension::from_evaluations_vec(instance_dim, a_hg)
}

/// Takes h_g and f2, returns a sumcheck state
pub fn start_phase0_sumcheck<F: Field>(
    instances: &[(&DenseMultilinearExtension<F>, &DenseMultilinearExtension<F>)],
) -> ProverState<F> {
    let dim = instances[0].0.num_vars;
    let mut poly = ListOfProductsOfPolynomials::new(dim);
    for (h_g, f2) in instances {
        poly.add_product(
            vec![Rc::new((*h_g).clone()), Rc::new((*f2).clone())],
            F::one(),
        );
    }
    IPForMLSumcheck::prover_init(&poly)
}

/// Takes f1_g fixed at u, f2 fixed at u, and f3, returns a sumcheck state
pub fn start_phase1_sumcheck<F: Field>(
    instances: &[(
        &DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
    )],
) -> ProverState<F> {
    let dim = instances[0].0.num_vars;
    //assert_eq!(f2.num_vars, dim);
    let mut poly = ListOfProductsOfPolynomials::new(dim);
    for (f1_gu, f2_u, f3) in instances {
        poly.add_product(
            vec![
                Rc::new((*f1_gu).clone()),
                Rc::new((*f2_u).clone()),
                Rc::new((*f3).clone()),
            ],
            F::one(),
        );
    }
    IPForMLSumcheck::prover_init(&poly)
}

/// Takes f1_g fixed at u||c, f3 fixed at c, and f2 evaluated at u|cc.
pub fn start_phase2_sumcheck<F: Field>(
    instances: &[(
        &DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
        F,
    )],
) -> ProverState<F> {
    let first = &instances[0];
    let dim = first.0.num_vars;
    let mut poly = ListOfProductsOfPolynomials::new(dim);
    for (f1_gu, f3, f2_u) in instances {
        assert_eq!(f1_gu.num_vars, dim);
        assert_eq!(f3.num_vars, dim);

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
            0 => self.functions[0].f2.num_vars - self.instance_bits,
            1 => self.instance_bits,
            2 => self.functions[0].f3.num_vars - self.instance_bits,
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
        let a_dim = round.num_variables(0);
        let c_dim = round.num_variables(1);
        let b_dim = round.num_variables(2);
        assert_eq!(a_dim, b_dim, "inputs should have the same length");

        let mut h_g_vec = Vec::with_capacity(round.functions.len());
        let mut f1_g_vec = Vec::with_capacity(round.functions.len());
        for function in &round.functions {
            let f1_g = &function.f1_g;
            let f3 = &function.f3;
            let h_g = initialize_phased_sumcheck(f1_g, f3, round.instance_bits);
            h_g_vec.push(h_g);
            f1_g_vec.push(f1_g);
        }

        let f2 = round.functions.iter().map(|func| &func.f2);
        let instances = h_g_vec
            .iter()
            .zip(f2.clone())
            .map(|(a, b)| (a, b))
            .collect::<Vec<_>>();

        let mut phase1_ps = start_phase0_sumcheck(instances.as_slice());
        let mut phase1_vm = None;
        let mut phase0_prover_msgs = Vec::with_capacity(a_dim);
        let mut u = Vec::with_capacity(a_dim);
        for _ in 0..a_dim {
            let pm = IPForMLSumcheck::prove_round(&mut phase1_ps, &phase1_vm);
            rng.feed(&pm).unwrap();
            phase0_prover_msgs.push(pm);
            let vm = IPForMLSumcheck::sample_round(rng);
            phase1_vm = Some(vm.clone());
            u.push(vm.randomness);
        }

        let mut f1_gu_vec = Vec::with_capacity(round.functions.len());

        for f1_g in f1_g_vec {
            f1_gu_vec.push(initialize_f1_gu(f1_g, &u, c_dim));
        }

        let f2_u = f2.map(|f2| f2.fix_variables(&u));

        let f2_u_exp = f2_u.clone().map(|f2| add_empty_variables(&f2, b_dim));

        let f3 = round
            .functions
            .iter()
            .map(|func| shift_variables_to_end(&func.f3, b_dim));

        let instances = f1_gu_vec
            .iter()
            .zip(f2_u_exp)
            .zip(f3.clone())
            .map(|((a, b), c)| (a, b, c))
            .collect::<Vec<_>>();

        let mut phase1_ps = start_phase1_sumcheck(&instances);
        let mut phase1_vm = None;
        let mut phase1_prover_msgs = Vec::with_capacity(c_dim);
        let mut cp = Vec::with_capacity(c_dim);
        for _ in 0..c_dim {
            let pm = IPForMLSumcheck::prove_round(&mut phase1_ps, &phase1_vm);
            rng.feed(&pm).unwrap();
            phase1_prover_msgs.push(pm);
            let vm = IPForMLSumcheck::sample_round(rng);
            phase1_vm = Some(vm.clone());
            cp.push(vm.randomness);
        }

        let mut f1_guc_vec = Vec::with_capacity(round.functions.len());
        for f1_gu in f1_gu_vec {
            let f1_guc = f1_gu.fix_variables(&cp);
            f1_guc_vec.push(f1_guc);
        }

        let f3 = round.functions.iter().map(|func| {
            // f3(y, c) has wrong endianness. we fixed c in the previous phase of sumcheck
            // now need to iterate over y. we'll relabel f3(y, c) to f3(c, y) and set c to a const
            // so we're left with f3(y) required for this phase of sumcheck

            let mut evaluations = vec![F::ZERO; func.f3.evaluations.len()];
            // currently y is in least significant bits, c in the most significant bits.
            for (yc, val) in func.f3.evaluations.iter().enumerate() {
                let y = yc & ((1 << b_dim) - 1);
                let c = yc >> b_dim;
                let cy = (y << round.instance_bits) + c;
                evaluations[cy] = *val;
            }
            let f3_r =
                DenseMultilinearExtension::from_evaluations_vec(func.f3.num_vars, evaluations);

            f3_r.fix_variables(&cp)
        });

        let instances = f1_guc_vec
            .iter()
            .zip(f3)
            .zip(f2_u)
            .map(|((a, b), c)| (a, b, c.evaluate(&cp)))
            .collect::<Vec<_>>();

        let mut phase2_ps = start_phase2_sumcheck(&instances);
        let mut phase2_vm = None;
        let mut phase2_prover_msgs = Vec::with_capacity(b_dim);
        let mut v = Vec::with_capacity(b_dim);
        for _ in 0..b_dim {
            let pm = IPForMLSumcheck::prove_round(&mut phase2_ps, &phase2_vm);
            rng.feed(&pm).unwrap();
            phase2_prover_msgs.push(pm);
            let vm = IPForMLSumcheck::sample_round(rng);
            phase2_vm = Some(vm.clone());
            v.push(vm.randomness);
        }

        u.extend(&cp);
        v.extend(&cp);

        (
            GKRRoundProof {
                phase0_sumcheck_msgs: phase0_prover_msgs,
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
        input_bits: usize,
        proof: &GKRRoundProof<F>,
        claimed_sum: F,
    ) -> Result<GKRRoundSumcheckSubClaim<F>, crate::Error> {
        // verify sumcheck on the first input
        let dim0 = input_bits;

        let mut phase0_vs = IPForMLSumcheck::verifier_init(&PolynomialInfo {
            max_multiplicands: 2,
            num_variables: dim0,
        });

        for i in 0..dim0 {
            let pm = &proof.phase0_sumcheck_msgs[i];
            rng.feed(pm).unwrap();
            let _result = IPForMLSumcheck::verify_round((*pm).clone(), &mut phase0_vs, rng);
        }
        let phase0_subclaim = IPForMLSumcheck::check_and_generate_subclaim(phase0_vs, claimed_sum)?;
        let u = phase0_subclaim.point;

        let dim1 = instance_bits;

        let mut phase1_vs = IPForMLSumcheck::verifier_init(&PolynomialInfo {
            max_multiplicands: 3,
            num_variables: dim1,
        });

        for i in 0..dim1 {
            let pm = &proof.phase1_sumcheck_msgs[i];
            rng.feed(pm).unwrap();
            let _result = IPForMLSumcheck::verify_round((*pm).clone(), &mut phase1_vs, rng);
        }
        let phase1_subclaim = IPForMLSumcheck::check_and_generate_subclaim(
            phase1_vs,
            phase0_subclaim.expected_evaluation,
        )?;
        let c = phase1_subclaim.point;

        let dim2 = input_bits;

        let mut phase2_vs = IPForMLSumcheck::verifier_init(&PolynomialInfo {
            max_multiplicands: 2,
            num_variables: dim2,
        });

        for i in 0..dim2 {
            let pm = &proof.phase2_sumcheck_msgs[i];
            rng.feed(pm).unwrap();
            let _result = IPForMLSumcheck::verify_round((*pm).clone(), &mut phase2_vs, rng);
        }
        let phase2_subclaim = IPForMLSumcheck::check_and_generate_subclaim(
            phase2_vs,
            phase1_subclaim.expected_evaluation,
        )?;
        let v = phase2_subclaim.point;

        let expected_evaluation = phase2_subclaim.expected_evaluation;

        Ok(GKRRoundSumcheckSubClaim {
            c,
            u,
            w_uc: proof.w_u,
            v,
            w_vc: proof.w_v,
            expected_evaluation,
        })
    }
}

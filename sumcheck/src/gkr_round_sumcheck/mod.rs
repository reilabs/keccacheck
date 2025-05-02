//! Implementation of GKR Round Sumcheck algorithm as described in [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.3) (Section 3.3)
//!
//! GKR Round Sumcheck will use `ml_sumcheck` as a subroutine.

pub mod data_structures;
#[cfg(test)]
mod test;

use core::num;

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
use tracing::Instrument;

/// Takes multilinear f1 fixed at g (output), and f3. Returns h_g.
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
    // println!("initialize phase one, ins dim {instance_dim} base dim {base_dim}");
    for (cxy, v) in f1_at_g.evaluations.iter() {
        // println!("cxy {cxy:b} v {v:?}");

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

            let cy = c + (y << instance_bits);
            // let c = yc >> dim;
            // let xc = (c << instance_bits) + x;

            
            // println!("c {c:b} x {x:b} y {y:b}");
            // println!("a_hg[{xc:b}] += {} * f3[{yc:b}] = {} * {}", *v, *v, f3[yc]);

            a_hg[xc] += *v * f3[yc];
        }
    }

    let hg = DenseMultilinearExtension::from_evaluations_vec(instance_dim, a_hg);

    // println!("returning hg {hg:?}");

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
        // println!("\nproduct");
        // println!("h_g {:?}", h_g.evaluations);
        // println!("f2 {:?}", h_g.evaluations);
        poly.add_product(
            vec![Rc::new((*h_g).clone()), Rc::new((*f2).clone())],
            F::one(),
        );
    }
    IPForMLSumcheck::prover_init(&poly)
}

/// Takes f1 fixed at g||u, f3, and f2 evaluated at u.
pub fn start_phase2_sumcheck<F: Field>(
    instances: &[(
        &DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
        F,
    )],
) -> ProverState<F> {
    let first = &instances[0];
    let dim = first.0.num_vars;
    println!("phase2 dim {dim}");
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

        let round_bf = round;
        assert_eq!(round_bf.functions.len(), 1);

        // f1_g(c', a, b), f2(a, c') f3(b, c') - each is exactly 1 bit
        let GKRFunction { f1_g, f2, f3 } =  &round_bf.functions[0];
        let c_dim = round_bf.instance_bits;
        let ab_dim = round_bf.num_variables(1);

        let dim = round.num_variables(0);

        println!("sumcheck phase 1 prep (dim {dim})");

        let mut h_g_vec = Vec::with_capacity(round.functions.len());
        let mut f1_g_vec = Vec::with_capacity(round.functions.len());
        for function in &round.functions {
            let f1_g = &function.f1_g;
            let f3 = &function.f3;
            let h_g = initialize_phase_one(f1_g, f3, round.instance_bits);
            h_g_vec.push(h_g);
            f1_g_vec.push(f1_g);
        }



        println!("BRUTE FORCE c a b vars {} {} {}", f1_g.num_vars, f2.num_vars, f3.num_vars);
        println!("  round 0 vars 3");
        let mut h = vec![F::ZERO; 3];
        for c in 0u64..3 {
            for ab in 0..4 {
                let a: u64 = ab & ((1 << ab_dim) - 1);
                let b = ab >> ab_dim;
                h[c as usize] += f1_g.evaluate(&vec![c.into(), a.into(), b.into()]) * f2.evaluate(&vec![a.into(), c.into()]) * f3.evaluate(&vec![b.into(), c.into()]);
            }
            println!("    h({c}) = {}", h[c as usize]);
        }
        println!("    h(0) + h(1) = {}", h[0] + h[1]);

        println!("  round 1 vars 2");
        let mut h = vec![F::ZERO; 3];
        for a in 0u64..3 {
            for b in 0..2 {
                h[a as usize] += f1_g.evaluate(&vec![2.into(), a.into(), b.into()]) * f2.evaluate(&vec![a.into(), 2.into()]) * f3.evaluate(&vec![b.into(), 2.into()]);
            }
            println!("    h({a}) = {}", h[a as usize]);
        }
        println!("    h(0) + h(1) = {}", h[0] + h[1]);

        println!("  round 2 vars 1");
        let mut h = vec![F::ZERO; 3];
        for b in 0u64..3 {
            h[b as usize] += f1_g.evaluate(&vec![2.into(), 2.into(), b.into()]) * f2.evaluate(&vec![2.into(), 2.into()]) * f3.evaluate(&vec![b.into(), 2.into()]);
            println!("    h({b}) = {}", h[b as usize]);
        }
        println!("    h(0) + h(1) = {}", h[0] + h[1]);


        println!("BRUTE FORCE a c b vars {} {} {}", f1_g.num_vars, f2.num_vars, f3.num_vars);
        println!("  round 0 vars 3");
        let mut h = vec![F::ZERO; 3];
        for a in 0u64..3 {
            for cb in 0..4 {
                let c: u64 = cb & ((1 << ab_dim) - 1);
                let b = cb >> ab_dim;
                h[a as usize] += f1_g.evaluate(&vec![c.into(), a.into(), b.into()]) * f2.evaluate(&vec![a.into(), c.into()]) * f3.evaluate(&vec![b.into(), c.into()]);
            }
            println!("    h({a}) = {}", h[a as usize]);
        }
        println!("    h(0) + h(1) = {}", h[0] + h[1]);

        println!("  round 1 vars 2");
        let mut h = vec![F::ZERO; 3];
        for c in 0u64..3 {
            for b in 0..2 {
                h[c as usize] += f1_g.evaluate(&vec![c.into(), 2.into(), b.into()]) * f2.evaluate(&vec![2.into(), c.into()]) * f3.evaluate(&vec![b.into(), c.into()]);
            }
            println!("    h({c}) = {}", h[c as usize]);
        }
        println!("    h(0) + h(1) = {}", h[0] + h[1]);

        println!("  round 2 vars 1");
        let mut h = vec![F::ZERO; 3];
        for b in 0u64..3 {
            h[b as usize] += f1_g.evaluate(&vec![2.into(), 2.into(), b.into()]) * f2.evaluate(&vec![2.into(), 2.into()]) * f3.evaluate(&vec![b.into(), 2.into()]);
            println!("    h({b}) = {}", h[b as usize]);
        }
        println!("    h(0) + h(1) = {}", h[0] + h[1]);


        let hg = &h_g_vec[0];
        println!("BRUTE FORCE ac hg vars {} {}", f2.num_vars, hg.num_vars);
        println!("  round 0 vars 2");
        println!("    h_g (dim {}) {:?}", hg.num_vars, hg.evaluations);
        let mut h = vec![F::ZERO; 3];
        for a in 0u64..3 {
            for c in 0..2 {
                h[a as usize] += f2.evaluate(&vec![a.into(), c.into()]) * hg.evaluate(&vec![a.into(), c.into()]);
            }
            println!("    h({a}) = {}", h[a as usize]);
        }
        println!("    h(0) + h(1) = {}", h[0] + h[1]);

        println!("  round 1 vars 2");
        let hg2 = hg.fix_variables(&[2.into()]);
        println!("    h_g (dim {}) {:?}", hg2.num_vars, hg2.evaluations);

        let mut h = vec![F::ZERO; 3];
        for c in 0u64..3 {
            h[c as usize] += f2.evaluate(&vec![2.into(), c.into()]) * hg.evaluate(&vec![2.into(), c.into()]);
            println!("    h({c}) = {}", h[c as usize]);
        }
        println!("    h(0) + h(1) = {}", h[0] + h[1]);

        println!("sumcheck phase 1 (dim {dim})");

        let f2 = round.functions.iter().map(|func| &func.f2);
        let instances = h_g_vec
            .iter()
            .zip(f2.clone())
            .map(|(a, b)| (a, b))
            .collect::<Vec<_>>();

        assert_eq!(instances.len(), 1);
        println!("  h_g (dim {}) {:?}", instances[0].0.num_vars, instances[0].0.evaluations);
        println!("  f2 (dim {}) {:?}", instances[0].1.num_vars, instances[0].1.evaluations);

        let mut phase1_ps = start_phase1_sumcheck(instances.as_slice());
        let mut phase1_vm = None;
        let mut phase1_prover_msgs = Vec::with_capacity(dim);
        let mut u = Vec::with_capacity(dim);
        for i in 0..dim {
            let pm = IPForMLSumcheck::prove_round(&mut phase1_ps, &phase1_vm);
            println!("  eval sum {:?}", pm.evaluations[0] + pm.evaluations[1]);
            println!("    h(0) = {:?}", pm.evaluations[0]);
            println!("    h(1) = {:?}", pm.evaluations[1]);
            println!("    h(2) = {:?}", pm.evaluations[2]);

            rng.feed(&pm).unwrap();
            phase1_prover_msgs.push(pm);
            let vm = IPForMLSumcheck::sample_round(rng);
            phase1_vm = Some(vm.clone());
            u.push(vm.randomness);
        }

        let u_x = u[0..u.len()-round.instance_bits].to_vec();
        let u_instance_bits = u[u.len()-round.instance_bits..].to_vec();


        let dim = round.num_variables(1);
        println!("sumcheck phase 2 (dim {dim})");

        let mut f1_gu_vec = Vec::with_capacity(round.functions.len());
        for f1_g in f1_g_vec {
            assert_eq!(u_x.len() * 2 + u_instance_bits.len(), f1_g.num_vars);

            // println!("f1_g {f1_g:?}");
            let f1_gc = f1_g.fix_variables(&u_instance_bits);
            // println!("f1_gc {f1_gc:?}");
            let f1_gcu = f1_gc.fix_variables(&u_x);
            // println!("f1_gcu {f1_gcu:?}");
            let f1_gu = f1_gcu.to_dense_multilinear_extension();
            // println!("f1_gu {f1_gu:?}");
            f1_gu_vec.push(f1_gu);
        }

        let f3 = round.functions.iter().map(|func| {
            // f3(y, c) has wrong endianness. we fixed c in the previous phase of sumcheck
            // now need to iterate over y. we'll relabel f3(y, c) to f3(c, y) and set c to a const
            // so we're left with f3(y) required for this phase of sumcheck

            // println!("relabel f3 vars {} var_dim {} instance_dim {}", func.f3.num_vars, dim, round.instance_bits);

            // println!("f3 {:?}", func.f3.evaluations);

            let mut evaluations = vec![F::ZERO; func.f3.evaluations.len()];
            // currently y is in least significant bits, c in the most significant bits.
            for (yc, val) in func.f3.evaluations.iter().enumerate() {
                let y = yc & ((1 << dim) - 1);
                let c = yc >> dim;
                let cy = (y << round.instance_bits) + c;
                // println!("relabel {yc:b} to {cy:b}");
                evaluations[cy] = *val;
            }
            let f3_r = DenseMultilinearExtension::from_evaluations_vec(func.f3.num_vars, evaluations);


            // let after = before.relabel(0, dim, round.instance_bits);

            // println!("f3_r {:?}", f3_r.evaluations);
            let f3_c = f3_r.fix_variables(&u_instance_bits);
            // println!("f3_c {f3_c:?}");
            f3_c
        });


        let instances = f1_gu_vec
            .iter()
            .zip(f3)
            .zip(f2)
            .map(|((a, b), c)| (a, b, c.evaluate(&u)))
            .collect::<Vec<_>>();

        assert_eq!(instances.len(), 1);
        println!("  f1_gu (dim {}) {:?}", instances[0].0.num_vars, instances[0].0.evaluations);
        println!("  f3 (dim {}) {:?}", instances[0].1.num_vars, instances[0].1.evaluations);
        println!("  f2 {:?}", instances[0].2);

        let mut phase2_ps = start_phase2_sumcheck(&instances);
        let mut phase2_vm = None;
        let mut phase2_prover_msgs = Vec::with_capacity(dim);
        let mut v = Vec::with_capacity(dim);
        for _ in 0..dim {
            let pm = IPForMLSumcheck::prove_round(&mut phase2_ps, &phase2_vm);
            println!("  eval sum {:?}", pm.evaluations[0] + pm.evaluations[1]);
            println!("    next {:?}", pm.evaluations[2]);
            rng.feed(&pm).unwrap();
            phase2_prover_msgs.push(pm);
            let vm = IPForMLSumcheck::sample_round(rng);
            phase2_vm = Some(vm.clone());
            v.push(vm.randomness);
        }

        v.extend(&u_instance_bits);

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
        let u = phase1_subclaim.point;
        println!("phase 1 verified, point {u:?}");


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

        let mut v = phase2_subclaim.point;
        v.extend(&u[u.len()-instance_bits..]);

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

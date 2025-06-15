use crate::reference::{ROUND_CONSTANTS, keccak_round, STATE};
use crate::sumcheck::util::{HALF, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly_xor_base, update, to_poly_xor_base_multi, to_poly_multi};
use crate::transcript::Prover;
use ark_bn254::Fr;
use ark_ff::{One, Zero};

pub struct ThetaProof {
    pub sum: Fr,
    pub r: Vec<Fr>,
    pub d: Vec<Fr>,
    pub ai: Vec<Fr>,
}

pub fn prove_theta(
    transcript: &mut Prover,
    num_vars: usize,
    r: &[Fr],
    beta: &[Fr],
    d: &[u64],
    a: &[u64],
    sum: Fr,
) -> ThetaProof {
    let instances = 1 << (num_vars - 6);

    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r);
    let mut d = d.chunks_exact(instances).map(|x| to_poly_xor_base_multi(x)).collect::<Vec<_>>();
    let mut ai = (0..5)
        .map(|i| {
            let mut rlc = vec![Fr::zero(); 1 << num_vars];
            for j in 0..5 {
                let id = (j * 5 + i);
                let idx = id * instances;
                let poly = to_poly_xor_base_multi(&a[idx..(idx + instances)]);
                for x in 0..(1 << num_vars) {
                    rlc[x] += beta[id] * poly[x];
                }
            }
            rlc
        })
        .collect::<Vec<_>>();

    #[cfg(debug_assertions)]
    {
        let mut ai_d_sum = Fr::zero();
        for j in 0..d.len() {
            for x in 0..(1 << num_vars) {
                ai_d_sum += eq[x] * d[j][x] * ai[j][x];
            }
        }
        assert_eq!(ai_d_sum, sum);
    }

    let proof = prove_sumcheck_theta(transcript, num_vars, &mut eq, &mut d, &mut ai, sum);

    proof
}

pub fn prove_sumcheck_theta(
    transcript: &mut Prover,
    size: usize,
    mut eq: &mut [Fr],
    ds: &mut Vec<Vec<Fr>>,
    ai_rlc: &mut Vec<Vec<Fr>>,
    mut sum: Fr,
) -> ThetaProof {
    #[cfg(debug_assertions)]
    {
        assert_eq!(eq.len(), 1 << size);
        assert_eq!(ds.len(), ai_rlc.len());
        ds.iter().for_each(|d| {
            assert_eq!(d.len(), 1 << size);
        });
        ai_rlc.iter().for_each(|ai| {
            assert_eq!(ai.len(), 1 << size);
        });
    }

    let mut rs = Vec::with_capacity(size);
    for _ in 0..size {
        // p(x) = p0 + p1 ⋅ x + p2 ⋅ x^2 + p3 ⋅ x^3
        let mut p0 = Fr::zero();
        let mut pem1 = Fr::zero();
        let mut p3 = Fr::zero();

        let (e0, e1) = eq.split_at(eq.len() / 2);
        let d = ds
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();
        let ai = ai_rlc
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();

        for i in 0..d[0].0.len() {
            for j in 0..d.len() {
                // Evaluation at 0
                p0 += e0[i] * d[j].0[i] * ai[j].0[i];

                // Evaluation at -1
                pem1 += (e0[i] + e0[i] - e1[i])
                    * (d[j].0[i] + d[j].0[i] - d[j].1[i])
                    * (ai[j].0[i] + ai[j].0[i] - ai[j].1[i]);

                // Evaluation at ∞
                p3 += (e1[i] - e0[i]) * (d[j].1[i] - d[j].0[i]) * (ai[j].1[i] - ai[j].0[i]);
            }
        }

        // Compute p1 and p2 from
        //  p(0) + p(1) = 2 ⋅ p0 + p1 + p2 + p3
        //  p(-1) = p0 - p1 + p2 - p3
        let p2 = HALF * (sum + pem1 - p0) - p0;
        let p1 = sum - p0 - p0 - p3 - p2;
        assert_eq!(sum, p0 + p0 + p1 + p2 + p3);
        assert_eq!(pem1, p0 - p1 + p2 - p3);

        transcript.write(p1);
        transcript.write(p2);
        transcript.write(p3);

        let r = transcript.read();
        rs.push(r);
        // TODO: Fold update into evaluation loop.
        eq = update(eq, r);
        for j in 0..ds.len() {
            // TODO: unnecessary allocation
            ds[j] = update(&mut ds[j], r).to_vec();
            ai_rlc[j] = update(&mut ai_rlc[j], r).to_vec();
        }

        // sum = p(r)
        sum = p0 + r * (p1 + r * (p2 + r * p3));
    }

    let mut ai_subclaims = Vec::with_capacity(ai_rlc.len());
    for j in 0..ai_rlc.len() {
        transcript.write(ai_rlc[j][0]);
        ai_subclaims.push(ai_rlc[j][0]);
    }

    let mut d_subclaims = Vec::with_capacity(ds.len());
    for j in 0..ds.len() {
        transcript.write(ds[j][0]);
        d_subclaims.push(ds[j][0]);
    }
    
    // check result
    #[cfg(debug_assertions)]
    {
        let mut checksum = Fr::zero();
        for j in 0..ds.len() {
            checksum += eq[0] * ds[j][0] * ai_rlc[j][0];
        }
        assert_eq!(sum, checksum);
    }

    ThetaProof {
        sum,
        r: rs,
        d: d_subclaims,
        ai: ai_subclaims,
    }
}

#[test]
fn theta_no_recursion() {
    let num_vars = 7; // two instances
    let instances = 1usize << (num_vars - 6);

    let mut data = (0..(instances * STATE)).map(|i| i as u64).collect::<Vec<_>>();
    let state = keccak_round(&mut data, ROUND_CONSTANTS[0]);

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    let real_theta_sum: Fr = state
        .theta
        .chunks_exact(instances)
        .map(|x| to_poly_multi(x))
        .map(|poly| eval_mle(&poly, &alpha) )
        .map(|x| Fr::one() - x - x)
        .enumerate()
        .map(|(i, x)| beta[i] * x)
        .sum();

    prove_theta(
        &mut prover,
        num_vars,
        &alpha,
        &beta,
        &state.d,
        &state.a,
        real_theta_sum,
    );
}

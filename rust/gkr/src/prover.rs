use crate::reference::{KeccakRoundState, ROUND_CONSTANTS, strip_pi};
use crate::sumcheck::chi::prove_chi;
use crate::sumcheck::iota::prove_iota;
use crate::sumcheck::outputs::{prove_bits, prove_outputs};
use crate::sumcheck::rho::prove_rho;
use crate::sumcheck::theta::prove_theta;
use crate::sumcheck::theta_a::{ThetaAProof, prove_theta_a};
use crate::sumcheck::theta_c::prove_theta_c;
use crate::sumcheck::theta_d::prove_theta_d;
use crate::sumcheck::util::{
    HALF, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_field_vec, to_poly,
};
use crate::transcript::Prover;
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use tracing::instrument;
use whir::algebra::linear_form::{Covector, LinearForm};
use whir::algebra::polynomials::{CoefficientList, EvaluationsList};
use whir::hash;
use whir::parameters::{FoldingFactor, MultivariateParameters, ProtocolParameters, SoundnessType};
use whir::protocols::whir::{Config, Witness};
use whir::transcript::codecs::Empty;
use whir::transcript::{DomainSeparator, ProverState};

#[instrument(skip_all, fields(num_vars=(6 + (data.len() / 25).ilog2())))]
pub fn prove(data: &[u64], alpha: Vec<Fr>) -> (Vec<Fr>, Vec<u64>, Vec<u64>) {
    let instances = data.len() / 25;

    let num_vars = 6 + instances.ilog2() as usize;

    let data = data.to_vec();

    let span = tracing::span!(tracing::Level::INFO, "calculate_states").entered();
    let mut state = Vec::with_capacity(24);
    state.push(KeccakRoundState::at_round(&data, 0));
    for i in 1..24 {
        state.push(state[i - 1].next());
    }
    span.exit();

    let mut prover = Prover::new();
    alpha.iter().for_each(|challenge| prover.absorb(*challenge));
    let span = tracing::span!(tracing::Level::INFO, "prove all rounds").entered();

    // TODO: feed output to the prover before obtaining alpha
    let mut beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    // Write final output sum
    // Over here we will instead make a claim about the words
    // to obtain the sum

    let output_words = to_field_vec(&state[23].iota);
    let c: Fr = output_words
        .chunks(instances)
        .enumerate()
        .map(|(i, word_poly)| beta[i] * eval_mle(word_poly, &alpha))
        .sum();
    prover.write(c);

    // We will run one round of reduction to reduce to a claim on the output bits
    let eq_proof = prove_outputs(&mut prover, num_vars - 6, &alpha, &output_words, &beta, c);
    let mut bits = to_poly(&state[23].iota);

    let bit_proof = prove_bits(
        &mut prover,
        &eq_proof.r_x,
        &mut bits,
        &beta,
        eq_proof.word_rlc_eval,
    );

    let mut r = Vec::with_capacity(num_vars);
    r.extend(eq_proof.r_x);
    r.extend(bit_proof.r_y);
    #[cfg(debug_assertions)]
    {
        let sum: Fr = state[23]
            .iota
            .chunks_exact(instances)
            .enumerate()
            .map(|(i, x)| {
                let poly = to_poly(x);
                beta[i] * eval_mle(&poly, &r)
            })
            .sum();
        assert_eq!(bit_proof.sum, bit_proof.bit_rlc_eval * bit_proof.pow_r_y);
        assert_eq!(sum, bit_proof.bit_rlc_eval)
    }

    let mut sum = bit_proof.bit_rlc_eval;
    for round in (0..24).rev() {
        let previous_proof = prove_round(
            &mut prover,
            num_vars,
            &state[round],
            &r,
            &mut beta,
            sum,
            ROUND_CONSTANTS[round],
        );
        r = previous_proof.r;
        if round != 0 {
            sum = Fr::zero();
            beta.iter_mut().enumerate().for_each(|(i, b)| {
                *b = prover.read();
                let v = HALF * (Fr::one() - previous_proof.iota_hat[i]);
                sum += *b * v;
            });
        }
    }
    span.exit();

    let input_words = to_field_vec(&state[0].a);
    // For the moment, let's have the rlc from the inputs, be exactly the same as from the rounds
    // This way the input bit polynomial under evaluation is the same
    // TODO: work out if this is secure
    let input_beta = beta;
    let input_alpha = (0..num_vars - 6).map(|_| prover.read()).collect::<Vec<_>>();

    let input_c: Fr = input_words
        .chunks(instances)
        .enumerate()
        .map(|(i, word_poly)| input_beta[i] * eval_mle(word_poly, &input_alpha))
        .sum();
    prover.write(c);

    // Reduce to a claim on the input bits
    let input_eq_proof = prove_outputs(
        &mut prover,
        num_vars - 6,
        &input_alpha,
        &input_words,
        &input_beta,
        input_c,
    );
    let mut input_bits = to_poly(&state[0].a);

    let input_bit_proof = prove_bits(
        &mut prover,
        &input_eq_proof.r_x,
        &mut input_bits,
        &input_beta,
        input_eq_proof.word_rlc_eval,
    );

    // Combine two claims on the input bits via line restriction:
    // Claim 1 (from rounds): per-lane evaluations at point r
    // Claim 2 (from input reduction): RLC evaluation at point r2
    let mut r2 = Vec::with_capacity(num_vars);
    r2.extend_from_slice(&input_eq_proof.r_x);
    r2.extend_from_slice(&input_bit_proof.r_y);

    let lane_size = 1 << num_vars;

    // Batch 25 lanes with random coefficients
    let mut h = vec![Fr::zero(); lane_size];
    for i in 0..25 {
        let lane = &input_bits[i * lane_size..(i + 1) * lane_size];
        for j in 0..lane_size {
            h[j] += input_beta[i] * lane[j];
        }
    }

    // g(t) = h((1-t)*r + t*r2) has degree num_vars
    // g(0) and g(1) known to verifier; send g(2), ..., g(num_vars)
    for t_val in 2..=num_vars {
        let t = Fr::from(t_val as u64);
        let point: Vec<Fr> = r
            .iter()
            .zip(r2.iter())
            .map(|(a, b)| (Fr::one() - t) * a + t * b)
            .collect();
        prover.write(eval_mle(&h, &point));
    }

    let mv_parameters = MultivariateParameters::new(num_vars);

    // TODO Revisit these parameters
    let whir_params = ProtocolParameters {
        initial_statement: true,
        security_level: 32,
        pow_bits: 0,
        folding_factor: FoldingFactor::Constant(1),
        soundness_type: SoundnessType::UniqueDecoding,
        starting_log_inv_rate: 1,
        batch_size: 25,
        hash_id: hash::SHA2,
    };

    let config = Config::new(mv_parameters, &whir_params);
    let ds = DomainSeparator::protocol(&whir_params)
        .session(&format!("Test at {}:{}", file!(), line!()))
        .instance(&Empty);
    let mut prover_state = ProverState::new_std(&ds);

    let lane_polynomials: Vec<CoefficientList<Fr>> = state[0]
        .a
        .chunks(instances)
        .map(|lane| CoefficientList::new(to_poly(lane)))
        .collect();

    let whir_commitment = whir_commit(&config, &mut prover_state, &lane_polynomials);

    for element in &whir_commitment.matrix {
        prover.absorb(*element);
    }

    let r_star: Vec<Fr> = (0..num_vars).map(|_| prover.read()).collect();
    let mut weights_polynomial: Vec<Fr> = Vec::with_capacity(1 << (num_vars + 1));

    let r_star_eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r_star);

    let zero_vec: Vec<Fr> = (0..(1 << num_vars)).map(|_| Fr::zero()).collect();
    weights_polynomial.extend_from_slice(&zero_vec);
    weights_polynomial.extend_from_slice(&r_star_eq);
    let r_star_evaluations: Vec<Fr> = (0..25)
        .map(|i| eval_mle(lane_polynomials[i].coeffs(), &r_star))
        .collect();

    let poly_refs = lane_polynomials.iter().collect::<Vec<_>>();

    let linear_weight_list: EvaluationsList<Fr> = CoefficientList::new(weights_polynomial).into();
    let weight = Covector::new(linear_weight_list.evals().to_vec());

    config.prove(
        &mut prover_state,
        &poly_refs,
        &[&whir_commitment],
        &[&weight as &dyn LinearForm<Fr>],
        &r_star_evaluations,
    );

    (prover.finish(), state[0].a.clone(), state[23].iota.clone())
}

#[instrument(skip_all)]
pub fn prove_round(
    prover: &mut Prover,
    num_vars: usize,
    layers: &KeccakRoundState,
    alpha: &[Fr],
    beta: &mut [Fr],
    sum: Fr,
    rc: u64,
) -> ThetaAProof {
    // prove iota
    let iota_proof = prove_iota(prover, num_vars, alpha, beta, &layers.pi_chi, sum, rc);

    // combine subclaims chi_00 and chi_rlc
    let x = prover.read();
    let y = prover.read();
    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);
    let sum = beta[0] * iota_proof.chi_00 + y * iota_proof.chi_rlc;

    // prove chi
    let pi_chi_proof = prove_chi(prover, num_vars, &iota_proof.r, beta, &layers.rho, sum);

    // strip pi to get rho
    let mut rho = pi_chi_proof.pi.clone();
    strip_pi(&pi_chi_proof.pi, &mut rho);

    // combine subclaims on rho
    let mut sum = Fr::zero();
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * rho[i];
    });

    // prove rho
    let rho_proof = prove_rho(prover, num_vars, &pi_chi_proof.r, beta, &layers.theta, sum);

    // combine subclaims on theta, change base
    let theta_xor_base = rho_proof
        .theta
        .iter()
        .map(|x| Fr::one() - x - x)
        .collect::<Vec<_>>();
    let mut sum = Fr::zero();
    // we need that beta to combine with the last theta sumcheck!
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_xor_base[i];
    });

    // prove theta
    let theta_proof = prove_theta(
        prover,
        num_vars,
        &rho_proof.r,
        beta,
        &layers.d,
        &layers.a,
        sum,
    );

    // combine subclaims on theta d
    let mut sum = Fr::zero();
    let mut beta_d = vec![Fr::zero(); theta_proof.d.len()];
    beta_d.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_proof.d[i];
    });

    // prove theta d
    let theta_d_proof = prove_theta_d(prover, num_vars, &theta_proof.r, &beta_d, &layers.c, sum);

    // combine claims on theta c and rot_c
    let mut sum = Fr::zero();
    let mut beta_c = vec![Fr::zero(); theta_d_proof.c.len()];
    let mut beta_rot_c = vec![Fr::zero(); theta_d_proof.rot_c.len()];
    beta_c.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_d_proof.c[i];
    });
    beta_rot_c.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_d_proof.rot_c[i];
    });

    // prove theta c
    let theta_c_proof = prove_theta_c(
        prover,
        num_vars,
        &theta_d_proof.r,
        &beta_c,
        &beta_rot_c,
        &layers.a,
        sum,
    );

    // combine claims on a from theta and theta c
    let mut sum = Fr::zero();
    let mut beta_a = vec![Fr::zero(); theta_c_proof.a.len()];

    theta_proof.ai.iter().enumerate().for_each(|(i, ai)| {
        let b = prover.read();
        for j in 0..5 {
            beta[j * 5 + i] *= b;
        }
        sum += b * *ai;
    });
    beta_a.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_c_proof.a[i];
    });

    // prove theta a
    prove_theta_a(
        prover,
        num_vars,
        &theta_proof.r,
        &theta_c_proof.r,
        beta,
        &beta_a,
        &layers.a,
        sum,
    )
}

fn whir_commit(
    config: &Config<Fr>,
    prover_state: &mut ProverState,
    polynomials: &[CoefficientList<Fr>],
) -> Witness<Fr> {
    // Define the Fiat-Shamir IOPattern for committing and proving
    let poly_refs = polynomials.iter().collect::<Vec<_>>();
    config.commit(prover_state, &poly_refs)
}

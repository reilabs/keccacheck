#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
//! A crate for sumcheck protocol of GKR functions
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, variant_size_differences)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_mut)]
#![deny(missing_docs)]
#![deny(unused_imports)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use)]

pub use error::Error;

/// use ark_std for std
#[macro_use]
extern crate ark_std;

/// error for this crate
mod error;

pub mod gkr_round_sumcheck;
pub mod ml_sumcheck;

pub mod rng;

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use ark_ff::{AdditiveGroup, Field};
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_test_curves::bls12_381::Fr;

    use crate::{ml_sumcheck::{protocol::ListOfProductsOfPolynomials, MLSumcheck}, rng::{Blake2b512Rng, FeedableRNG}};

    #[test]
    fn test_zerocheck() {
        // zero-check on P(x, y) = xy * (1 - x - y - xy)
        let nv = 2;
        let mut poly = ListOfProductsOfPolynomials::<Fr>::new(nv);
        let poly_1 = DenseMultilinearExtension::from_evaluations_slice(nv, &[Fr::ZERO, Fr::ZERO, Fr::ZERO, Fr::ONE]);
        let poly_2 = DenseMultilinearExtension::from_evaluations_slice(nv, &[Fr::ONE, Fr::ZERO, Fr::ZERO, Fr::ZERO]);

        println!("poly_1: {poly_1:?}");
        println!("poly_2: {poly_2:?}");

        poly.add_product([Rc::new(poly_1), Rc::new(poly_2)], Fr::ONE);

        let poly_info = poly.info();
        let proof = MLSumcheck::prove(&poly).expect("fail to prove");
        let subclaim = MLSumcheck::verify(&poly_info, Fr::ZERO, &proof).expect("fail to verify");
        assert!(
            poly.evaluate(&subclaim.point) == subclaim.expected_evaluation,
            "wrong subclaim"
        );    
    }

    fn eq<F: Field>(lft: DenseMultilinearExtension<F>) -> DenseMultilinearExtension<F> {
        lft
    }

    #[test]
    fn test_non_zerocheck() {
        let nv = 2;

        let mut minus_one: Fr = 1.into();
        minus_one.neg_in_place();

        let mut rng = Blake2b512Rng::setup();
        let r = DenseMultilinearExtension::<Fr>::rand(nv, &mut rng);
        let eq_r = eq(r);

        let mut poly = ListOfProductsOfPolynomials::<Fr>::new(nv);
        let poly_1 = DenseMultilinearExtension::from_evaluations_slice(nv, &[Fr::ZERO, Fr::ONE, minus_one, Fr::ZERO]);

        println!("poly_1: {poly_1:?}");

        poly.add_product([Rc::new(poly_1)], Fr::ONE);

        let poly_info = poly.info();
        let proof = MLSumcheck::prove(&poly).expect("fail to prove");
        let subclaim = MLSumcheck::verify(&poly_info, Fr::ZERO, &proof).expect("fail to verify");
        assert!(
            poly.evaluate(&subclaim.point) == subclaim.expected_evaluation,
            "wrong subclaim"
        );    
    }

}

use std::rc::Rc;

use ark_bn254::Fr;
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::rand::RngCore;
use ark_sumcheck::{ml_sumcheck::{protocol::ListOfProductsOfPolynomials, MLSumcheck}, rng::{Blake2b512Rng, FeedableRNG}};
use tracing::instrument;

fn random_mle<F: Field, R: RngCore>(
    dim: usize,
    rng: &mut R,
) ->  DenseMultilinearExtension<F> {
    DenseMultilinearExtension::rand(dim, rng)
}

#[instrument(skip_all, fields(dim = instance.num_variables, add_terms = instance.products.len(), product_len = instance.products[0].1.len()))]
fn sumcheck<F: Field>(instance: &ListOfProductsOfPolynomials<F>) {
    MLSumcheck::prove(&instance).unwrap();
}

fn main() {
    tracing_forest::init();

    let dim = 19;

    let mut rng = Blake2b512Rng::setup();
    let mle = (0..10).map(|_| {
        Rc::new(random_mle::<Fr, _>(dim, &mut rng))
    }).collect::<Vec<_>>();

    // a single polynomial
    let mut instance = ListOfProductsOfPolynomials::new(dim);
    instance.add_product(mle[0..1].iter().cloned(), Fr::ONE);
    sumcheck(&instance);

    // a product of 3 polynomials
    let mut instance = ListOfProductsOfPolynomials::new(dim);
    instance.add_product(mle[0..3].iter().cloned(), Fr::ONE);
    sumcheck(&instance);

    // a sum of 3 products, each product with 3 polynomials
    let mut instance = ListOfProductsOfPolynomials::new(dim);
    (0..3).for_each(|i| {
        instance.add_product(mle[(i*3)..(i*3+3)].iter().cloned(), Fr::ONE);
    });
    sumcheck(&instance);
    
}

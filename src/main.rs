use ark_ff_optimized::fp64::Fp;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};

pub mod keccak;

fn main() {
    let num_vars = 2;
    let poly = DenseMultilinearExtension::<Fp>::from_evaluations_slice(
        num_vars, 
        &[Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(4)]
    );

    let mut sum = Fp::from(0);
    let mut point = vec![Fp::from(0); num_vars];
    
    for ind in 0..(1 << num_vars) {
        let mut n = ind;
        for var in 0..num_vars {
            point[var] = Fp::from(n % 2);
            n /= 2;
        }

        let res = poly.evaluate(&point).unwrap();
        println!("eval at: {point:?} -> {res:?}");
        sum += res;
    }

    println!("result: {sum:?}");
}

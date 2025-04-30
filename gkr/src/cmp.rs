use ark_bn254::Fr;
use ark_sumcheck::{
    gkr::{
        Circuit, GKR, Gate, Instance, Layer, LayerGate,
        compiled::CompiledCircuit,
        predicate::{eq, eq_const},
    },
    rng::{Blake2b512Rng, FeedableRNG},
};

// all gates are multiplications
// w0:   36         6
// f1:  /  \      /    \
// w1: 9     4   6      1
// f2: ||    ||/  \     ||
// w2: 3     2     3     1
#[test]
fn test_cmp() {
    let circuit = Circuit {
        //000 001 010 011 101
        input_bits: 3,
        output_bits: 3,
        layers: vec![Layer {
            layer_bits: 3,
            gates: vec![LayerGate {
                gate: Gate::Left,
                // get all positions <= 5; so x2, x1, x0 <= 1 0 1
                // out: 0, 1, 2
                // in1: 3, 4, 5
                // in2: 6, 7, 8
                wiring: (eq_const(2, 0)
                    * eq_const(5, 0)
                    * eq_const(8, 0)
                    * eq(&[1, 4, 7])
                    * eq(&[0, 3, 6]))
                    + (eq_const(2, 1)
                        * eq_const(1, 0)
                        * eq_const(5, 1)
                        * eq_const(4, 0)
                        * eq_const(8, 1)
                        * eq_const(7, 0)
                        * eq(&[0, 3, 6])),
            }],
        }],
    };

    let instance = Instance::<Fr> {
        //000 001 010 011 101
        inputs: vec![
            1.into(),
            2.into(),
            3.into(),
            4.into(),
            5.into(),
            6.into(),
            7.into(),
            8.into(),
        ],
        outputs: vec![
            1.into(),
            2.into(),
            3.into(),
            4.into(),
            5.into(),
            6.into(),
            0.into(),
            0.into(),
        ],
    };

    let compiled = CompiledCircuit::from_circuit(&circuit);

    println!("proving...");
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &[&instance]);

    println!("verifying...");
    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &[&instance], &gkr_proof);
}

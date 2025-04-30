use ark_bn254::Fr;
use ark_sumcheck::{
    gkr::{Circuit, GKR, Gate, Instance, Layer, LayerGate, compiled::CompiledCircuit},
    rng::{Blake2b512Rng, FeedableRNG},
};

// all gates are multiplications
// w0:   36         6
// f1:  /  \      /    \
// w1: 9     4   6      1
// f2: ||    ||/  \     ||
// w2: 3     2     3     1
#[test]
fn test_gkr_basic_mul() {
    // TODO: make it data-parallel
    let circuit = Circuit {
        input_bits: 2,
        output_bits: 1,
        layers: vec![
            Layer::with_builder(1, 2, |out| (Gate::Mul, 2 * out, 2 * out + 1)),
            Layer {
                layer_bits: 2,
                gates: vec![LayerGate::new(
                    2,
                    2,
                    Gate::Mul,
                    vec![(1, 1, 1), (2, 1, 2), (0, 0, 0), (3, 3, 3)],
                )],
            },
        ],
    };

    let instance = Instance::<Fr> {
        inputs: vec![3.into(), 2.into(), 3.into(), 1.into()],
        outputs: vec![36.into(), 6.into()],
    };

    let compiled = CompiledCircuit::from_circuit(&circuit);

    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &[&instance]);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &[&instance], &gkr_proof);
}

// w0:           24          9
// f1(mul,add)  / * \      / + \
// w1:         6     4   5      4
// f2 (add):  ||    ||/  \     ||
// w2:         3     2     3     2
// f3 (add):
// w3:           1        2
#[test]
fn test_gkr_basic_add() {
    // TODO: make it data-parallel
    let circuit = Circuit {
        input_bits: 1,
        output_bits: 1,
        layers: vec![
            Layer {
                layer_bits: 1,
                gates: vec![
                    LayerGate::new(1, 2, Gate::Mul, vec![(0, 0, 1)]),
                    LayerGate::new(1, 2, Gate::Add, vec![(1, 2, 3)]),
                ],
            },
            Layer {
                layer_bits: 2,
                gates: vec![LayerGate::new(
                    2,
                    2,
                    Gate::Add,
                    vec![(0, 0, 0), (1, 1, 1), (2, 1, 2), (3, 3, 3)],
                )],
            },
            Layer {
                layer_bits: 2,
                gates: vec![LayerGate::new(
                    2,
                    1,
                    Gate::Add,
                    vec![(0, 0, 1), (1, 0, 0), (2, 0, 1), (3, 0, 0)],
                )],
            },
        ],
    };

    let instance = Instance::<Fr> {
        inputs: vec![1.into(), 2.into()],
        outputs: vec![24.into(), 9.into()],
    };

    let compiled = CompiledCircuit::from_circuit(&circuit);

    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &[&instance]);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &[&instance], &gkr_proof);
}

// w0:           1          0
// f1(xor)      /  \      /   \
// w1:         1     0   0     0
// f2 (id) :  ||    ||/  \     ||    // copy left child
// w2:         1     0     1     0
#[test]
fn test_gkr_basic_id_xor() {
    // TODO: make it data-parallel
    let circuit = Circuit {
        input_bits: 2,
        output_bits: 1,
        layers: vec![
            Layer {
                layer_bits: 1,
                gates: vec![LayerGate::new(1, 2, Gate::Xor, vec![(0, 0, 1), (1, 2, 3)])],
            },
            Layer {
                layer_bits: 2,
                gates: vec![LayerGate::new(
                    2,
                    2,
                    Gate::Left,
                    vec![(0, 0, 0), (1, 1, 1), (2, 1, 2), (3, 3, 3)],
                )],
            },
        ],
    };

    let instance = Instance::<Fr> {
        inputs: vec![1.into(), 0.into(), 1.into(), 0.into()],
        outputs: vec![1.into(), 0.into()],
    };

    let compiled = CompiledCircuit::from_circuit(&circuit);

    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &[&instance]);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &[&instance], &gkr_proof);
}

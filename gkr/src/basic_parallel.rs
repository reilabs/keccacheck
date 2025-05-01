use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_sumcheck::{
    gkr::{Circuit, GKR, Gate, Instance, Layer, LayerGate, compiled::CompiledCircuit},
    rng::{Blake2b512Rng, FeedableRNG},
};

// all gates are multiplications
// w0:          24
// f1:       /     \
// w1:     2        12
// f2:   /  \     /   \
// w2: 1     2   3     4
#[test]
fn test_parallel_reference() {
    let circuit = Circuit {
        input_bits: 3,
        output_bits: 1,
        layers: vec![
            Layer::with_builder(1, 2, |out| (Gate::Mul, 2 * out, 2 * out + 1)),
            Layer::with_builder(2, 3, |out| (Gate::Mul, 2 * out, 2 * out + 1)),
        ],
    };

    let num_instances = 1;

    let instances = (0u64..num_instances).map(|i| {
        Instance::<Fr> {
            inputs: (0..8).map(|j| (i * 8 + j + 1).into()).collect(),
            outputs: vec![
                (0..4).fold(Fr::ONE, |acc, j| acc * Into::<Fr>::into(i * 8 + j + 1)),
                (4..8).fold(Fr::ONE, |acc, j| acc * Into::<Fr>::into(i * 8 + j + 1)),
            ]
        }
    }).collect::<Vec<_>>();


    let compiled = CompiledCircuit::from_circuit_batched(&circuit, num_instances as usize);

    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);
}


// all gates are multiplications
// w0:          24
// f1:       /     \
// w1:     2        12
// f2:   /  \     /   \
// w2: 1     2   3     4
#[test]
fn test_basic_parallel() {
    let circuit = Circuit {
        input_bits: 2,
        output_bits: 0,
        layers: vec![
            Layer::with_builder(0, 1, |out| (Gate::Mul, 2 * out, 2 * out + 1)),
            Layer::with_builder(1, 2, |out| (Gate::Mul, 2 * out, 2 * out + 1)),
        ],
    };

    let num_instances = 2;

    let instances = (0u64..num_instances).map(|i| {
        Instance::<Fr> {
            inputs: (0..4).map(|j| (i * 4 + j + 1).into()).collect(),
            outputs: vec![(0..4).fold(Fr::ONE, |acc, j| acc * Into::<Fr>::into(i * 4 + j + 1))]
        }
    }).collect::<Vec<_>>();


    let compiled = CompiledCircuit::from_circuit_batched(&circuit, num_instances as usize);

    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);
}

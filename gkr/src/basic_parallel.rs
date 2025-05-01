use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use ark_sumcheck::{
    gkr::{compiled::CompiledCircuit, Circuit, Gate, Instance, Layer, LayerGate, GKR},
    rng::{Blake2b512Rng, FeedableRNG}, Error as RngError,
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

#[test]
fn not_rand() {
    let mut rng = NotReallyRng::setup();
    let result = Fr::rand(&mut rng);

    let one = Fr::ONE;
    println!("result = {result}, one {} {:?}", one, one.0.0);

    let result = Fr::rand(&mut rng);

    let one = Fr::ONE;
    println!("result = {result}, one {} {:?}", one, one.0.0);


    let result = Fr::rand(&mut rng);

    let one = Fr::ONE;
    println!("result = {result}, one {} {:?}", one, one.0.0);

}

struct NotReallyRng {
    iter: usize,
}

impl RngCore for NotReallyRng {
    fn next_u32(&mut self) -> u32 {
        todo!()
    }

    fn next_u64(&mut self) -> u64 {
        //println!("call next_u64");
        let result = match self.iter {
            0 => 12436184717236109307,
            1 => 3962172157175319849,
            2 => 7381016538464732718,
            3 => 1011752739694698287,
            _ => panic!()
        };
        self.iter = (self.iter + 1) % 4;
        result
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        todo!()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        todo!()
    }
}

impl FeedableRNG for NotReallyRng {
    type Error = RngError;

    fn setup() -> Self {
        Self { iter: 0, }
    }

    fn feed<M: CanonicalSerialize>(&mut self, msg: &M) -> Result<(), Self::Error> {
        Ok(())
    }
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

    let mut fs_rng = NotReallyRng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    let mut fs_rng = NotReallyRng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);
}

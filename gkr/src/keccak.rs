use ark_bn254::Fr;
use ark_poly::SparseMultilinearExtension;
use ark_sumcheck::{
    gkr::{Circuit, GKR, Gate, Layer, LayerGate, eval_index},
    rng::{Blake2b512Rng, FeedableRNG},
};

// all gates are multiplications
// w0:   36         6
// f1:  /  \      /    \
// w1: 9     4   6      1
// f2: ||    ||/  \     ||
// w2: 3     2     3     1
pub fn gkr_mul() {
    // TODO: make wirings a formula for faster verification. V should be able to calc f_i in O(num_vars) time
    // TOOD: make it data-parallel
    let circuit = Circuit::<Fr> {
        inputs: vec![3.into(), 2.into(), 3.into(), 1.into()],
        outputs: vec![36.into(), 6.into()],
        layers: vec![
            Layer::with_builder(1, 2, |out| (Gate::Mul, 2 * out, 2 * out + 1)),
            Layer {
                gates: vec![LayerGate {
                    wiring: SparseMultilinearExtension::<Fr>::from_evaluations(
                        6,
                        vec![
                            eval_index(2, 0, 2, 0, 0),
                            eval_index(2, 1, 2, 1, 1),
                            eval_index(2, 2, 2, 1, 2),
                            eval_index(2, 3, 2, 3, 3),
                        ]
                        .iter(),
                    ),
                    gate: Gate::Mul,
                }],
            },
        ],
    };

    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &circuit);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &gkr_proof);
}

// w0:           24          9
// f1(mul,add)  / * \      / + \
// w1:         6     4   5      4
// f2 (add):  ||    ||/  \     ||
// w2:         3     2     3     2
// f3 (add):
// w3:           1        2
pub fn gkr_add_mul() {
    // TODO: make it a formula for faster verification. V should be able to calc f_i in O(num_vars) time
    // TOOD: make it data-parallel
    let circuit = Circuit::<Fr> {
        inputs: vec![1.into(), 2.into()],
        outputs: vec![24.into(), 9.into()],
        layers: vec![
            Layer {
                gates: vec![
                    LayerGate {
                        wiring: SparseMultilinearExtension::<Fr>::from_evaluations(
                            5,
                            vec![eval_index(1, 0, 2, 0, 1)].iter(),
                        ),
                        gate: Gate::Mul,
                    },
                    LayerGate {
                        wiring: SparseMultilinearExtension::<Fr>::from_evaluations(
                            5,
                            vec![eval_index(1, 1, 2, 2, 3)].iter(),
                        ),
                        gate: Gate::Add,
                    },
                ],
            },
            Layer {
                gates: vec![LayerGate {
                    wiring: SparseMultilinearExtension::<Fr>::from_evaluations(
                        6,
                        vec![
                            eval_index(2, 0, 2, 0, 0),
                            eval_index(2, 1, 2, 1, 1),
                            eval_index(2, 2, 2, 1, 2),
                            eval_index(2, 3, 2, 3, 3),
                        ]
                        .iter(),
                    ),
                    gate: Gate::Add,
                }],
            },
            Layer {
                gates: vec![LayerGate {
                    wiring: SparseMultilinearExtension::<Fr>::from_evaluations(
                        4,
                        vec![
                            eval_index(2, 0, 1, 0, 1),
                            eval_index(2, 1, 1, 0, 0),
                            eval_index(2, 2, 1, 0, 1),
                            eval_index(2, 3, 1, 0, 0),
                        ]
                        .iter(),
                    ),
                    gate: Gate::Add,
                }],
            },
        ],
    };

    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &circuit);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &gkr_proof);
}

// w0:           1          0
// f1(xor)      /  \      /   \
// w1:         1     0   0     0
// f2 (id) :  ||    ||/  \     ||    // copy left child
// w2:         1     0     1     0
pub fn gkr_id_xor() {
    // TODO: make it a formula for faster verification. V should be able to calc f_i in O(num_vars) time
    // TOOD: make it data-parallel
    let circuit = Circuit::<Fr> {
        inputs: vec![1.into(), 0.into(), 1.into(), 0.into()],
        outputs: vec![1.into(), 0.into()],
        layers: vec![
            Layer {
                gates: vec![LayerGate {
                    wiring: SparseMultilinearExtension::<Fr>::from_evaluations(
                        5,
                        vec![eval_index(1, 0, 2, 0, 1), eval_index(1, 1, 2, 2, 3)].iter(),
                    ),
                    gate: Gate::Xor,
                }],
            },
            Layer {
                gates: vec![LayerGate {
                    wiring: SparseMultilinearExtension::<Fr>::from_evaluations(
                        6,
                        vec![
                            eval_index(2, 0, 2, 0, 0),
                            eval_index(2, 1, 2, 1, 1),
                            eval_index(2, 2, 2, 1, 2),
                            eval_index(2, 3, 2, 3, 3),
                        ]
                        .iter(),
                    ),
                    gate: Gate::Left,
                }],
            },
        ],
    };

    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &circuit);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &gkr_proof);
}

#[test]
fn test_gkr_basic_mul() {
    gkr_mul();
}

#[test]
fn test_gkr_basic_add() {
    gkr_add_mul();
}

#[test]
fn test_gkr_basic_id_xor() {
    gkr_id_xor();
}

// pub fn gkr_theta() {
//     let input = vec![0; 1 << 11];
//     let output = vec![0; 1 << 11];

//     // layer 0: output
//     // gates: g_xor(x, y)
//     // wiring: for each output element, xor it with a corresponding array column
//     let mut f_0 = Vec::with_capacity(25 * 64);
//     for y in 0..5 {
//         for x in 0..5 {
//             for bit in 0..64 {
//                 let out = y * 5 * 64 + x * 64 + bit;
//                 let in1 = y * 5 * 64 + x * 64 + bit;
//                 let in2 =  5 * 5 * 64 + x * 64 + bit;
//                 f_0.push((in1, in2));
//             }
//         }
//     }
//     let mut f_0 = SparseMultilinearExtension::from_evaluations(33, f_0.iter().enumerate().map(|(out, (in1, in2))| {
//         &(out << 22 + in1 << 11 + in2, Fr::ONE)
//     }));

//     // layer 1: copy inputs, array is xor of previous and next, shifted left (within each 64 bit element)
//     let mut f_1_copy = (0..25 * 64).map(|x| (x, x)).collect::<Vec<_>>();
//     let mut f_1_xorshl = Vec::with_capacity(5 * 64);

//     // inputs: all state bits: 25 * 64 < 32 * 64 = (1 << 11)
//     // layer 1-4: xor all columns (array), but also copy inputs. fits in (1 << 11)
//     //   can squeeze this into 3 layers
//     // layer 5: array is now xor of previous and next, also copy inputs. fits in (1 << 11)
//     // layer 5b: rotate array elements (can be done in one step above)
//     // output: xor all columns with corresponding array elements

//     // for each layer:
//     // - a wiring (predicate) polynomial f - what's connected to what, fan-in <= 2
//     // - a gate polynomial (but ours are not uniform?)
//     //   but I can probably have separate wiring for each gate type
//     //   it's still multilinear so should be fine, right?

//     // layers 1:
//     // - g_id(x) -> x          with wiring f_id(x, z) = eq(x, z)
//     // - g_xor(x, y) -> x ^ y  with wiring f_xor(x, y, z) = z is in the array section,
//     //                                                      x, y are corresponding 1st bits of state inputs
//     // layers 2:

// }

pub fn keccak_round(a: &mut [u64; 25], rc: u64) {
    let mut array: [u64; 5] = [0; 5];

    // Theta
    // english: xor all 5 state columns into 5-element array
    for x in 0..5 {
        for y_count in 0..5 {
            let y = y_count * 5;
            array[x] ^= a[x + y];
        }
    }

    for x in 0..5 {
        // for each column:
        //   d = xor previous and next (wrapped) array element, then rotate bits (wrapping)
        //   for each state element: element xor d
        let d = array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
        for y_count in 0..5 {
            let y = y_count * 5;
            a[y + x] ^= d;
        }
    }

    // // Rho and pi
    // let mut last = a[1];
    // for x in 0..24 {
    //     array[0] = a[PI[x]];
    //     a[PI[x]] = last.rotate_left(RHO_OFFSETS[x]);
    //     last = array[0];
    // }

    // // Chi
    // for y_step in 0..5 {
    //     let y = y_step * 5;

    //     for x in 0..5 {
    //         array[x] = a[y + x];
    //     }

    //     for x in 0..5 {
    //         a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
    //     }
    // }

    // // Iota
    // a[0] ^= rc;
}

pub fn keccak_f(a: &mut [u64; 25]) {
    for i in 0..24 {
        keccak_round(a, ROUND_CONSTANTS[i]);
    }
}

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const RHO_OFFSETS: [u32; 24] = [
    1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

#[test]
fn test_keccak_f() {
    //gkr_theta();
    let mut state = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    println!("state {state:x?}");
    keccak_round(&mut state, ROUND_CONSTANTS[0]);
    println!("state {state:x?}");
}

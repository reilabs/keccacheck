use ark_bn254::Fr;
use ark_ff::Field;
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

fn ilog2_ceil(n: u64) -> u32 {
    if n <= 1 {
        return 0;
    }
    64 - (n - 1).leading_zeros()
}

fn u64_to_bits<F: Field>(vec: &[u64]) -> Vec<F> {
    let size = 1 << ilog2_ceil((vec.len() * 64) as u64);
    let mut result = Vec::<F>::with_capacity(size);
    for element in vec {
        let mut element = *element;
        for _ in 0..64 {
            result.push((element % 2).into());
            element >>= 1;
        }
    }

    while result.len() < size {
        result.push(0.into());
    }

    result
}

fn bits_to_u64<F: Field>(vec: &[F]) -> Vec<u64> {
    let size = vec.len() / 64;
    let mut result = Vec::<u64>::with_capacity(size);

    let mut buffer: u64 = 0;
    let mut bit_pos: usize = 0;

    for element in vec {
        let value: u64 = if *element == F::ZERO {
            0
        } else if *element == F::ONE {
            1
        } else {
            panic!("bit not a bit, found {}", element);
        };
        buffer += value << bit_pos;
        bit_pos += 1;

        if bit_pos == 64 {
            result.push(buffer);
            buffer = 0;
            bit_pos = 0;
        }
    }

    result
}

pub fn gkr_theta(input: &[u64], output: &[u64]) {
    // inputs: all state bits: 25 * 64 < 32 * 64 = (1 << 11)
    // layer 1-3: xor all columns (array), but also copy inputs. fits in (1 << 11)
    // layer 4: array is now xor of previous and (next rotated one left), also copy inputs. fits in (1 << 11)
    // output: xor all columns with corresponding array elements
    let state_length = 25 * 64;
    let row_length = 5 * 64;
    let circuit = Circuit::<Fr> {
        inputs: u64_to_bits(&input),
        outputs: u64_to_bits(&output),
        layers: vec![
            Layer::with_builder(11, 11, |out| {
                if out < 25 * 64 {
                    // xor with corresponsing array element
                    let ary_offset = out % row_length;
                    (Gate::Xor, out, state_length + ary_offset)
                } else {
                    // fill with zeros
                    (Gate::Null, 0, 0)
                }
            }),
            Layer::with_builder(11, 11, |out| {
                if out < 25 * 64 {
                    // copy input bits
                    (Gate::Left, out, out)
                } else if out < 30 * 64 {
                    let ary_offset = out - state_length;

                    // TODO: enable rotation again
                    let right = (ary_offset + 64) % row_length;
                    // + 63 (to rotate, unless first bit, then 63 + 64)
                    // let right = if out % 64 == 0 {
                    //     (ary_offset + 63 + 64) % row_length
                    // } else {
                    //     (ary_offset + 63) % row_length
                    // };
                    let left = (ary_offset + 4 * 64) % row_length;
                    (Gate::Xor, left + state_length, right + state_length)
                } else {
                    // fill with zeros
                    (Gate::Null, 0, 0)
                }
            }),
            Layer::with_builder(11, 11, |out| {
                if out < 25 * 64 {
                    // copy input bits
                    (Gate::Left, out, out)
                } else if out < 30 * 64 {
                    // xor row 0, 1, 2, 3, 4
                    let row_4 = (out % row_length) + 4 * row_length;
                    (Gate::Xor, out, row_4)
                } else {
                    // fill with zeros
                    (Gate::Null, 0, 0)
                }
            }),
            Layer::with_builder(11, 12, |out| {
                if out < 25 * 64 {
                    // copy input bits
                    (Gate::Left, out, out)
                } else if out < 30 * 64 {
                    // xor row 0, 1, 2, 3
                    (Gate::Xor, out, out + row_length)
                } else {
                    // fill with zeros
                    (Gate::Null, 0, 0)
                }
            }),
            Layer::with_builder(12, 11, |out| {
                if out < 25 * 64 {
                    // copy input bits
                    (Gate::Left, out, out)
                } else if out < 30 * 64 {
                    // xor row 0 and 1
                    let row_0 = out % row_length;
                    let row_1 = row_0 + row_length;
                    (Gate::Xor, row_0, row_1)
                } else if out < 35 * 64 {
                    // xor row 2 and 3
                    let row_2 = (out % row_length) + 2 * row_length;
                    let row_3 = row_2 + row_length;
                    (Gate::Xor, row_2, row_3)
                } else {
                    // fill with zeros
                    (Gate::Null, 0, 0)
                }
            }),
        ],
    };
    let evaluations = GKR::evaluate(&circuit);
    for (i, layer) in evaluations.iter().enumerate() {
        println!("layer {i}");
        let layer = bits_to_u64(&layer);
        println!("{layer:x?}");
    }

    println!("proving...");
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &circuit);

    // verify proof size
    let rounds = gkr_proof
        .rounds
        .iter()
        .map(|round| {
            for msg in &round.phase1_sumcheck_msgs {
                assert_eq!(msg.evaluations.len(), 3);
            }
            for msg in &round.phase2_sumcheck_msgs {
                assert_eq!(msg.evaluations.len(), 3);
            }
            round.phase1_sumcheck_msgs.len() + round.phase1_sumcheck_msgs.len()
        })
        .collect::<Vec<_>>();

    // 5 layers, 22 inputs each (except for the layer with 2 xors)
    assert_eq!(rounds, vec![22, 22, 22, 24, 22]);

    println!("verifying...");
    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &gkr_proof);

    println!("done.");
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
        //   d = xor previous and (next with bits rotated) (wrapping)
        //   for each state element: element xor d
        // TODO: enable rotation again
        let d = array[(x + 4) % 5] ^ array[(x + 1) % 5]; //.rotate_left(1);
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
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut output = input.clone();
    keccak_round(&mut output, ROUND_CONSTANTS[0]);

    println!("input  {input:x?}");
    println!("output {output:x?}");

    gkr_theta(&input, &output);
}

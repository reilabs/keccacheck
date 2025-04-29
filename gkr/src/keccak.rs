use ark_bn254::Fr;
use ark_sumcheck::{
    gkr::{
        Circuit, GKR, Gate, Layer, LayerGate,
        predicate::{PredicateSum, eq, eq_const, eq_vec, eq_vec_const},
        util::u64_to_bits,
    },
    rng::{Blake2b512Rng, FeedableRNG},
};

// all gates are multiplications
// w0:   36         6
// f1:  /  \      /    \
// w1: 9     4   6      1
// f2: ||    ||/  \     ||
// w2: 3     2     3     1
pub fn gkr_mul() {
    // TODO: make it data-parallel
    let circuit = Circuit::<Fr> {
        inputs: vec![3.into(), 2.into(), 3.into(), 1.into()],
        outputs: vec![36.into(), 6.into()],
        layers: vec![
            Layer::with_builder(1, 2, |out| (Gate::Mul, 2 * out, 2 * out + 1)),
            Layer {
                gates: vec![LayerGate::new(
                    2,
                    2,
                    Gate::Mul,
                    vec![(1, 1, 1), (2, 1, 2), (0, 0, 0), (3, 3, 3)],
                )],
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
    // TODO: make it data-parallel
    let circuit = Circuit::<Fr> {
        inputs: vec![1.into(), 2.into()],
        outputs: vec![24.into(), 9.into()],
        layers: vec![
            Layer {
                gates: vec![
                    LayerGate::new(1, 2, Gate::Mul, vec![(0, 0, 1)]),
                    LayerGate::new(1, 2, Gate::Add, vec![(1, 2, 3)]),
                ],
            },
            Layer {
                gates: vec![LayerGate::new(
                    2,
                    2,
                    Gate::Add,
                    vec![(0, 0, 0), (1, 1, 1), (2, 1, 2), (3, 3, 3)],
                )],
            },
            Layer {
                gates: vec![LayerGate::new(
                    2,
                    1,
                    Gate::Add,
                    vec![(0, 0, 1), (1, 0, 0), (2, 0, 1), (3, 0, 0)],
                )],
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
    // TODO: make it data-parallel
    let circuit = Circuit::<Fr> {
        inputs: vec![1.into(), 0.into(), 1.into(), 0.into()],
        outputs: vec![1.into(), 0.into()],
        layers: vec![
            Layer {
                gates: vec![LayerGate::new(1, 2, Gate::Xor, vec![(0, 0, 1), (1, 2, 3)])],
            },
            Layer {
                gates: vec![LayerGate::new(
                    2,
                    2,
                    Gate::Left,
                    vec![(0, 0, 0), (1, 1, 1), (2, 1, 2), (3, 3, 3)],
                )],
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

                    // + 63 (to rotate, unless first bit, then 63 + 64)
                    let right = if out % 64 == 0 {
                        (ary_offset + 63 + 64) % row_length
                    } else {
                        (ary_offset + 63) % row_length
                    };
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

pub fn keccak_round(a: &mut [u64; 25], _rc: u64) {
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

const _RHO_OFFSETS: [u32; 24] = [
    1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const _PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

pub fn gkr_pred_theta(input: &[u64], output: &[u64]) {
    // inputs: all state bits: 25 * 64 < 32 * 64 = (1 << 11)
    // layer 1-3: xor all columns (array), but also copy inputs. fits in (1 << 11)
    // layer 4: array is now xor of previous and (next rotated one left), also copy inputs. fits in (1 << 11)
    // output: xor all columns with corresponding array elements
    let inputs = 12;
    let outputs = 12;
    let z = |i: u8| i;
    let a = |i: u8| i + outputs as u8;
    let b = |i: u8| i + outputs as u8 + inputs as u8;

    let circuit = Circuit::<Fr> {
        inputs: u64_to_bits(&input),
        outputs: u64_to_bits(&output),
        layers: vec![
            Layer {
                gates: {
                    vec![
                        LayerGate {
                            gate: Gate::Left,
                            wiring: PredicateSum {
                                predicates: vec![eq_vec(&[
                                    z(0)..=z(11),
                                    a(0)..=a(11), // all original state elements are copied to z
                                    b(0)..=b(11),
                                ])],
                                inputs,
                                outputs,
                            },
                        },
                        LayerGate {
                            gate: Gate::XorLeft,
                            wiring: PredicateSum {
                                predicates: vec![
                                    // bits 0..=8 are element offset within a row
                                    // bits 9..=11 are the row number
                                    eq_vec(&[
                                        z(0)..=z(8),
                                        a(0)..=a(8),                   // same element offset for z, a, b
                                        b(0)..=b(8),
                                    ])
                                        * eq_const(z(11), 1)
                                        * eq_const(z(10), 1)           // z stored in the last row of state
                                        * eq_const(z(9), 1)

                                        * eq_const(a(11), 1)
                                        * eq_const(a(10), 1)           // a is xor(0, 1)
                                        * eq_const(a(9), 0)

                                        * eq_const(b(11), 1)
                                        * eq_const(b(10), 1)           // b is xor(2, 3, 4)
                                        * eq_const(b(9), 1),
                                ],
                                inputs,
                                outputs,
                            },
                        },
                    ]
                },
            },
            Layer {
                gates: {
                    vec![
                        LayerGate {
                            gate: Gate::Left,
                            wiring: PredicateSum {
                                predicates: vec![eq_vec(&[
                                    z(0)..=z(11),
                                    a(0)..=a(11), // all original state elements are copied to z
                                    b(0)..=b(11),
                                ])],
                                inputs,
                                outputs,
                            },
                        },
                        LayerGate {
                            gate: Gate::XorLeft,
                            wiring: PredicateSum {
                                predicates: vec![
                                    // bits 0..=8 are element offset within a row
                                    // bits 9..=11 are the row number
                                    eq_vec(&[
                                        z(0)..=z(8),
                                        a(0)..=a(8),                   // same element offset for z, a, b
                                        b(0)..=b(8),
                                    ])
                                        * eq_const(z(11), 1)
                                        * eq_const(z(10), 1)           // z stored in the last row of state
                                        * eq_const(z(9), 1)

                                        * eq_const(a(11), 1)
                                        * eq_const(a(10), 0)           // a is row 4
                                        * eq_const(a(9), 0)

                                        * eq_const(b(11), 1)
                                        * eq_const(b(10), 1)           // b is xor(2, 3)
                                        * eq_const(b(9), 1),
                                ],
                                inputs,
                                outputs,
                            },
                        },
                    ]
                },
            },
            Layer {
                gates: vec![
                    LayerGate {
                        gate: Gate::Left,
                        wiring: PredicateSum {
                            predicates: vec![eq_vec(&[
                                z(0)..=z(11),
                                a(0)..=a(11), // all original state elements are copied to z
                                b(0)..=b(11),
                            ])],
                            inputs,
                            outputs,
                        },
                    },
                    LayerGate {
                        gate: Gate::Xor,
                        wiring: PredicateSum {
                            predicates: vec![
                                // bits 0..=8 are element offset within a row
                                // bits 9..=11 are the row number
                                eq_vec(&[
                                    z(0)..=z(8),
                                    a(0)..=a(8),                   // same element offset for z, a, b
                                    b(0)..=b(8),
                                ])
                                    * eq_const(z(11), 1)
                                    * eq_const(z(10), 1)           // z stored in the last two rows of state
                                    * eq_const(a(11), 0)           // a is always in the first 4 rows of state
                                    * eq_const(b(11), 0)           // b is always in the first 4 rows of state
                                    * eq_const(a(9), 0)            // even rows (x x 0) are a
                                    * eq_const(b(9), 1)            // odd rows (x x 1) are b
                                    * eq(&[a(10), b(10), z(9)]), // z(9) = 0 xors rows 0, 1; z(9) = 1 xors rows 2, 3
                            ],
                            inputs,
                            outputs,
                        },
                    },
                ],
            },
        ],
    };

    println!("proving...");
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &circuit);

    println!("verifying...");
    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &gkr_proof);
}

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

    let mut gkr_input = vec![0; 8 * 8];
    let mut gkr_output = vec![0; 8 * 8];

    for row in 0..8 {
        for col in 0..8 {
            if row < 5 && col < 5 {
                gkr_input[row * 8 + col] = input[row * 5 + col];
                gkr_output[row * 8 + col] = input[row * 5 + col];
            // } else if row == 5 && col < 5 {
            //     gkr_input[row * 8 + col] = 0;
            //     gkr_output[row * 8 + col] = input[2 * 5 + col] ^ input[3 * 5 + col] ^ input[4 * 5 + col];
            } else if row == 6 && col < 5 {
                gkr_input[row * 8 + col] = 0;
                gkr_output[row * 8 + col] = input[0 * 5 + col] ^ input[1 * 5 + col];
            } else if row == 7 && col < 5 {
                gkr_input[row * 8 + col] = 0;
                gkr_output[row * 8 + col] = input[0 * 5 + col]
                    ^ input[1 * 5 + col]
                    ^ input[2 * 5 + col]
                    ^ input[3 * 5 + col]
                    ^ input[4 * 5 + col];
            } else {
                gkr_input[row * 8 + col] = 0;
                gkr_output[row * 8 + col] = 0;
            }
        }
    }
    println!("gkr_input  {gkr_input:x?}");
    println!("gkr_output {gkr_output:x?}");

    gkr_pred_theta(&gkr_input, &gkr_output);
}

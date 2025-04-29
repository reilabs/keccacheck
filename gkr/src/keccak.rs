use ark_bn254::Fr;
use ark_sumcheck::{
    gkr::{
        Circuit, GKR, Gate, Layer, LayerGate,
        predicate::{PredicateSum, eq, eq_const, eq_vec},
        util::u64_to_bits,
    },
    rng::{Blake2b512Rng, FeedableRNG},
};

use crate::keccak_definition::{ROUND_CONSTANTS, keccak_round};

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
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut output = input.clone();
    keccak_round(&mut output, ROUND_CONSTANTS[0]);

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

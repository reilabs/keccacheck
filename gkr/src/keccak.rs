use ark_bn254::Fr;
use ark_sumcheck::{
    gkr::{
        Circuit, GKR, Gate, Instance, Layer, LayerGate,
        compiled::CompiledCircuit,
        predicate::{cmp_gt, cmp_leq, eq, eq_const, eq_vec, rot},
        util::u64_to_bits,
    },
    rng::{Blake2b512Rng, FeedableRNG},
};

use crate::keccak_definition::keccak_round;

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

// Layers: 15, Gates: 67
pub fn gkr_pred(input: &[u64], output: &[u64]) {
    // inputs: all state bits: 25 * 64 < 32 * 64 = (1 << 11)
    // layer 1-3: xor all columns (array), but also copy inputs. fits in (1 << 11)
    // layer 4: array is now xor of previous and (next rotated one left), also copy inputs. fits in (1 << 11)
    // output: xor all columns with corresponding array elements
    let inputs = 12;
    let outputs = 12;
    let z = |i: u8| i;
    let a = |i: u8| i + outputs as u8;
    let b = |i: u8| i + outputs as u8 + inputs as u8;

    let circuit = Circuit {
        input_bits: inputs,
        output_bits: outputs,
        layers: vec![
            // extra layer to copy only the necessary values - we should be able to remove this
            vec![Layer {
                layer_bits: 12,
                gates: vec![LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)])
                        * cmp_leq(&[z(6)..=z(8), a(6)..=a(8), b(6)..=b(8)], &[0, 0, 1])
                        * eq_vec(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)]),
                }],
            }],
            gkr_iota_layers(z, a, b),
            gkr_chi_layers(z, a, b),
            gkr_rho_and_pi_layers(z, a, b),
            gkr_theta_layers(z, a, b),
        ]
        .into_iter()
        .flatten()
        .collect(),
    };

    let instances = vec![Instance::<Fr> {
        inputs: u64_to_bits(&input),
        outputs: u64_to_bits(&output),
    }];

    let compiled = CompiledCircuit::from_circuit(&circuit);

    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);
}

// Layers: 5, Gates: 9
fn gkr_theta_layers(
    z: impl Fn(u8) -> u8,
    a: impl Fn(u8) -> u8,
    b: impl Fn(u8) -> u8,
) -> Vec<Layer> {
    vec![
        Layer {
            layer_bits: 12,
            gates: {
                vec![LayerGate {
                    gate: Gate::Xor,
                    wiring: eq_vec(&[
                                        z(0)..=z(8),
                                        a(0)..=a(8),               // same element offset for z, a, b
                                        b(0)..=b(8),
                                    ])

                                    * cmp_leq(&[
                                        z(9)..=z(11),
                                        a(9)..=a(11),
                                    ], &[1, 0, 1])

                                    * eq_const(b(11), 1)
                                    * eq_const(b(10), 0)           // b is the aux array in the row 0b101
                                    * eq_const(b(9), 1),
                }]
            },
        },
        // aux array = xor(prev, next.rotate_left(1))
        Layer {
            layer_bits: 12,
            gates: {
                vec![
                    LayerGate {
                        gate: Gate::Left,
                        wiring: eq_vec(&[
                            z(0)..=z(11),
                            a(0)..=a(11), // all original state elements are copied to z
                            b(0)..=b(11),
                        ]),
                    },
                    LayerGate {
                        gate: Gate::Xor,
                        wiring: rot(
                                        (z(0)..=z(5), 0, 64),
                                        (a(0)..=a(5), 0, 64),
                                        (b(0)..=b(5), 63, 64),     // rotate_left(1)
                                    )

                                    * rot(
                                        (z(6)..=z(8), 0, 5),
                                        (a(6)..=a(8), 4, 5),       // add 4 mod 5, i.e. select previous element
                                        (b(6)..=b(8), 1, 5),       // add 1 mod 5, i.e. select next element
                                    )

                                    * eq_const(a(11), 1)
                                    * eq_const(a(10), 1)           // a is xor(column)
                                    * eq_const(a(9), 1)

                                    * eq_const(b(11), 1)
                                    * eq_const(b(10), 1)           // b is xor(column)
                                    * eq_const(b(9), 1)

                                    * eq_const(z(11), 1)
                                    * eq_const(z(10), 0)           // z is xor(prev, next) in the row 0b101
                                    * eq_const(z(9), 1),
                    },
                ]
            },
        },
        // Xor the entire column (4 xors, 3 layers) into aux array
        Layer {
            layer_bits: 12,
            gates: {
                vec![
                    LayerGate {
                        gate: Gate::Left,
                        wiring: eq_vec(&[
                            z(0)..=z(11),
                            a(0)..=a(11), // all original state elements are copied to z
                            b(0)..=b(11),
                        ]),
                    },
                    LayerGate {
                        gate: Gate::XorLeft,
                        wiring: eq_vec(&[
                                        z(0)..=z(8),
                                        a(0)..=a(8),                   // same element offset for z, a, b
                                        b(0)..=b(8),
                                    ])
                                        * eq_const(a(11), 1)
                                        * eq_const(a(10), 1)           // a is xor(0, 1)
                                        * eq_const(a(9), 0)

                                        * eq_const(b(11), 1)
                                        * eq_const(b(10), 1)           // b is xor(2, 3, 4)
                                        * eq_const(b(9), 1)

                                        * eq_const(z(11), 1)
                                        * eq_const(z(10), 1)           // z is xor(0, 1, 2, 3, 4) in the last row
                                        * eq_const(z(9), 1),
                    },
                ]
            },
        },
        Layer {
            layer_bits: 12,
            gates: {
                vec![
                    LayerGate {
                        gate: Gate::Left,
                        wiring: eq_vec(&[
                            z(0)..=z(11),
                            a(0)..=a(11), // all original state elements are copied to z
                            b(0)..=b(11),
                        ]),
                    },
                    LayerGate {
                        gate: Gate::XorLeft,
                        wiring: eq_vec(&[
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
                    },
                ]
            },
        },
        Layer {
            layer_bits: 12,
            gates: vec![
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[
                        z(0)..=z(11),
                        a(0)..=a(11), // all original state elements are copied to z
                        b(0)..=b(11),
                    ]),
                },
                LayerGate {
                    gate: Gate::Xor,
                    wiring: eq_vec(&[
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
                },
            ],
        },
    ]
}

// Helper function to convert a u8 value (0-4) into its 3-bit binary representation (msb, mid, lsb)
fn coord_to_3_bits(val: u8) -> (usize, usize, usize) {
    assert!(
        val < 5,
        "Coordinate value must be less than 5 for 3-bit representation"
    );
    (
        ((val >> 2) & 1).into(),
        ((val >> 1) & 1).into(),
        (val & 1).into(),
    )
}

// Function to get (x,y) coordinates in 3-bit binary representation from 1D Keccak lane index k (0-24)
fn k_to_coords_binary(k: usize) -> ((usize, usize, usize), (usize, usize, usize)) {
    assert!(k < 25, "index position must be less than 25 for a 5x5 grid");
    let x_val = (k % 5) as u8;
    let y_val = (k / 5) as u8;
    (coord_to_3_bits(x_val), coord_to_3_bits(y_val))
}

// Layers: 1, Gates: 25
fn gkr_rho_and_pi_layers(
    z: impl Fn(u8) -> u8,
    a: impl Fn(u8) -> u8,
    b: impl Fn(u8) -> u8,
) -> Vec<Layer> {
    let mut gates = vec![
        // copy auxiliary values
        LayerGate {
            gate: Gate::Left,
            wiring: eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)])
                * eq_vec(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)])
                * eq_const(z(8), 1)
                * eq_const(z(7), 1)
                * eq_const(z(6), 1)
                * eq_const(a(8), 1)
                * eq_const(a(7), 1)
                * eq_const(a(6), 1)
                * eq_const(b(8), 1)
                * eq_const(b(7), 1)
                * eq_const(b(6), 1),
        },
        // copy value from position 0,0
        LayerGate {
            gate: Gate::Left,
            wiring: eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)])
                * eq_const(a(6), 0)
                * eq_const(a(7), 0)
                * eq_const(a(8), 0)
                * eq_const(a(9), 0)
                * eq_const(a(10), 0)
                * eq_const(a(11), 0)
                * eq_const(b(6), 0)
                * eq_const(b(7), 0)
                * eq_const(b(8), 0)
                * eq_const(b(9), 0)
                * eq_const(b(10), 0)
                * eq_const(b(11), 0)
                * eq_const(z(6), 0)
                * eq_const(z(7), 0)
                * eq_const(z(8), 0)
                * eq_const(z(9), 0)
                * eq_const(z(10), 0)
                * eq_const(z(11), 0),
        },
    ];

    (1..=24).for_each(|k| {
        let coords = k_to_coords_binary(k);
        let new_coords = k_to_coords_binary(PI[k - 1]);

        gates.push(LayerGate {
            gate: Gate::Left,
            wiring: eq_const(z(11), new_coords.1.0)
                * eq_const(z(10), new_coords.1.1)
                * eq_const(z(9), new_coords.1.2)
                * eq_const(z(8), new_coords.0.0)
                * eq_const(z(7), new_coords.0.1)
                * eq_const(z(6), new_coords.0.2)
                * eq_const(a(11), coords.1.0)
                * eq_const(a(10), coords.1.1)
                * eq_const(a(9), coords.1.2)
                * eq_const(a(8), coords.0.0)
                * eq_const(a(7), coords.0.1)
                * eq_const(a(6), coords.0.2)
                * eq_const(b(11), coords.1.0)
                * eq_const(b(10), coords.1.1)
                * eq_const(b(9), coords.1.2)
                * eq_const(b(8), coords.0.0)
                * eq_const(b(7), coords.0.1)
                * eq_const(b(6), coords.0.2)
                * rot(
                    (z(0)..=z(5), 0, 64),
                    (a(0)..=a(5), (64 - RHO_OFFSETS[k - 1]) as usize, 64),
                    (b(0)..=b(5), 0, 64),
                ),
        });
    });

    vec![Layer {
        layer_bits: 12,
        gates,
    }]
}

// Layers: 8, Gates: 30
fn gkr_chi_layers(z: impl Fn(u8) -> u8, a: impl Fn(u8) -> u8, b: impl Fn(u8) -> u8) -> Vec<Layer> {
    vec![
        Layer {
            layer_bits: 12,
            gates: vec![
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[
                        z(0)..=z(8),
                        a(0)..=a(8), // all original state elements are copied to z
                        b(0)..=b(8),
                    ]) * cmp_leq(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)], &[0, 1, 0]),
                },
                // row index 3
                LayerGate {
                    gate: Gate::Xor,
                    wiring: eq_const(z(11), 0) * eq_const(z(10), 1) * eq_const(z(9), 1)

                            * eq_const(a(11), 0) * eq_const(a(10), 1) * eq_const(a(9), 1)

                            * eq_const(b(11), 1) * eq_const(b(10), 0) * eq_const(b(9), 1)

                            // same x for inputs and outputs
                            * eq_vec(&[z(6)..=z(8), a(6)..=a(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 4
                LayerGate {
                    gate: Gate::Xor,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 0) * eq_const(z(9), 0)

                            * eq_const(a(11), 1) * eq_const(a(10), 0) * eq_const(a(9), 0)

                            // b_y = 5
                            * eq_const(b(11), 1) * eq_const(b(10), 1) * eq_const(b(9), 0)

                            // same x for inputs and outputs
                            * eq_vec(&[z(6)..=z(8), a(6)..=a(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
            ],
        },
        Layer {
            layer_bits: 12,
            gates: vec![
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[
                        z(0)..=z(8),
                        a(0)..=a(8), // all original state elements are copied to z
                        b(0)..=b(8),
                    ]) * cmp_leq(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)], &[0, 0, 1]),
                },
                // row index 3
                LayerGate {
                    gate: Gate::Mul,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 0) * eq_const(z(9), 1)

                            * eq_const(b(11), 1) * eq_const(b(10), 0) * eq_const(b(9), 1)

                            * eq_const(a(11), 0) * eq_const(a(10), 1) * eq_const(a(9), 1)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 2, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 4
                LayerGate {
                    gate: Gate::Mul,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 1) * eq_const(z(9), 0)

                            * eq_const(b(11), 1) * eq_const(b(10), 1) * eq_const(b(9), 0)

                            * eq_const(a(11), 1) * eq_const(a(10), 0) * eq_const(a(9), 0)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 2, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
            ],
        },
        Layer {
            layer_bits: 12,
            gates: vec![
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[
                        z(0)..=z(8),
                        a(0)..=a(8), // all original state elements are copied to z
                        b(0)..=b(8),
                    ]) * cmp_leq(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)], &[0, 0, 1]),
                },
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[
                        z(0)..=z(5),
                        a(0)..=a(5), // all original state elements are copied to z
                        b(0)..=b(5),
                    ]) * cmp_leq(&[z(6)..=z(8), a(6)..=a(8), b(6)..=b(8)], &[0, 0, 1])
                        * cmp_gt(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)], &[0, 0, 1]),
                },
                // NOT A[(x+1)%5, y]
                // row index 3
                LayerGate {
                    gate: Gate::XorLeft,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 0) * eq_const(z(9), 1)
                            // a_x and a_y are constant
                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 1)
                            * eq_const(a(8), 1) * eq_const(a(7), 1) * eq_const(a(6), 1)

                            * eq_const(b(11), 1) * eq_const(b(10), 0) * eq_const(b(9), 1)

                            // z_x and b_x are the same
                            * eq_vec(&[z(6)..=z(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 4
                LayerGate {
                    gate: Gate::XorLeft,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 1) * eq_const(z(9), 0)
                            // a_x and a_y are constant
                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 1)
                            * eq_const(a(8), 1) * eq_const(a(7), 1) * eq_const(a(6), 1)

                            * eq_const(b(11), 1) * eq_const(b(10), 1) * eq_const(b(9), 0)

                            // z_x and b_x are the same
                            * eq_vec(&[z(6)..=z(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
            ],
        },
        Layer {
            layer_bits: 12,
            gates: vec![
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[z(0)..=z(8), a(0)..=a(8), b(0)..=b(8)])
                        * cmp_leq(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)], &[0, 0, 1]),
                },
                // A[(x+1)%5, y]
                // row index 3
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 0) * eq_const(z(9), 1)

                            * eq_const(a(11), 0) * eq_const(a(10), 1) * eq_const(a(9), 1)

                            * eq_const(b(11), 0) * eq_const(b(10), 0) * eq_const(b(9), 0)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 1, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // binds values together
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 4
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 1) * eq_const(z(9), 0)

                            * eq_const(a(11), 1) * eq_const(a(10), 0) * eq_const(a(9), 0)

                            * eq_const(b(11), 0) * eq_const(b(10), 0) * eq_const(b(9), 0)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 1, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // binds values together
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
            ],
        },
        Layer {
            layer_bits: 12,
            gates: vec![
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[z(0)..=z(8), a(0)..=a(8), b(0)..=b(8)])
                        * cmp_gt(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)], &[0, 1, 0]),
                },
                // row index 0
                LayerGate {
                    gate: Gate::Xor,
                    wiring: eq_const(z(11), 0) * eq_const(z(10), 0) * eq_const(z(9), 0)

                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 0)

                            // b_y = 5
                            * eq_const(b(11), 1) * eq_const(b(10), 0) * eq_const(b(9), 1)

                            // same x for inputs and outputs
                            * eq_vec(&[z(6)..=z(8), a(6)..=a(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 1
                LayerGate {
                    gate: Gate::Xor,
                    wiring: eq_const(z(11), 0) * eq_const(z(10), 0) * eq_const(z(9), 1)

                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 1)

                            // b_y = 6
                            * eq_const(b(11), 1) * eq_const(b(10), 1) * eq_const(b(9), 0)

                            // same x for inputs and outputs
                            * eq_vec(&[z(6)..=z(8), a(6)..=a(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 2
                LayerGate {
                    gate: Gate::Xor,
                    wiring: eq_const(z(11), 0) * eq_const(z(10), 1) * eq_const(z(9), 0)

                            * eq_const(a(11), 0) * eq_const(a(10), 1) * eq_const(a(9), 0)

                            // b_y = 7
                            * eq_const(b(11), 1) * eq_const(b(10), 1) * eq_const(b(9), 1)

                            // same x for inputs and outputs
                            * eq_vec(&[z(6)..=z(8), a(6)..=a(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
            ],
        },
        Layer {
            layer_bits: 12,
            gates: vec![
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[
                        z(0)..=z(8),
                        a(0)..=a(8), // all original state elements are copied to z
                        b(0)..=b(8),
                    ]) * cmp_leq(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)], &[0, 0, 1]),
                },
                // row index 0
                LayerGate {
                    gate: Gate::Mul,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 0) * eq_const(z(9), 1)

                            * eq_const(b(11), 1) * eq_const(b(10), 0) * eq_const(b(9), 1)

                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 0)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 2, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 1
                LayerGate {
                    gate: Gate::Mul,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 1) * eq_const(z(9), 0)

                            * eq_const(b(11), 1) * eq_const(b(10), 1) * eq_const(b(9), 0)

                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 1)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 2, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 2
                LayerGate {
                    gate: Gate::Mul,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 1) * eq_const(z(9), 1)

                            * eq_const(b(11), 1) * eq_const(b(10), 1) * eq_const(b(9), 1)

                            * eq_const(a(11), 0) * eq_const(a(10), 1) * eq_const(a(9), 0)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 2, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
            ],
        },
        Layer {
            layer_bits: 12,
            gates: vec![
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[
                        z(0)..=z(8),
                        a(0)..=a(8), // all original state elements are copied to z
                        b(0)..=b(8),
                    ]) * cmp_leq(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)], &[0, 0, 1]),
                },
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[
                        z(0)..=z(5),
                        a(0)..=a(5), // all original state elements are copied to z
                        b(0)..=b(5),
                    ]) * cmp_leq(&[z(6)..=z(8), a(6)..=a(8), b(6)..=b(8)], &[0, 0, 1])
                        * cmp_gt(&[z(9)..=z(11), a(9)..=a(11), b(9)..=b(11)], &[0, 0, 1]),
                },
                // NOT A[(x+1)%5, y]
                // row index 0
                LayerGate {
                    gate: Gate::XorLeft,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 0) * eq_const(z(9), 1)
                            // a_x and a_y are constant
                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 1)
                            * eq_const(a(8), 1) * eq_const(a(7), 1) * eq_const(a(6), 1)
                            // b_y = 5
                            * eq_const(b(11), 1) * eq_const(b(10), 0) * eq_const(b(9), 1)

                            // z_x and b_x are the same
                            * eq_vec(&[z(6)..=z(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 1
                LayerGate {
                    gate: Gate::XorLeft,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 1) * eq_const(z(9), 0)
                            // a_x and a_y are constant
                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 1)
                            * eq_const(a(8), 1) * eq_const(a(7), 1) * eq_const(a(6), 1)

                            * eq_const(b(11), 1) * eq_const(b(10), 1) * eq_const(b(9), 0)

                            // z_x and b_x are the same
                            * eq_vec(&[z(6)..=z(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 2
                LayerGate {
                    gate: Gate::XorLeft,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 1) * eq_const(z(9), 1)
                            // a_x and a_y are constant
                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 1)
                            * eq_const(a(8), 1) * eq_const(a(7), 1) * eq_const(a(6), 1)

                            * eq_const(b(11), 1) * eq_const(b(10), 1) * eq_const(b(9), 1)

                            // z_x and b_x are the same
                            * eq_vec(&[z(6)..=z(8), b(6)..=b(8)])

                            // same offset for values
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
            ],
        },
        Layer {
            layer_bits: 12,
            gates: vec![
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_vec(&[
                        z(0)..=z(11),
                        a(0)..=a(11), // all original state elements are copied to z
                        b(0)..=b(11),
                    ]),
                },
                // A[(x+1)%5, y]
                // row index 0
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 0) * eq_const(z(9), 1)

                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 0)

                            * eq_const(b(11), 0) * eq_const(b(10), 0) * eq_const(b(9), 0)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 1, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // binds values together
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 1
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 1) * eq_const(z(9), 0)

                            * eq_const(a(11), 0) * eq_const(a(10), 0) * eq_const(a(9), 1)

                            * eq_const(b(11), 0) * eq_const(b(10), 0) * eq_const(b(9), 0)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 1, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // binds values together
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
                // row index 2
                LayerGate {
                    gate: Gate::Left,
                    wiring: eq_const(z(11), 1) * eq_const(z(10), 1) * eq_const(z(9), 1)

                            * eq_const(a(11), 0) * eq_const(a(10), 1) * eq_const(a(9), 0)

                            * eq_const(b(11), 0) * eq_const(b(10), 0) * eq_const(b(9), 0)

                            * rot(
                                (z(6)..=z(8), 0, 5),
                                (a(6)..=a(8), 1, 5),
                                (b(6)..=b(8), 0, 5)
                            )

                            // binds values together
                            * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
                },
            ],
        },
    ]
}

// Layers: 1, Gates: 2
fn gkr_iota_layers(z: impl Fn(u8) -> u8, a: impl Fn(u8) -> u8, b: impl Fn(u8) -> u8) -> Vec<Layer> {
    vec![Layer {
        layer_bits: 12,
        gates: vec![
            LayerGate {
                gate: Gate::Left,
                wiring: eq_vec(&[
                            z(0)..=z(5),
                            a(0)..=a(5),
                            b(0)..=b(5),
                        ])
                        // Ensure position is > (0,0).
                        // cmp_gt ensures z, a, and b positions are all > (0,0) and equal to each other.
                        * cmp_gt(&[z(6)..=z(11), a(6)..=a(11), b(6)..=b(11)], &[0, 0, 0, 0, 0, 0]),
            },
            LayerGate {
                gate: Gate::Xor,
                wiring: eq_vec(&[
                            z(0)..=z(5),
                            a(0)..=a(5),
                            b(0)..=b(5),
                        ])
                        // Ensure output z's position IS (0,0)
                        * eq_const(z(6), 0) * eq_const(z(7), 0) * eq_const(z(8), 0) *
                          eq_const(z(9), 0) * eq_const(z(10), 0) * eq_const(z(11), 0)
                        // Ensure input a's position IS (0,0)
                        * eq_const(a(6), 0) * eq_const(a(7), 0) * eq_const(a(8), 0) *
                          eq_const(a(9), 0) * eq_const(a(10), 0) * eq_const(a(11), 0)
                        // Ensure input b's position IS (0,7) for the round constant
                        * eq_const(b(6), 1) * eq_const(b(7), 1) * eq_const(b(8), 1) *
                          eq_const(b(9), 0) * eq_const(b(10), 0) * eq_const(b(11), 0),
            },
        ],
    }]
}

#[test]
fn test_keccak_f() {
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut output = input.clone();
    let rc = ROUND_CONSTANTS[12];
    keccak_round(&mut output, rc);

    let mut gkr_input = vec![0; 8 * 8];
    let mut gkr_output = vec![0; 8 * 8];

    for row in 0..8 {
        for col in 0..8 {
            if row < 5 && col < 5 {
                gkr_input[row * 8 + col] = input[row * 5 + col];
                gkr_output[row * 8 + col] = output[row * 5 + col];
            } else {
                gkr_input[row * 8 + col] = 0;
                gkr_output[row * 8 + col] = 0;
            }
        }
    }

    // Add round constant at position (0,7)
    gkr_input[0 * 8 + 7] = rc;
    // Add max u64 value needed to perform bitwise NOT operation
    gkr_input[1 * 8 + 7] = u64::MAX;

    gkr_pred(&gkr_input, &gkr_output);
}

#[test]
fn test_row_rotation() {
    let inputs = 12;
    let outputs = 12;
    let z = |i: u8| i;
    let a = |i: u8| i + outputs as u8;
    let b = |i: u8| i + outputs as u8 + inputs as u8;

    let circuit = Circuit {
        input_bits: inputs,
        output_bits: outputs,
        layers: vec![Layer {
            layer_bits: 12,
            gates: vec![LayerGate {
                gate: Gate::Left,
                wiring: eq_const(z(9), 1)
                    * eq_const(z(10), 0)
                    * eq_const(z(11), 0)
                    * eq_const(a(9), 0)
                    * eq_const(a(10), 0)
                    * eq_const(a(11), 0)
                    * eq_const(b(9), 0)
                    * eq_const(b(10), 0)
                    * eq_const(b(11), 0)
                    * rot(
                        (z(6)..=z(8), 0, 5),
                        (a(6)..=a(8), 1, 5),
                        (b(6)..=b(8), 0, 5),
                    )
                    * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
            }],
        }],
    };

    let test_input = [
        1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    let expected_output = [
        0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 4, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    let instances = vec![Instance::<Fr> {
        inputs: u64_to_bits(&test_input),
        outputs: u64_to_bits(&expected_output),
    }];

    let compiled = CompiledCircuit::from_circuit(&circuit);

    // Run the test
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);
}

#[test]
fn test_column_rotation() {
    let inputs = 12;
    let outputs = 12;
    let z = |i: u8| i;
    let a = |i: u8| i + outputs as u8;
    let b = |i: u8| i + outputs as u8 + inputs as u8;

    let circuit = Circuit {
        input_bits: inputs,
        output_bits: outputs,
        layers: vec![Layer {
            layer_bits: 12,
            gates: vec![LayerGate {
                gate: Gate::Left,
                wiring: eq_const(z(6), 1)
                    * eq_const(z(7), 0)
                    * eq_const(z(8), 0)
                    * eq_const(a(6), 0)
                    * eq_const(a(7), 0)
                    * eq_const(a(8), 0)
                    * eq_const(b(6), 0)
                    * eq_const(b(7), 0)
                    * eq_const(b(8), 0)
                    * rot(
                        (z(9)..=z(11), 0, 5),
                        (a(9)..=a(11), 1, 5),
                        (b(9)..=b(11), 0, 5),
                    )
                    * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
            }],
        }],
    };

    let test_input = [
        1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0,
        0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    let expected_output = [
        0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    let instances = vec![Instance::<Fr> {
        inputs: u64_to_bits(&test_input),
        outputs: u64_to_bits(&expected_output),
    }];

    let compiled = CompiledCircuit::from_circuit(&circuit);

    // Run the test
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);
}

#[test]
fn test_row_to_column_rotation() {
    let inputs = 12;
    let outputs = 12;
    let z = |i: u8| i;
    let a = |i: u8| i + outputs as u8;
    let b = |i: u8| i + outputs as u8 + inputs as u8;

    let circuit = Circuit {
        input_bits: inputs,
        output_bits: outputs,
        layers: vec![Layer {
            layer_bits: 12,
            gates: vec![LayerGate {
                gate: Gate::Left,
                wiring: eq_const(z(6), 1)
                    * eq_const(z(7), 0)
                    * eq_const(z(8), 0)
                    * eq_const(a(9), 0)
                    * eq_const(a(10), 0)
                    * eq_const(a(11), 0)
                    * eq_const(b(9), 0)
                    * eq_const(b(10), 0)
                    * eq_const(b(11), 0)
                    * rot(
                        (z(9)..=z(11), 0, 5),
                        (a(6)..=a(8), 1, 5),
                        (b(6)..=b(8), 0, 5),
                    )
                    * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
            }],
        }],
    };

    let test_input = [
        1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    let expected_output = [
        0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    let instances = vec![Instance::<Fr> {
        inputs: u64_to_bits(&test_input),
        outputs: u64_to_bits(&expected_output),
    }];

    let compiled = CompiledCircuit::from_circuit(&circuit);

    // Run the test
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);
}

#[test]
fn test_column_to_row_rotation() {
    let inputs = 12;
    let outputs = 12;
    let z = |i: u8| i;
    let a = |i: u8| i + outputs as u8;
    let b = |i: u8| i + outputs as u8 + inputs as u8;

    let circuit = Circuit {
        input_bits: inputs,
        output_bits: outputs,
        layers: vec![Layer {
            layer_bits: 12,
            gates: vec![LayerGate {
                gate: Gate::Left,
                wiring: eq_const(z(9), 0)
                    * eq_const(z(10), 0)
                    * eq_const(z(11), 0)
                    * eq_const(a(6), 1)
                    * eq_const(a(7), 0)
                    * eq_const(a(8), 0)
                    * eq_const(b(6), 0)
                    * eq_const(b(7), 0)
                    * eq_const(b(8), 0)
                    * rot(
                        (z(6)..=z(8), 0, 5),
                        (a(9)..=a(11), 4, 5),
                        (b(9)..=b(11), 0, 5),
                    )
                    * eq_vec(&[z(0)..=z(5), a(0)..=a(5), b(0)..=b(5)]),
            }],
        }],
    };

    let test_input = [
        0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    let expected_output = [
        1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    let instances = vec![Instance::<Fr> {
        inputs: u64_to_bits(&test_input),
        outputs: u64_to_bits(&expected_output),
    }];

    let compiled = CompiledCircuit::from_circuit(&circuit);

    // Run the test
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);
}

#[test]
fn test_value_rotation() {
    let inputs = 12;
    let outputs = 12;
    let z = |i: u8| i;
    let a = |i: u8| i + outputs as u8;
    let b = |i: u8| i + outputs as u8 + inputs as u8;

    let circuit = Circuit {
        input_bits: inputs,
        output_bits: outputs,
        layers: vec![Layer {
            layer_bits: 12,
            gates: vec![LayerGate {
                gate: Gate::Left,
                wiring: rot(
                    (z(0)..=z(5), 0, 64),
                    (a(0)..=a(5), 63, 64),
                    (b(0)..=b(5), 0, 64),
                ) * eq_vec(&[z(6)..=z(11), a(6)..=a(11), b(6)..=b(11)]),
            }],
        }],
    };

    let test_input = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    let expected_output = [
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    let instances = vec![Instance::<Fr> {
        inputs: u64_to_bits(&test_input),
        outputs: u64_to_bits(&expected_output),
    }];

    let compiled = CompiledCircuit::from_circuit(&circuit);

    // Run the test
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);
}

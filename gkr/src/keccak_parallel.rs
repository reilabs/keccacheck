use ark_bn254::Fr;
use ark_sumcheck::{
    gkr::{
        Circuit, GKR, Gate, Instance, Layer, LayerGate,
        compiled::CompiledCircuit,
        predicate::{cmp_leq, eq, eq_const, eq_vec, rot},
        util::u64_to_bits,
    },
    rng::{Blake2b512Rng, FeedableRNG},
};

use crate::keccak_definition::{ROUND_CONSTANTS, keccak_round};

pub fn gkr_pred_theta(instances: &[Instance<Fr>]) {
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
            // keccak_f theta, xor state columns with aux array
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
        ],
    };

    let compiled = CompiledCircuit::from_circuit_batched(&circuit, instances.len());

    // println!("proving...");
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, instances);

    // println!("verifying...");
    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, instances, &gkr_proof);
}

#[test]
fn test_keccak_f() {
    let instances = 4;

    let instance_size = 25;

    let input = (0..(instances * instance_size))
        .map(|x| x as u64)
        .collect::<Vec<_>>();
    let mut output = input.clone();

    for i in 0..instances {
        let output_slice = &mut output[(i * instance_size)..((i + 1) * instance_size)];
        keccak_round(output_slice, ROUND_CONSTANTS[0]);
        // println!("keccak_round {output_slice:x?}");
    }

    let gkr_instance_size = 64;

    let mut gkr_input = vec![0; instances * 8 * 8];
    let mut gkr_output = vec![0; instances * 8 * 8];

    let mut gkr_instances = Vec::with_capacity(instances);

    for i in 0..instances {
        let gkr_input = &mut gkr_input[(i * gkr_instance_size)..((i + 1) * gkr_instance_size)];
        let gkr_output = &mut gkr_output[(i * gkr_instance_size)..((i + 1) * gkr_instance_size)];

        for row in 0..8 {
            for col in 0..8 {
                if row < 5 && col < 5 {
                    gkr_input[row * 8 + col] = input[i * instance_size + row * 5 + col];
                    gkr_output[row * 8 + col] = output[i * instance_size + row * 5 + col];
                } else {
                    gkr_input[row * 8 + col] = 0;
                    gkr_output[row * 8 + col] = 0;
                }
            }
        }

        // println!("gkr_input  {gkr_input:x?}");
        // println!("gkr_output {gkr_output:x?}");

        gkr_instances.push(Instance::<Fr> {
            inputs: u64_to_bits(gkr_input),
            outputs: u64_to_bits(gkr_output),
        });
    }
    gkr_pred_theta(&gkr_instances);
}

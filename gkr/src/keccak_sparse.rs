use ark_bn254::Fr;
use ark_sumcheck::{
    gkr::{Circuit, GKR, Gate, Instance, Layer, compiled::CompiledCircuit, util::u64_to_bits},
    rng::{Blake2b512Rng, FeedableRNG},
};

use crate::keccak_definition::{ROUND_CONSTANTS, keccak_round};

fn gkr_theta(input: &[u64], output: &[u64]) {
    // inputs: all state bits: 25 * 64 < 32 * 64 = (1 << 11)
    // layer 1-3: xor all columns (array), but also copy inputs. fits in (1 << 11)
    // layer 4: array is now xor of previous and (next rotated one left), also copy inputs. fits in (1 << 11)
    // output: xor all columns with corresponding array elements
    let state_length = 25 * 64;
    let row_length = 5 * 64;
    let circuit = Circuit {
        input_bits: 11,
        output_bits: 11,
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

    let instances = vec![Instance::<Fr> {
        inputs: u64_to_bits(&input),
        outputs: u64_to_bits(&output),
    }];

    let compiled = CompiledCircuit::from_circuit(&circuit);

    println!("proving...");
    let mut fs_rng = Blake2b512Rng::setup();
    let gkr_proof = GKR::prove(&mut fs_rng, &compiled, &instances);

    // verify proof size
    let rounds = gkr_proof
        .rounds
        .iter()
        .map(|round| {
            for msg in &round.phase0_sumcheck_msgs {
                assert_eq!(msg.evaluations.len(), 3);
            }
            for msg in &round.phase2_sumcheck_msgs {
                assert_eq!(msg.evaluations.len(), 3);
            }
            round.phase0_sumcheck_msgs.len() + round.phase0_sumcheck_msgs.len()
        })
        .collect::<Vec<_>>();

    // 5 layers, 22 inputs each (except for the layer with 2 xors)
    assert_eq!(rounds, vec![22, 22, 22, 24, 22]);

    println!("verifying...");
    let mut fs_rng = Blake2b512Rng::setup();
    GKR::verify(&mut fs_rng, &circuit, &instances, &gkr_proof);

    println!("done.");
}

#[test]
fn test_keccak_sparse() {
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

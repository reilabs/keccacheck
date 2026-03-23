use std::sync::Once;

use ark_bn254::Fr;
use whir::algebra::fields::Field256;
use whir::parameters::{FoldingFactor, MultivariateParameters, ProtocolParameters, SoundnessType};
use whir::protocols::whir::Config;
use whir::transcript::codecs::Empty;
use whir::transcript::{DomainSeparator, Proof as WhirProof};

use crate::poseidon::hash_engine::POSEIDON2;

static REGISTER_POSEIDON2: Once = Once::new();

pub(crate) fn change_type(f: Fr) -> Field256 {
    Field256::new_unchecked(f.0)
}

pub(crate) fn change_type_vec(f: &[Fr]) -> Vec<Field256> {
    let mut res: Vec<Field256> = Vec::with_capacity(f.len());
    for i in f.iter() {
        res.push(change_type(*i));
    }
    res
}
#[cfg(debug_assertions)]
pub(crate) fn serialize_whir_proof(proof: &WhirProof) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(proof, &mut buf).expect("CBOR serialization failed");
    buf
}

#[cfg(debug_assertions)]
pub(crate) fn deserialize_whir_proof(bytes: &[u8]) -> WhirProof {
    ciborium::from_reader(bytes).expect("CBOR deserialization failed")
}

/// Serialize a WhirProof as a flat byte buffer:
/// [narg_string_len: 8 bytes LE][narg_string bytes][hints_len: 8 bytes LE][hints bytes]
#[cfg(not(debug_assertions))]
pub(crate) fn serialize_whir_proof_flat(proof: &WhirProof) -> Vec<u8> {
    let mut result = Vec::with_capacity(8 + proof.narg_string.len() + 8 + proof.hints.len());
    result.extend_from_slice(&(proof.narg_string.len() as u64).to_le_bytes());
    result.extend_from_slice(&proof.narg_string);
    result.extend_from_slice(&(proof.hints.len() as u64).to_le_bytes());
    result.extend_from_slice(&proof.hints);
    result
}

/// Deserialize a WhirProof from the flat byte layout produced by
/// [serialize_whir_proof_flat]:
/// [narg_string_len: 8 bytes LE][narg_string bytes][hints_len: 8 bytes LE][hints bytes]
#[cfg(not(debug_assertions))]
pub(crate) fn deserialize_whir_proof_flat(data: &[u8]) -> WhirProof {
    let narg_byte_len = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
    let narg_bytes = data[8..8 + narg_byte_len].to_vec();
    let hints_start = 8 + narg_byte_len;
    let hints_byte_len =
        u64::from_le_bytes(data[hints_start..hints_start + 8].try_into().unwrap()) as usize;
    let hints_bytes = data[hints_start + 8..hints_start + 8 + hints_byte_len].to_vec();
    WhirProof {
        narg_string: narg_bytes,
        hints: hints_bytes,
    }
}

pub(crate) fn whir_config(num_vars: usize) -> (Config<Field256>, DomainSeparator<'static, Empty>) {
    REGISTER_POSEIDON2.call_once(crate::poseidon::hash_engine::register);
    let mv_parameters = MultivariateParameters::new(num_vars);
    let whir_params = ProtocolParameters {
        initial_statement: true,
        security_level: 100,
        pow_bits: 20,
        folding_factor: FoldingFactor::ConstantFromSecondRound(2, 4),
        soundness_type: SoundnessType::ProvableList,
        starting_log_inv_rate: 1,
        batch_size: 25,
        hash_id: POSEIDON2,
    };
    let config = Config::new(mv_parameters, &whir_params);
    let ds = DomainSeparator::protocol(&whir_params)
        .session(&"keccacheck-input-coxmmitment")
        .instance(&Empty);
    (config, ds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};

    #[test]
    fn change_type_zero() {
        assert_eq!(change_type(Fr::zero()), Field256::zero());
    }

    #[test]
    fn change_type_one() {
        assert_eq!(change_type(Fr::one()), Field256::one());
    }

    #[test]
    fn change_type_preserves_value() {
        let x = Fr::from(12345u64);
        let y = change_type(x);
        assert_eq!(y, Field256::from(12345u64));
    }

    #[test]
    fn change_type_large_value() {
        // Use a value close to the modulus
        let x = -Fr::one(); // p - 1
        let y = change_type(x);
        assert_eq!(y, -Field256::one());
    }

    #[test]
    fn change_type_preserves_arithmetic() {
        let a = Fr::from(42u64);
        let b = Fr::from(7u64);
        let sum = change_type(a + b);
        let product = change_type(a * b);
        assert_eq!(sum, Field256::from(49u64));
        assert_eq!(product, Field256::from(294u64));
    }
}

use std::sync::Once;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
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

/// Bytes packed per Fr element (248 bits, safely under the 254-bit bn254 modulus).
pub(crate) const BYTES_PER_FR: usize = 31;

/// Pack a byte slice into Fr elements, 31 bytes per element.
pub(crate) fn pack_bytes_to_fr(bytes: &[u8]) -> Vec<Fr> {
    bytes
        .chunks(BYTES_PER_FR)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[..chunk.len()].copy_from_slice(chunk);
            Fr::from_le_bytes_mod_order(&buf)
        })
        .collect()
}

/// Unpack Fr elements back to bytes, recovering exactly `byte_len` bytes.
pub(crate) fn unpack_fr_to_bytes(elements: &[Fr], byte_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(byte_len);
    for fr in elements {
        let bytes_le = fr.into_bigint().to_bytes_le();
        let take = BYTES_PER_FR.min(byte_len - result.len());
        result.extend_from_slice(&bytes_le[..take]);
    }
    result
}

/// Serialize a WhirProof as a flat sequence of Fr elements:
/// [narg_string_len, narg_string_fr_0, ..., hints_len, hints_fr_0, ...]
///
/// Each 32-byte LE chunk in the byte vectors becomes one Fr element.
/// This avoids CBOR overhead and lets the gnark circuit read field elements
/// directly from the proof buffer.
#[cfg(not(debug_assertions))]
pub(crate) fn serialize_whir_proof_flat(proof: &WhirProof) -> Vec<Fr> {
    let narg_frs = pack_bytes_to_fr(&proof.narg_string);
    let hints_frs = pack_bytes_to_fr(&proof.hints);
    let mut result = Vec::with_capacity(2 + narg_frs.len() + hints_frs.len());
    result.push(Fr::from(proof.narg_string.len() as u64));
    result.extend(narg_frs);
    result.push(Fr::from(proof.hints.len() as u64));
    result.extend(hints_frs);
    result
}

/// Deserialize a WhirProof from the flat Fr element layout produced by
/// [serialize_whir_proof_flat].
#[cfg(not(debug_assertions))]
pub(crate) fn deserialize_whir_proof_flat(data: &[Fr]) -> WhirProof {
    let narg_byte_len = fr_to_usize(data[0]);
    let narg_fr_count = narg_byte_len.div_ceil(BYTES_PER_FR);
    let narg_bytes = unpack_fr_to_bytes(&data[1..1 + narg_fr_count], narg_byte_len);
    let hints_start = 1 + narg_fr_count;
    let hints_byte_len = fr_to_usize(data[hints_start]);
    let hints_fr_count = hints_byte_len.div_ceil(BYTES_PER_FR);
    let hints_bytes = unpack_fr_to_bytes(
        &data[hints_start + 1..hints_start + 1 + hints_fr_count],
        hints_byte_len,
    );
    WhirProof {
        narg_string: narg_bytes,
        hints: hints_bytes,
        #[cfg(debug_assertions)]
        pattern: vec![],
    }
}

pub(crate) fn whir_config(num_vars: usize) -> (Config<Field256>, DomainSeparator<'static, Empty>) {
    REGISTER_POSEIDON2.call_once(crate::poseidon::hash_engine::register);
    let mv_parameters = MultivariateParameters::new(num_vars);
    let whir_params = ProtocolParameters {
        initial_statement: true,
        security_level: 128,
        pow_bits: 20,
        folding_factor: FoldingFactor::Constant(4),
        soundness_type: SoundnessType::UniqueDecoding,
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

pub(crate) fn fr_to_usize(f: Fr) -> usize {
    let bytes = f.into_bigint().to_bytes_le();
    u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize
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
    fn pack_unpack_roundtrip_exact() {
        let data = vec![42u8; 31];
        let packed = pack_bytes_to_fr(&data);
        assert_eq!(packed.len(), 1);
        assert_eq!(unpack_fr_to_bytes(&packed, 31), data);
    }

    #[test]
    fn pack_unpack_roundtrip_multi() {
        let data: Vec<u8> = (0..100).collect();
        let packed = pack_bytes_to_fr(&data);
        assert_eq!(packed.len(), 4); // ceil(100/31)
        assert_eq!(unpack_fr_to_bytes(&packed, 100), data);
    }

    #[test]
    fn pack_unpack_empty() {
        let packed = pack_bytes_to_fr(&[]);
        assert_eq!(packed.len(), 0);
        assert_eq!(unpack_fr_to_bytes(&packed, 0), vec![]);
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

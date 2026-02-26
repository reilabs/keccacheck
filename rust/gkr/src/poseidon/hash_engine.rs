//! Poseidon2 hash engine - this allows the poseidon2 permutation to be used by WHIR.
use std::{borrow::Cow, sync::Arc};

use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};
use const_oid::ObjectIdentifier;
use hex_literal::hex;
use whir::{engines::EngineId, hash, hash::Hash, hash::HashEngine};

use super::compress;

/// Register the Poseidon2 hash engine with WHIR's global engine registry.
/// Must be called before any WHIR operations that use Poseidon2.
pub fn register() {
    hash::ENGINES.register(Arc::new(Poseidon2));
}

pub const POSEIDON2: EngineId = EngineId::new(hex!(
    "ab4c810f79ddf2a54e81731f9708236acf5cc2cc35e9c457a43537dc01236bb7"
));

#[derive(Clone, Copy, Debug)]
pub struct Poseidon2;

impl Poseidon2 {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for Poseidon2 {
    fn default() -> Self {
        Self::new()
    }
}

impl HashEngine for Poseidon2 {
    fn name(&self) -> Cow<'_, str> {
        "poseidon2".into()
    }

    fn oid(&self) -> Option<ObjectIdentifier> {
        // Poseidon2 has no OID assigned.
        None
    }

    fn supports_size(&self, size: usize) -> bool {
        size.is_multiple_of(32)
    }

    fn preferred_batch_size(&self) -> usize {
        1
    }

    fn hash_many(&self, size: usize, input: &[u8], output: &mut [Hash]) {
        assert_eq!(
            input.len(),
            size * output.len(),
            "Input length ({}) should be size * output.len() = {size} * {}",
            input.len(),
            output.len()
        );
        assert!(
            size.is_multiple_of(32),
            "Poseidon2 requires input size to be a multiple of 32 bytes, got {size}"
        );

        if size == 0 {
            output.fill(fr_to_hash(compress(&[])));
            return;
        }

        for (chunk, out) in input.chunks_exact(size).zip(output.iter_mut()) {
            let elements: Vec<Fr> = chunk.chunks_exact(32).map(bytes_to_fr).collect();
            *out = fr_to_hash(compress(&elements));
        }
    }
}

/// Interpret 32 little-endian bytes as a standard-form field element.
pub fn bytes_to_fr(bytes: &[u8]) -> Fr {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    Fr::from(BigInt(limbs))
}

/// Write a field element to a `Hash` in standard (non-Montgomery) form.
fn fr_to_hash(fr: Fr) -> Hash {
    let mut bytes = [0u8; 32];
    for (chunk, limb) in bytes.chunks_exact_mut(8).zip(fr.into_bigint().0.iter()) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    Hash(bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::PrimeField;
    use whir::protocols::matrix_commit::Encodable;

    /// Serialize an Fr element to 32 little-endian bytes (standard form).
    fn fr_to_bytes(fr: Fr) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (chunk, limb) in bytes.chunks_exact_mut(8).zip(fr.into_bigint().0.iter()) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn compress_matches_hash_many() {
        let engine = Poseidon2;
        let elements: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64)).collect();

        // Direct compression from field elements.
        let expected = compress(&elements);
        let expected_hash = fr_to_hash(expected);

        // Same elements serialised as bytes, fed through hash_many.
        let mut encoder = Fr::encoder();
        let input_bytes = encoder.encode(&elements);
        let mut output = [Hash([0u8; 32])];
        engine.hash_many(input_bytes.len(), input_bytes, &mut output);

        assert_eq!(output[0], expected_hash);
    }
}

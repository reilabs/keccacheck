mod sponge;

use ark_bn254::Fr;
pub use sponge::Sponge;

pub struct Prover {
    sponge: Sponge,
    pub proof: Vec<Fr>,
}

/// Trait for transcript entities that can generate FS randomness
pub trait RandomnessGenerator {
    fn generate(&mut self) -> Fr;

    fn generate_beta(&mut self, slice: &mut [Fr]) {
        let base: Fr = self.generate();
        let mut power = base;

        slice.iter_mut().for_each(|x| {
            *x = power;
            power *= base;
        });
    }
}

pub struct Verifier<'a> {
    sponge: Sponge,
    proof: &'a [Fr],
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover {
    pub fn new() -> Self {
        Self {
            sponge: Sponge::new(),
            proof: Vec::new(),
        }
    }

    pub fn finish(self) -> Vec<Fr> {
        self.proof
    }

    pub fn write(&mut self, value: Fr) {
        self.sponge.absorb(value);
        self.proof.push(value);
    }

    pub fn absorb(&mut self, value: Fr) {
        self.sponge.absorb(value);
    }
}

impl<'a> Verifier<'a> {
    pub fn new(proof: &'a [Fr]) -> Self {
        Self {
            sponge: Sponge::new(),
            proof,
        }
    }

    pub fn absorb(&mut self, value: Fr) {
        self.sponge.absorb(value);
    }

    pub fn read(&mut self) -> Fr {
        let value = self.reveal();
        self.sponge.absorb(value);
        value
    }

    pub fn reveal(&mut self) -> Fr {
        let (value, tail) = self
            .proof
            .split_first()
            .expect("Ran out of proof elements.");
        self.proof = tail;
        *value
    }
}

impl RandomnessGenerator for Prover {
    fn generate(&mut self) -> Fr {
        self.sponge.squeeze()
    }
}

impl<'a> RandomnessGenerator for Verifier<'a> {
    fn generate(&mut self) -> Fr {
        self.sponge.squeeze()
    }
}

mod sponge;

pub use sponge::Sponge;
use ark_bn254::Fr;

pub struct Prover {
    sponge:    Sponge,
    pub proof: Vec<Fr>,
}

pub struct Verifier<'a> {
    sponge: Sponge,
    proof:  &'a [Fr],
}

impl Prover {
    pub fn new() -> Self {
        Self {
            sponge: Sponge::new(),
            proof:  Vec::new(),
        }
    }

    pub fn finish(self) -> Vec<Fr> {
        self.proof
    }

    pub fn read(&mut self) -> Fr {
        self.sponge.squeeze()
    }

    pub fn write(&mut self, value: Fr) {
        self.sponge.absorb(value);
        self.proof.push(value);
    }

    // Reveal a value to the verifier, but do hash it into the transcript.
    // This is useful for decommitting values.
    pub fn reveal(&mut self, value: Fr) {
        self.proof.push(value);
    }
}

impl<'a> Verifier<'a> {
    pub fn new(proof: &'a [Fr]) -> Self {
        Self {
            sponge: Sponge::new(),
            proof,
        }
    }

    pub fn generate(&mut self) -> Fr {
        self.sponge.squeeze()
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

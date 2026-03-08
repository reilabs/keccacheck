package transcript

import (
	"reilabs/keccacheck/poseidon2"

	"github.com/consensys/gnark/frontend"
)

type Verifier struct {
	sponge Sponge
	Proof  []frontend.Variable
	index  int
}

// NewVerifier initializes a new verifier with a sponge and proof elements.
func NewVerifier(proof []frontend.Variable) *Verifier {
	return &Verifier{
		sponge: *NewSponge(),
		Proof:  proof,
		index:  0,
	}
}

// Generate squeezes a value from the sponge.
func (v *Verifier) Generate(api frontend.API) frontend.Variable {
	return v.sponge.Squeeze(api)
}

// Get a vector of challenges
func (v *Verifier) GenerateVector(api frontend.API, n uint) []frontend.Variable {
	challenges := make([]frontend.Variable, n)
	for i := range challenges {
		challenges[i] = v.Generate(api)
	}
	return challenges
}

// Read a vector of values
func (v *Verifier) ReadVector(api frontend.API, n uint) []frontend.Variable {
	values := make([]frontend.Variable, n)
	for i := range values {
		values[i] = v.Read(api)
	}
	return values
}

// Read reveals the next value and absorbs it into the sponge.
func (v *Verifier) Read(api frontend.API) frontend.Variable {
	value := v.Reveal()
	v.sponge.absorb(api, value)
	return value
}

// Read reveals the next value and absorbs it into the sponge.
func (v *Verifier) Absorb(api frontend.API, value frontend.Variable) frontend.Variable {
	v.sponge.absorb(api, value)
	return value
}

// Reveal gets the next element from the proof slice.
func (v *Verifier) Reveal() frontend.Variable {
	if v.index >= len(v.Proof) {
		panic("Ran out of proof elements.")
	}
	value := v.Proof[v.index]
	v.index++
	return value
}

// HashNode calculates the hash of a slice of children nodes (N-ary).
// It creates a fresh sponge instance to ensure the operation is stateless
// and isolated, which is required for Merkle tree logic.
func HashNode(api frontend.API, children []frontend.Variable) frontend.Variable {
	return poseidon2.Compress(api, children)
}

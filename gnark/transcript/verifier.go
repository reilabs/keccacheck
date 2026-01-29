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
	hasher := NewSponge()
	for _, child := range children {
		hasher.absorb(api, child)
	}

	// Critical: We must force a permutation to mix the absorbed inputs into the state.
	// The standard absorb() only permutes if the rate is filled, but for a
	// hash function, we need a permutation at the end regardless of fill level
	// to protect the input structure.
	poseidon2.Permute16(api, &hasher.State)

	// Rest and Output
	hasher.idx = 0
	return hasher.Squeeze(api)
}

func VerifyMerkleProof(api frontend.API, arity int, leaf frontend.Variable, proof []frontend.Variable, pathIndices []frontend.Variable, rootHash frontend.Variable) {
	currentDigest := leaf

	for i := 0; i < len(pathIndices); i++ {
		// 1. Assemble the children for this level
		children := make([]frontend.Variable, 1+arity)

		// (Logic to arrange currentDigest and siblings based on pathIndices goes here)
		// For simplicity, let's assume we just append them:
		children[0] = currentDigest
		for j := 0; j < arity; j++ {
			children[j+1] = proof[i*arity+j]
		}

		// 2. Hash the children to get the parent
		currentDigest = HashNode(api, children)
	}

	// Check if calculated root matches expected root
	api.AssertIsEqual(currentDigest, rootHash)
}

func VerifyMerkleTreeProofs(
	api frontend.API,
	arity int,
	leaves []frontend.Variable,
	proofs [][]frontend.Variable, // Each element is one full proof (slice of siblings)
	pathIndices [][]frontend.Variable, // Each element is one full path (slice of indices)
	rootHash frontend.Variable,
) {
	// Iterate over every leaf provided
	for i := 0; i < len(leaves); i++ {
		// Delegate the verification to the single-leaf verifier
		VerifyMerkleProof(
			api,
			arity,
			leaves[i],
			proofs[i],
			pathIndices[i],
			rootHash,
		)
	}
}

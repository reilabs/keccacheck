package transcript

import (
	"reilabs/keccacheck/poseidon2"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type Verifier struct {
	sponge    Sponge
	Proof     []frontend.Variable
	index     int
	Hints     []frontend.Variable // Out-of-band hint data (e.g. Merkle siblings), not absorbed into sponge
	hintIndex int
}

// NewVerifier initializes a new verifier with a sponge and proof elements.
func NewVerifier(proof []frontend.Variable) *Verifier {
	return &Verifier{
		sponge: *NewSponge(),
		Proof:  proof,
		index:  0,
	}
}

// NewVerifierWithHints initializes a verifier with both transcript proof elements
// and out-of-band hint data. Hints are read separately and never absorbed into the sponge.
// This mirrors Rust's VerifierState which has both narg_string (transcript) and hints.
func NewVerifierWithHints(proof []frontend.Variable, hints []frontend.Variable) *Verifier {
	return &Verifier{
		sponge: *NewSponge(),
		Proof:  proof,
		index:  0,
		Hints:  hints,
	}
}

// ReadHint reads the next hint value without absorbing into the sponge.
// Mirrors Rust's verifier_state.prover_hint().
func (v *Verifier) ReadHint() frontend.Variable {
	if v.hintIndex >= len(v.Hints) {
		panic("Ran out of hint elements.")
	}
	value := v.Hints[v.hintIndex]
	v.hintIndex++
	return value
}

// ReadHintVector reads n hint values without absorbing into the sponge.
func (v *Verifier) ReadHintVector(n uint) []frontend.Variable {
	values := make([]frontend.Variable, n)
	for i := range values {
		values[i] = v.ReadHint()
	}
	return values
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

func (v *Verifier) ReadBytes(api frontend.API, uapi *uints.BinaryField[uints.U64], n uint) []uints.U8 {
	bytes := make([]uints.U8, n)
	for i := range bytes {
		bytes[i] = v.ReadByte(api, uapi)
	}
	return bytes
}

// Read reveals the next value and absorbs it into the sponge.
func (v *Verifier) Read(api frontend.API) frontend.Variable {
	value := v.Reveal()
	v.sponge.absorb(api, value)
	return value
}

// Read reveals the next value and absorbs it into the sponge.
func (v *Verifier) ReadByte(api frontend.API, uapi *uints.BinaryField[uints.U64]) uints.U8 {
	value := v.RevealByte(api, uapi)
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

// Reveal gets the next element from the proof slice.
func (v *Verifier) RevealByte(api frontend.API, uapi *uints.BinaryField[uints.U64]) uints.U8 {
	if v.index >= len(v.Proof) {
		panic("Ran out of proof elements.")
	}
	value := v.Proof[v.index]
	v.index++

	return uapi.ByteValueOf(value)
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

// verifyMerkleTreeProofs verifies a batch of Merkle membership proofs within a circuit.
//
// For each leaf, it:
//  1. Reconstructs the leaf hash by sequentially hashing its constituent elements.
//  2. Navigates the Merkle tree from the bottom up using the bits of leafIndexes.
//  3. Orders child nodes (left vs. right) at each level using api.Select based on the index bit.
//  4. Asserts that the final computed hash matches the provided rootHash.
//
// Parameters:
//   - leafIndexes: The positions of the leaves in the tree.
//   - leaves: 2D slice where each inner slice contains the data elements of a leaf.
//   - leafSiblingHashes: The immediate sibling hash for the leaf level.
//   - authPaths: The remaining sibling hashes along the path to the root.
//   - rootHash: The expected Merkle root to verify against.
func VerifyMerkleTreeProofs(api frontend.API, uapi *uints.BinaryField[uints.U64], leafIndexes []uints.U64, leaves [][]frontend.Variable, leafSiblingHashes []frontend.Variable, authPaths [][]frontend.Variable, rootHash frontend.Variable) error {
	numOfLeavesProved := len(leaves)

	for i := range numOfLeavesProved {
		// Calculate tree height based on proof length; convert index to bits for path navigation
		treeHeight := len(authPaths[i]) + 1
		leafIndexBits := api.ToBinary(uapi.ToValue(leafIndexes[i]), treeHeight)
		leafSiblingHash := leafSiblingHashes[i]

		// 1. Hash the leaf elements sequentially to compute the initial 'claimedLeafHash'
		claimedLeafHash := HashNode(api, []frontend.Variable{leaves[i][0], leaves[i][1]})
		for x := range len(leaves[i]) - 2 {
			claimedLeafHash = HashNode(api, []frontend.Variable{claimedLeafHash, leaves[i][x+2]})
		}

		// 2. Determine if leaf is left or right child at the bottom level
		dir := leafIndexBits[0]
		xLeftChild := api.Select(dir, leafSiblingHash, claimedLeafHash)
		xRightChild := api.Select(dir, claimedLeafHash, leafSiblingHash)

		// 3. Start building the path upwards
		currentHash := HashNode(api, []frontend.Variable{xLeftChild, xRightChild})

		// 4. Iterate through authentication path (siblings) to reconstruct the root
		for level := 1; level < treeHeight; level++ {
			indexBit := leafIndexBits[level]
			siblingHash := authPaths[i][level-1]

			// Select order (left vs right) based on the index bit at this depth
			dir := api.And(indexBit, 1)
			left := api.Select(dir, siblingHash, currentHash)
			right := api.Select(dir, currentHash, siblingHash)

			currentHash = HashNode(api, []frontend.Variable{left, right})
		}

		// 5. Constrain the calculated hash to equal the known Merkle Root
		api.AssertIsEqual(currentHash, rootHash)
	}
	return nil
}

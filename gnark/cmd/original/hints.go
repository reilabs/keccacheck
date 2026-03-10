package main

import (
	"math/big"
	"reilabs/keccacheck/keccacheck"
	"unsafe"
)

// KeccacheckProveHint reduces output words to input bits
// and verifies that claim by directly accessing the input bits.
func KeccacheckProveHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	ptr := keccacheck.KeccacheckProve(inputs)
	result := (*keccacheck.KeccacheckResult)(ptr)

	proofBytes := unsafe.Slice((*byte)(result.ProofPtr), keccacheck.GKR_PROOF_LEN*32)
	proof := keccacheck.GetBigInt4FromBytes(proofBytes)

	for i := 0; i < keccacheck.GKR_PROOF_LEN; i++ {
		outputs[i].Set(proof[i])
	}

	return nil
}

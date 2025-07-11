package main

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestKeccakVerify(t *testing.T) {
	assert := test.NewAssert(t)

	log_n := 0
	n := 1 << log_n

	inputs := make([]*big.Int, 25*n)
	for i := range inputs {
		inputs[i] = big.NewInt(0)
	}

	// Call prover and get result
	ptr := KeccacheckProve(inputs)
	result := (*KeccacheckResult)(ptr)

	// Convert input and output from result
	input := getBigIntSlice(result.InputPtr, 25*n)
	output := getBigIntSlice(result.OutputPtr, 25*n)

	// Size them to fixed arrays
	var inputSized [25]frontend.Variable
	var outputSized [25]frontend.Variable
	for i := 0; i < 25; i++ {
		inputSized[i] = input[i]
		outputSized[i] = output[i]
	}

	proofSize := 552*(log_n+6) + 2929
	proof := getFSlice(result.ProofPtr, proofSize)

	var proofSized [6241]frontend.Variable
	if len(proof) != 6241 {
		t.Fatalf("Expected proof size 6241, but got %d", len(proof))
	}
	for i := 0; i < 6241; i++ {
		proofSized[i] = proof[i]
	}

	// Prepare the witness and empty circuit
	circuit := KeccakfCircuit{}
	witness := KeccakfCircuit{
		Input:  inputSized,
		Output: outputSized,
		Proof:  proofSized,
	}

	// Assert the prover succeeds with given backend and curve
	assert.ProverSucceeded(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

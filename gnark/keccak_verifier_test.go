package main

import (
	"math/big"
	"testing"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestKeccakVerify(t *testing.T) {
	assert := test.NewAssert(t)

	solver.RegisterHint(KeccacheckProveHint)

	log_n := 0
	n := 1 << log_n

	inputs := make([]*big.Int, 25*n)
	for i := range inputs {
		inputs[i] = big.NewInt(0)
	}

	var inputSized [25]frontend.Variable
	for i := 0; i < 25; i++ {
		inputSized[i] = inputs[i]

	}

	output_ptr := KeccacheckInit(inputs)
	words := unsafe.Slice((*uint64)(output_ptr), 600)

	var outputSized [25]frontend.Variable
	for i := 0; i < 25; i++ {
		outputSized[i] = words[575+i]
	}

	// Prepare the witness and empty circuit
	circuit := KeccakfCircuit{}
	witness := KeccakfCircuit{
		Input:  inputSized,
		Output: outputSized,
	}

	// Assert the prover succeeds with given backend and curve
	assert.ProverSucceeded(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

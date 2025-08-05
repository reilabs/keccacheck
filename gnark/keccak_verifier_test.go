package main

import (
	"math/big"
	"math/rand"
	"testing"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/test"
)

func TestKeccakVerify(t *testing.T) {
	assert := test.NewAssert(t)

	solver.RegisterHint(KeccacheckProveHint)

	inputs := make([]*big.Int, 25*N)
	for i := range inputs {
		inputs[i] = big.NewInt(int64(i))
	}

	output_ptr := KeccacheckInit(inputs)
	words := unsafe.Slice((*uint64)(output_ptr), 600*N)

	inputSized, outputSized, inputDSized, outputDSized := decompose_IO(inputs, words)

	// Prepare the witness and empty circuit
	circuit := KeccakfCircuit{}
	witness := KeccakfCircuit{
		InputD:  inputDSized,
		Input:   inputSized,
		OutputD: outputDSized,
		Output:  outputSized,
	}

	// Assert the prover succeeds with given backend and curve
	assert.ProverSucceeded(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

func TestKeccakVerifyFailing(t *testing.T) {
	assert := test.NewAssert(t)

	solver.RegisterHint(KeccacheckProveHint)

	inputs := make([]*big.Int, 25*N)
	for i := range inputs {
		inputs[i] = big.NewInt(int64(0))
	}

	output_ptr := KeccacheckInit(inputs)
	words := unsafe.Slice((*uint64)(output_ptr), 600*N)
	flip_idx := rand.Intn(25 * N)

	inputs[flip_idx] = big.NewInt(int64(1))
	inputSized, outputSized, inputDSized, outputDSized := decompose_IO(inputs, words)

	circuit := KeccakfCircuit{}
	witness := KeccakfCircuit{
		InputD:  inputDSized,
		Input:   inputSized,
		OutputD: outputDSized,
		Output:  outputSized,
	}

	// Assert the prover succeeds with given backend and curve
	assert.ProverFailed(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

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
		inputs[i] = big.NewInt(rand.Int63())
	}

	output_ptr := KeccacheckInit(inputs)
	outputs := unsafe.Slice((*uint64)(output_ptr), 600*N)

	inputSized, inputDSized, outputSized := initCircuitFields(inputs, outputs)

	circuit := KeccakfCircuit{}
	witness := KeccakfCircuit{
		InputD: inputDSized,
		Input:  inputSized,
		Output: outputSized,
	}

	// Assert the prover succeeds
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
		inputs[i] = big.NewInt(int64(i))
	}

	output_ptr := KeccacheckInit(inputs)
	outputs := unsafe.Slice((*uint64)(output_ptr), 600*N)

	//Randomly change one of the input words
	flip_idx := rand.Intn(25 * N)
	inputs[flip_idx] = big.NewInt(int64(1))

	inputSized, inputDSized, outputSized := initCircuitFields(inputs, outputs)

	circuit := KeccakfCircuit{}
	witness := KeccakfCircuit{
		InputD: inputDSized,
		Input:  inputSized,
		Output: outputSized,
	}

	// Assert the prover fails
	assert.ProverFailed(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

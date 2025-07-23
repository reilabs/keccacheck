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

	inputs := make([]*big.Int, 25*N)
	for i := range inputs {
		inputs[i] = big.NewInt(int64(i))
	}
	var inputDSized [64 * 25 * N]frontend.Variable
	var inputSized [25 * N]frontend.Variable
	// TODO: simplify this
	// inputs are currently instance by instance sequentially
	// But decomposed inputs are stored round by round
	for i := 0; i < 25; i++ {
		for instance := 0; instance < N; instance++ {
			inputSized[instance*25+i] = inputs[instance*25+i]
			w := inputs[instance*25+i]
			for j := 0; j < 64; j++ {
				bit := w.Bit(j)
				inputDSized[64*(i*N+instance)+j] = frontend.Variable(bit)
			}
		}
	}

	output_ptr := KeccacheckInit(inputs)
	words := unsafe.Slice((*uint64)(output_ptr), 600*N)

	var outputSized [64 * 25 * N]frontend.Variable

	for i := 0; i < 25; i++ {
		for instance := 0; instance < N; instance++ {
			w := words[575*N+i*N+instance]
			for j := 0; j < 64; j++ {
				bit := (w >> j) & 1
				flatIndex := 64*(i*N+instance) + j
				outputSized[flatIndex] = frontend.Variable(bit)
			}
		}
	}

	// Prepare the witness and empty circuit
	circuit := KeccakfCircuit{}
	witness := KeccakfCircuit{
		InputD: inputDSized,
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

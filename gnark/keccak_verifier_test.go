package main

import (
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/test"
)

func TestKeccakVerify(t *testing.T) {
	assert := test.NewAssert(t)

	solver.RegisterHint(KeccacheckProveHint)

	inputs, outputs := PrepareTestIO()

	witness := KeccakfCircuit{}
	witness.Input, witness.InputD, witness.Output = initCircuitFields(inputs, outputs)

	circuit := KeccakfCircuit{}

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

	inputs, outputs := PrepareTestIO()

	// Make sure that if keccak(inputs) != outputs
	// Then the prover fails
	flip_idx := rand.Intn(600*N-575*N+1) + 575*N
	outputs[flip_idx] = rand.Uint64()

	witness := KeccakfCircuit{}
	witness.Input, witness.InputD, witness.Output = initCircuitFields(inputs, outputs)

	circuit := KeccakfCircuit{}

	assert.ProverFailed(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

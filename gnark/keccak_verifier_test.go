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

	solver.RegisterHint(GKRProofHint)
	solver.RegisterHint(WhirProofHint)
	solver.RegisterHint(ReadVecHint)
	solver.RegisterHint(ReadHashHint)

	inputs, outputs := PrepareTestIO()

	witness := KeccakfCircuit{}
	witness.Input, witness.Output = initCircuitFieldsWHIR(inputs, outputs)

	var circuit = *NewKeccakfCircuit()

	assert.ProverSucceeded(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

func TestKeccakVerifyFailing(t *testing.T) {
	assert := test.NewAssert(t)

	solver.RegisterHint(GKRProofHint)
	solver.RegisterHint(WhirProofHint)
	solver.RegisterHint(ReadVecHint)
	solver.RegisterHint(ReadHashHint)

	inputs, outputs := PrepareTestIO()

	// Make sure that if keccak(inputs) != outputs
	// Then the prover fails
	flip_idx := rand.Intn(600*N-575*N+1) + 575*N
	outputs[flip_idx] = rand.Uint64()

	witness := KeccakfCircuit{}
	witness.Input, witness.Output = initCircuitFieldsWHIR(inputs, outputs)

	var circuit = *NewKeccakfCircuit()

	assert.ProverFailed(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

package main

import (
	"math/rand"
	"reilabs/keccacheck/keccacheck"
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

	inputs, outputs := keccacheck.PrepareTestIO()

	witness := KeccacheckWhirCircuit{}
	witness.Input, witness.Output = keccacheck.InitCircuitFieldsWHIR(inputs, outputs)

	var circuit = *NewKeccacheckWhirCircuit()

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

	inputs, outputs := keccacheck.PrepareTestIO()

	// Make sure that if keccak(inputs) != outputs
	// Then the prover fails
	flip_idx := rand.Intn(600*keccacheck.N-575*keccacheck.N+1) + 575*keccacheck.N
	outputs[flip_idx] = rand.Uint64()

	witness := KeccacheckWhirCircuit{}
	witness.Input, witness.Output = keccacheck.InitCircuitFieldsWHIR(inputs, outputs)

	var circuit = *NewKeccacheckWhirCircuit()

	assert.ProverFailed(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

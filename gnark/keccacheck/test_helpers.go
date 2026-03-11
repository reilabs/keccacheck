package keccacheck

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// SetupFn prepares a circuit and witness from the given inputs and outputs.
type SetupFn func(inputs []*big.Int, outputs []uint64) (circuit, witness frontend.Circuit)

// AssertVerifySucceeds checks that the prover succeeds with valid keccak IO.
func AssertVerifySucceeds(t *testing.T, setup SetupFn) {
	t.Helper()
	assert := test.NewAssert(t)

	inputs, outputs := PrepareTestIO()
	circuit, witness := setup(inputs, outputs)

	assert.ProverSucceeded(
		circuit,
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

// AssertVerifyFails checks that the prover fails when keccak outputs are corrupted.
func AssertVerifyFails(t *testing.T, setup SetupFn) {
	t.Helper()
	assert := test.NewAssert(t)

	inputs, outputs := PrepareTestIO()

	// Flip a random output value so keccak(inputs) != outputs
	flipIdx := rand.Intn(25*N) + 575*N
	outputs[flipIdx] = rand.Uint64()

	circuit, witness := setup(inputs, outputs)

	assert.ProverFailed(
		circuit,
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

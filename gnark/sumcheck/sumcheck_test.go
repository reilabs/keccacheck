package sumcheck

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type sumcheckCircuit struct {
	ClaimedSum frontend.Variable
	Proof      [2]frontend.Variable
	// Degree and Num_polys are config-only, not part of the circuit
	degree    int `gnark:"-"`
	num_polys int `gnark:"-"`
}

func (c *sumcheckCircuit) Define(api frontend.API) error {
	verifier := NewSCVerifier(c.Proof[:])
	verifier.VerifySumcheck(api, c.num_polys, c.degree, c.ClaimedSum)
	return nil
}

func TestSumcheck(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := sumcheckCircuit{
		degree:    2,
		num_polys: 1,
	}

	witness := sumcheckCircuit{
		ClaimedSum: 15,
		Proof:      [2]frontend.Variable{4, 5},
	}

	assert.ProverSucceeded(
		&circuit,
		&witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

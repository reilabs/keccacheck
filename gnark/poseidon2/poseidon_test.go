package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// --- TESTS BELOW ---

type sboxCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *sboxCircuit) Define(api frontend.API) error {
	y := Sbox(api, c.X)
	api.AssertIsEqual(y, c.Y)
	return nil
}

type doubleCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *doubleCircuit) Define(api frontend.API) error {
	y := Double(api, c.X)
	api.AssertIsEqual(y, c.Y)
	return nil
}

func TestSbox(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit sboxCircuit
	witness := sboxCircuit{
		X: 3,
		Y: 243, // 3^5 = 243
	}

	// Generate poseidon hash using gnark implementation
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

}

func TestDouble(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit doubleCircuit
	witness := doubleCircuit{
		X: 7,
		Y: 14, // 7 * 2 = 14
	}

	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

}

package poseidon2

import (
	"math/big"
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

type Permute3Circuit struct {
	Input  [3]frontend.Variable `gnark:",public"`
	Output [3]frontend.Variable `gnark:",public"`
}

func (c *Permute3Circuit) Define(api frontend.API) error {
	// Make a copy of Input slice to permute
	permuted := make([]frontend.Variable, 3)
	copy(permuted, c.Input[:])

	Permute3(api, permuted) // permute in place

	// Assert permuted equals Output
	for i := 0; i < 3; i++ {
		api.AssertIsEqual(permuted[i], c.Output[i])
	}

	return nil
}

func TestPermute3(t *testing.T) {
	assert := test.NewAssert(t)
	var state [3]frontend.Variable
	for i := 0; i < 3; i++ {
		state[i] = frontend.Variable(uint64(i))
	}

	expectedStrings := [3]string{
		"5297208644449048816064511434384511824916970985131888684874823260532015509555",
		"21816030159894113985964609355246484851575571273661473159848781012394295965040",
		"13940986381491601233448981668101586453321811870310341844570924906201623195336",
	}
	var expected [3]frontend.Variable
	for i := 0; i < 3; i++ {
		n, ok := new(big.Int).SetString(expectedStrings[i], 10)
		if !ok {
			t.Fatalf("failed to parse expected value at index %d", i)
		}
		expected[i] = n
	}

	var circuit Permute3Circuit
	witness := Permute3Circuit{
		Input:  state,
		Output: expected,
	}
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

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

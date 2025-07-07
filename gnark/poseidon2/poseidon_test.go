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

// TODO add tests for Compress function

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
	var permuted [3]frontend.Variable
	copy(permuted[:], c.Input[:])

	Permute3(api, permuted) // permute in place

	// Assert permuted equals Output
	for i := 0; i < 3; i++ {
		api.AssertIsEqual(permuted[i], c.Output[i])
	}

	return nil
}

type Permute16Circuit struct {
	Input  [16]frontend.Variable `gnark:",public"`
	Output [16]frontend.Variable `gnark:",public"`
}

func (c *Permute16Circuit) Define(api frontend.API) error {
	// Make a copy of Input slice to permute
	permuted := make([]frontend.Variable, 16)
	copy(permuted, c.Input[:])

	Permute16(api, permuted) // permute in place

	// Assert permuted equals Output
	for i := 0; i < 16; i++ {
		api.AssertIsEqual(permuted[i], c.Output[i])
	}

	return nil
}

func TestPermute16(t *testing.T) {
	assert := test.NewAssert(t)
	var state [16]frontend.Variable
	for i := 0; i < 16; i++ {
		state[i] = frontend.Variable(uint64(i))
	}

	expectedStrings := [16]string{
		"7913381039332130239696391099451993335431181984785002668304949494341223775274",
		"13114653827862491802574904733838965281638599136692207397625218937112857111034",
		"5260853315038320427224620415642584677122388717694035179209277980943813780924",
		"7095024045008646205239214300853055797853073914974523849403489586109304674318",
		"11664126658871199607513817593804851005031659127482990910815038911508774317102",
		"21691268210223129298713399970686330714477903121168305788892425830857815420367",
		"15407749918419823821950514932508821086098597396159344284212197839468132459424",
		"3700132805016741054511056287749681800817432409246278104503824118777934690609",
		"13475608459764345682938188282460443165916896876560315420064665395458277714687",
		"18987216660139014734696038650605544213230472335532851371054548844179055634758",
		"17098838082363265763018775191456472278582317688982731800988108801795688061056",
		"3704449316190953774036093128903455108907706865492001018359052264170727740578",
		"8303990102165258148989759595771034397853874952332156771392628127282197656348",
		"18627657396274070742089584793052815672287729224897005011410297740742199191244",
		"6607980408076394938800075571563852892263752584185562986216463830821958103371",
		"12353300117943495010938017401947409192192248445045039923330878007229549978485",
	}
	var expected [16]frontend.Variable
	for i := 0; i < 16; i++ {
		n, ok := new(big.Int).SetString(expectedStrings[i], 10)
		if !ok {
			t.Fatalf("failed to parse expected value at index %d", i)
		}
		expected[i] = n
	}

	var circuit Permute16Circuit
	witness := Permute16Circuit{
		Input:  state,
		Output: expected,
	}
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

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

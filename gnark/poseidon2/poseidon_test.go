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

type Compress10000Circuit struct {
	Input  [10000]frontend.Variable `gnark:",public"`
	Output frontend.Variable        `gnark:",public"`
}

func (c *Compress10000Circuit) Define(api frontend.API) error {
	res := Compress(api, c.Input[:])
	api.AssertIsEqual(res, c.Output)
	return nil
}

func TestCompress10000(t *testing.T) {
	assert := test.NewAssert(t)
	var state [10000]frontend.Variable
	for i := 0; i < 10000; i++ {
		state[i] = frontend.Variable(uint64(i))
	}
	outputString := "14886603848044981475714290163318647373226509781142547401218185586086586147802"
	n, ok := new(big.Int).SetString(outputString, 10)
	if !ok {
		t.Fatalf("failed to parse expected value")
	}

	var circuit Compress10000Circuit
	witness := Compress10000Circuit{
		Input:  state,
		Output: n,
	}
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

}

type Compress100Circuit struct {
	Input  [100]frontend.Variable `gnark:",public"`
	Output frontend.Variable      `gnark:",public"`
}

func (c *Compress100Circuit) Define(api frontend.API) error {
	res := Compress(api, c.Input[:])
	api.AssertIsEqual(res, c.Output)
	return nil
}

type Permute16Circuit struct {
	Input  [16]frontend.Variable `gnark:",public"`
	Output [16]frontend.Variable `gnark:",public"`
}

func TestCompress100(t *testing.T) {
	assert := test.NewAssert(t)
	var state [100]frontend.Variable
	for i := 0; i < 100; i++ {
		state[i] = frontend.Variable(uint64(i))
	}
	outputString := "12499924002878240429854338251741815095221048573818181736189831611992454862386"
	n, ok := new(big.Int).SetString(outputString, 10)
	if !ok {
		t.Fatalf("failed to parse expected value")
	}

	var circuit Compress100Circuit
	witness := Compress100Circuit{
		Input:  state,
		Output: n,
	}
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

}

func (c *Permute16Circuit) Define(api frontend.API) error {
	Permute16(api, &c.Input)
	for i := 0; i < 16; i++ {
		api.AssertIsEqual(c.Input[i], c.Output[i])
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

type Permute3Circuit struct {
	Input  [3]frontend.Variable `gnark:",public"`
	Output [3]frontend.Variable `gnark:",public"`
}

func (c *Permute3Circuit) Define(api frontend.API) error {
	Permute3(api, &c.Input)
	for i := 0; i < 3; i++ {
		api.AssertIsEqual(c.Input[i], c.Output[i])
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

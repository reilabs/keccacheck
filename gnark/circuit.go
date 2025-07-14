package main

import (
	"github.com/consensys/gnark/frontend"
)

type KeccakfCircuit struct {
	Input [25]frontend.Variable `gnark:",public"`
}

// Main Verifier circuit definition
func (circuit *KeccakfCircuit) Define(api frontend.API) error {
	state_words, err := api.Compiler().NewHint(KeccacheckInitHint, 600, circuit.Input[:]...)

	if err != nil {
		panic("Failed at keccak initialisation")
	}

	commiter, ok := api.(frontend.Committer)

	if !ok {
		panic("unable to initialise committer")
	}

	r_0, err := commiter.Commit(state_words[575:600]...)

	if err != nil {
		panic("was not able to commit to the outputs")
	}

	hintInputs := append([]frontend.Variable{r_0}, circuit.Input[:]...)
	proof, err := api.Compiler().NewHint(KeccacheckProveHint, 6241, hintInputs...)
	if err != nil {
		panic("failed to generate proof hint")
	}

	VerifyKeccakF(api, 6, circuit.Input[:], state_words[575:600], proof, r_0)
	return nil
}

package main

import (
	"github.com/consensys/gnark/frontend"
)

type KeccakfCircuit struct {
	Input  [25]frontend.Variable `gnark:",public"`
	Output [25]frontend.Variable `gnark:",public"`
}

// Main Verifier circuit definition
func (circuit *KeccakfCircuit) Define(api frontend.API) error {

	committer, ok := api.(frontend.Committer)

	if !ok {
		panic("unable to initialise committer")
	}

	r := make([]frontend.Variable, 6)

	// First commitment: commit to circuit.Output
	var err error
	r[0], err = committer.Commit(circuit.Output[:]...)
	if err != nil {
		return err
	}

	for i := 1; i < 6; i++ {
		r[i], err = committer.Commit(r[i-1])
		if err != nil {
			return err
		}
	}
	if err != nil {
		panic("was not able to commit to the outputs")
	}

	hintInputs := append(r, circuit.Input[:]...)
	proof, err := api.Compiler().NewHint(KeccacheckProveHint, 6241, hintInputs...)
	if err != nil {
		panic("failed to generate proof hint")
	}

	VerifyKeccakF(api, 6, circuit.Input[:], circuit.Output[:], proof, r)
	return nil
}

package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
)

type KeccakfCircuit struct {
	InputD []frontend.Variable `gnark:",secret"`
	Input  []frontend.Variable `gnark:",secret"`
	Output []frontend.Variable `gnark:",public"`
}

func NewKeccakfCircuit() *KeccakfCircuit {
	return &KeccakfCircuit{
		Input:  make([]frontend.Variable, 25*N),
		InputD: make([]frontend.Variable, 64*25*N),
		Output: make([]frontend.Variable, 64*25*N),
	}
}

// Main Verifier circuit definition
func (circuit *KeccakfCircuit) Define(api frontend.API) error {

	committer, ok := api.(frontend.Committer)

	if !ok {
		panic("unable to initialise committer")
	}

	r := make([]frontend.Variable, 6+Log_N)

	// First commitment: commit to circuit.Output
	var err error
	r[0], err = committer.Commit(circuit.Output[:]...)
	if err != nil {
		return err
	}

	for i := 1; i < 6+Log_N; i++ {
		r[i], err = committer.Commit(r[i-1])
		if err != nil {
			return err
		}
	}
	if err != nil {
		panic("was not able to commit to the outputs")
	}

	hintInputs := append(r, circuit.Input[:]...)
	proof, err := api.Compiler().NewHint(KeccacheckProveHint, 552*(6+Log_N)+2929, hintInputs...)
	if err != nil {
		panic("failed to generate proof hint")
	}

	VerifyKeccakF(api, circuit.InputD[:], circuit.Output[:], proof, r)
	return nil
}

func Profile() {
	// default options generate gnark.pprof in current dir
	// use pprof as usual (go tool pprof -http=:8080 gnark.pprof) to read the profile file
	// overlapping profiles are allowed (define profiles inside Define or subfunction to profile
	// part of the circuit only)
	p := profile.Start()
	circuit := *NewKeccakfCircuit()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	p.Stop()

	fmt.Println(p.NbConstraints())
	fmt.Println(p.Top())

}

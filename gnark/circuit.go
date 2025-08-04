package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
)

const N = 1 << Log_N
const Log_N = 3

type KeccakfCircuit struct {
	InputD  [64 * 25 * N]frontend.Variable `gnark:",secret"`
	Input   [25 * N]frontend.Variable      `gnark:",secret"`
	OutputD [64 * 25 * N]frontend.Variable `gnark:",public"`
	Output  [25 * N]frontend.Variable      `gnark:",public"`
}

// Main Verifier circuit definition
func (circuit *KeccakfCircuit) Define(api frontend.API) error {
	proof, err := api.Compiler().NewHint(KeccacheckProveHint, 552*(6+Log_N)+2929, circuit.Input[:]...)
	if err != nil {
		panic("failed to generate proof hint")
	}

	VerifyKeccakF(api, circuit.InputD[:], circuit.OutputD[:], circuit.Output[:], proof)
	return nil
}

func Profile() {
	// default options generate gnark.pprof in current dir
	// use pprof as usual (go tool pprof -http=:8080 gnark.pprof) to read the profile file
	// overlapping profiles are allowed (define profiles inside Define or subfunction to profile
	// part of the circuit only)
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &KeccakfCircuit{})
	p.Stop()

	fmt.Println(p.NbConstraints())
	fmt.Println(p.Top())

}

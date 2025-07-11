package main

import (
	"github.com/consensys/gnark/frontend"
)

type KeccakfCircuit struct {
	Input  [25]frontend.Variable   `gnark:",public"`
	Output [25]frontend.Variable   `gnark:",public"`
	Proof  [6241]frontend.Variable `gnark:"public"`
}

// Main Verifier circuit definition
func (circuit *KeccakfCircuit) Define(api frontend.API) error {
	VerifyKeccakF(api, 6, circuit.Input[:], circuit.Output[:], circuit.Proof[:])
	return nil
}

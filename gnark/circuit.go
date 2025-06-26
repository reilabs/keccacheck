package main

import (
	"github.com/consensys/gnark/frontend"
)

type KeccakfCircuit struct {
	Input  frontend.Variable `gnark:",public"`
	Output frontend.Variable `gnark:",public"`
}

func (circuit *KeccakfCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(circuit.Input, 2), circuit.Output)

	hint, err := api.NewHint(
		KeccacheckHint,
		1,
		circuit.Input,
	)
	c := frontend.Variable(hint[0])
	api.AssertIsEqual(c, circuit.Output)

	if err != nil {
		panic(err)
	}

	return nil
}

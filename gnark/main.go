package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
)

/*
#cgo LDFLAGS: ./libkeccak.a -ldl
#include "./bindings.h"
*/
import "C"

type KeccakfCircuit struct {
	Input  frontend.Variable `gnark:",public"`
	Output frontend.Variable `gnark:",public"`
}

func (circuit *KeccakfCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.Input, circuit.Output)

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

func KeccacheckHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	for i := 0; i < len(outputs); i++ {
		outputs[i] = big.NewInt(int64(C.keccacheck_init()))
	}

	return nil
}

func main() {
	log := logger.Logger()

	log.Info().Msg("initialize Rust prover")
	solver.RegisterHint(KeccacheckHint)

	log.Info().Msg("call frontend.Compile")
	var circuit KeccakfCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	log.Info().Msg("call groth16.Setup")
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	log.Info().Msg("create witness")
	assignment := KeccakfCircuit{}
	assignment.Input = 5
	assignment.Output = 5
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	log.Info().Msg("call groth16.Prove")
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	log.Info().Msg("call groth16.Verify")
	err = groth16.Verify(proof, vk, witness)
	if err != nil {
		panic(err)
	}
}

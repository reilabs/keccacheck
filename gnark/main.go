package main

import (
	"math/big"
	"unsafe"

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

// inputs, outputs are NOT in the montgomery form
func KeccacheckHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	inputBytes := inputs[0].Bytes()
	inputLen := C.uintptr_t(len(inputBytes))
	inputPtr := (*C.uint8_t)(C.CBytes(inputBytes))
	defer C.free(unsafe.Pointer(inputPtr))

	var outLen C.uintptr_t
	retPtr := C.keccacheck_init(inputPtr, inputLen, &outLen)
	defer C.keccacheck_free(retPtr, outLen)

	// Copy the result from C memory to Go []byte
	result := C.GoBytes(unsafe.Pointer(retPtr), C.int(outLen))
	outputs[0] = new(big.Int).SetBytes(result)

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
	assignment.Input = -1
	assignment.Output = -2
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

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

func main() {
	log := logger.Logger()

	log.Info().Msg("initialize Rust prover")
	solver.RegisterHint(KeccacheckInitHint)

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

	// defer KeccacheckFree(assignment.gkrProver)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	log_n := 0
	n := 1 << log_n

	inputs := make([]*big.Int, 25*n)
	for i := range inputs {
		inputs[i] = big.NewInt(0)
	}

	ptr := KeccacheckProve(inputs)
	result := (*KeccacheckResult)(ptr)

	input := getBigIntSlice(result.InputPtr, 25*n)

	var inputSized [25]big.Int

	for i := 0; i < 25; i++ {
		inputSized[i].Set(input[i])
	}

	log.Info().Msg("call groth16.Prove")
	gproof, gerr := groth16.Prove(r1cs, pk, witness)
	if gerr != nil {
		panic(gerr)
	}

	log.Info().Msg("call groth16.Verify")
	witness, err = witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(gproof, vk, witness)
	if err != nil {
		panic(err)
	}
}

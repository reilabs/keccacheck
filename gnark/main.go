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
	assignment.Output = 10
	assignment.gkrProver = KeccacheckInit([]*big.Int{big.NewInt(5)}, []*big.Int{big.NewInt(10)})
	defer KeccacheckFree(assignment.gkrProver)
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
	witness, err = witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, witness)
	if err != nil {
		panic(err)
	}
}

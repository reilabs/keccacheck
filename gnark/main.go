package main

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const N = 1 << Log_N
const Log_N = 3

func main() {

	var circuit KeccakfCircuit

	// Compile the circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Setup
	fmt.Println("Running setup...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	assignment := KeccakfCircuit{}
	solver.RegisterHint(KeccacheckProveHint)

	inputs, outputs := PrepareTestIO()

	assignment.Input, assignment.InputD, assignment.Output = initCircuitFields(inputs, outputs)

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())

	// Prove
	fmt.Printf("Proving starts\n")
	for i := 1; i <= 10; i++ {
		start := time.Now()
		proof, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			panic(err)
		}
		duration := time.Since(start)
		fmt.Printf("Proving time: %s\n", duration)
		start = time.Now()
		_ = groth16.Verify(proof, vk, witness)
		duration = time.Since(start)
		fmt.Printf("Verifying time: %s\n", duration)
	}
}

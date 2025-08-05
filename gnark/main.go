package main

import (
	"fmt"
	"math/big"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

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

	inputs := make([]*big.Int, 25*N)
	for i := range inputs {
		inputs[i] = big.NewInt(int64(i))
	}

	output_ptr := KeccacheckInit(inputs)
	outputs := unsafe.Slice((*uint64)(output_ptr), 600*N)

	inputSized, inputDSized, outputSized := initCircuitFields(inputs, outputs)

	assignment.Input = inputSized
	assignment.InputD = inputDSized
	assignment.Output = outputSized
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

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
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	assignment := KeccakfCircuit{}
	solver.RegisterHint(KeccacheckProveHint)

	inputs := make([]*big.Int, 25*N)
	for i := range inputs {
		inputs[i] = big.NewInt(0)
	}

	var inputDSized [64 * 25 * N]frontend.Variable
	var inputSized [25 * N]frontend.Variable
	for i := 0; i < 25*N; i++ {
		inputSized[i] = inputs[i]
		w := inputs[i]
		for j := 0; j < 64; j++ {
			bit := w.Bit(j)
			inputDSized[64*i+j] = frontend.Variable(bit)
		}
	}

	output_ptr := KeccacheckInit(inputs)
	words := unsafe.Slice((*uint64)(output_ptr), 600*N)

	var outputSized [64 * 25 * N]frontend.Variable

	for i := 0; i < 25; i++ {
		for instance := 0; instance < N; instance++ {
			w := words[575+i]
			for j := 0; j < 64; j++ {
				bit := (w >> j) & 1
				flatIndex := i*N*64 + instance*64 + j
				outputSized[flatIndex] = frontend.Variable(bit)
			}
		}
	}
	assignment.Input = inputSized
	assignment.InputD = inputDSized
	assignment.Output = outputSized
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())

	// Prove
	fmt.Printf("Proving starts\n")
	for i := 1; i <= 10; i++ {
		start := time.Now()
		_, err = groth16.Prove(ccs, pk, witness)
		if err != nil {
			panic(err)
		}
		duration := time.Since(start)
		fmt.Printf("Proving time: %s\n", duration)
	}
}

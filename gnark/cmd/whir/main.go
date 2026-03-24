package main

import (
	"math/big"
	"reilabs/keccacheck/keccacheck"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func main() {
	keccacheck.RunBenchmark(keccacheck.BenchmarkConfig{
		Circuit: NewKeccacheckWhirCircuit(),
		Hints:   []solver.Hint{GKRProofHint, WhirProofHint, AllWhirHintsHint},
		SetupWitness: func(inputs []*big.Int, outputs []uint64) frontend.Circuit {
			a := &KeccacheckWhirCircuit{}
			a.Input, a.Output = keccacheck.InitCircuitFieldsWHIR(inputs, outputs)
			return a
		},
		BeforeProve: ResetProveCache,
	})
}

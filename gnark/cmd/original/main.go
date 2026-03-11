package main

import (
	"math/big"
	"reilabs/keccacheck/keccacheck"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func main() {
	keccacheck.RunBenchmark(keccacheck.BenchmarkConfig{
		Circuit: NewKeccakfCircuit(),
		Hints:   []solver.Hint{KeccacheckProveHint},
		SetupWitness: func(inputs []*big.Int, outputs []uint64) frontend.Circuit {
			a := &KeccakfCircuit{}
			a.Input, a.InputD, a.Output = keccacheck.InitCircuitFields(inputs, outputs)
			return a
		},
	})
}

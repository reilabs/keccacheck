package keccacheck

import (
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// BenchmarkConfig holds the configuration for running a proving benchmark.
type BenchmarkConfig struct {
	Circuit      frontend.Circuit
	SetupWitness func(inputs []*big.Int, outputs []uint64) frontend.Circuit
	Hints        []solver.Hint
	BeforeProve  func() // optional, called before each prove iteration
}

// RunBenchmark compiles, sets up, and benchmarks proving/verifying a circuit.
func RunBenchmark(cfg BenchmarkConfig) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, cfg.Circuit)
	if err != nil {
		panic(err)
	}

	fmt.Println("Running setup...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	for _, h := range cfg.Hints {
		solver.RegisterHint(h)
	}

	inputs, outputs := PrepareTestIO()
	assignment := cfg.SetupWitness(inputs, outputs)
	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	fmt.Printf("Proving starts\n")
	for i := 1; i <= 10; i++ {
		if cfg.BeforeProve != nil {
			cfg.BeforeProve()
		}
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

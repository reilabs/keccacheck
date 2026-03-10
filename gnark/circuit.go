package main

import (
	"fmt"
	"reilabs/keccacheck/whir"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
)

type KeccakfCircuit struct {
	Input  []frontend.Variable `gnark:",secret"`
	Output []frontend.Variable `gnark:",public"`
}

func NewKeccakfCircuit() *KeccakfCircuit {
	return &KeccakfCircuit{
		Input:  make([]frontend.Variable, 25*N),
		Output: make([]frontend.Variable, 25*N),
	}
}

// Maximum output sizes for each proof component hint.
const MaxGKRProofLen = 3034 + 559*NUM_VARS

// Main Verifier circuit definition
func (circuit *KeccakfCircuit) Define(api frontend.API) error {

	committer, ok := api.(frontend.Committer)

	if !ok {
		panic("unable to initialise committer")
	}

	r := make([]frontend.Variable, Log_N)

	// First commitment: commit to circuit.Output
	// If there is only 1 instance, then the output polynomials are constant
	// and no challenge is needed
	var err error
	if Log_N > 0 {
		r[0], err = committer.Commit(circuit.Output[:]...)
		if err != nil {
			return err
		}

		for i := 1; i < Log_N; i++ {
			r[i], err = committer.Commit(r[i-1])
			if err != nil {
				return err
			}
		}
		if err != nil {
			panic("was not able to commit to the outputs")
		}
	}

	hintInputs := append(r, circuit.Input[:]...)

	whirParams := whir.NewParams(whir.NewProtocolConfig(
		25, NUM_VARS,
		whir.ConstantFromSecondRoundFoldingFactor(2, 4),
		whir.ProvableList, 20,
	))

	// Must be set before any hint calls, since the test engine executes hints
	// inline during Define() and getOrComputeProof needs the block types.
	SetHintBlockTypes(whir.ComputeHintBlockTypes(whirParams))

	// Three separate hints, each producing exactly one proof component.
	// They share a cached FFI result internally to avoid redundant computation.
	gkrProof, err := api.Compiler().NewHint(GKRProofHint, MaxGKRProofLen, hintInputs...)
	if err != nil {
		return fmt.Errorf("failed to generate GKR proof hint: %w", err)
	}
	whirProofFrs := whir.ComputeWhirProofFrs(whirParams)
	whirProof, err := api.Compiler().NewHint(WhirProofHint, whirProofFrs, hintInputs...)
	if err != nil {
		return fmt.Errorf("failed to generate WHIR proof hint: %w", err)
	}

	VerifyKeccakFWHIR(api, circuit.Output[:], gkrProof, r, whirProof, hintInputs, whirParams)
	// Needed for the test engine, which executes hints inline during Define().
	ResetProveCache()
	return nil
}

func Profile() {
	// default options generate gnark.pprof in current dir
	// use pprof as usual (go tool pprof -http=:8080 gnark.pprof) to read the profile file
	// overlapping profiles are allowed (define profiles inside Define or subfunction to profile
	// part of the circuit only)
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewKeccakfCircuit())
	p.Stop()

	fmt.Println(p.NbConstraints())
	fmt.Println(p.Top())

}

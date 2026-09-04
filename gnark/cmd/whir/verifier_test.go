package main

import (
	"math/big"
	"reilabs/keccacheck/keccacheck"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func setupWhir(inputs []*big.Int, outputs []uint64) (frontend.Circuit, frontend.Circuit) {
	solver.RegisterHint(GKRProofHint)
	solver.RegisterHint(WhirProofHint)
	solver.RegisterHint(AllWhirHintsHint)

	witness := &KeccacheckWhirCircuit{}
	witness.Input, witness.Output = keccacheck.InitCircuitFieldsWHIR(inputs, outputs)

	circuit := NewKeccacheckWhirCircuit()
	return circuit, witness
}

func TestKeccakVerify(t *testing.T) {
	keccacheck.AssertVerifySucceeds(t, setupWhir)
}

func TestKeccakVerifyFailing(t *testing.T) {
	keccacheck.AssertVerifyFails(t, setupWhir)
}

package main

import (
	"math/big"
	"reilabs/keccacheck/keccacheck"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func setupOriginal(inputs []*big.Int, outputs []uint64) (frontend.Circuit, frontend.Circuit) {
	solver.RegisterHint(KeccacheckProveHint)

	witness := &KeccakfCircuit{}
	witness.Input, witness.InputD, witness.Output = keccacheck.InitCircuitFields(inputs, outputs)

	circuit := NewKeccakfCircuit()
	return circuit, witness
}

func TestKeccakVerify(t *testing.T) {
	keccacheck.AssertVerifySucceeds(t, setupOriginal)
}

func TestKeccakVerifyFailing(t *testing.T) {
	keccacheck.AssertVerifyFails(t, setupOriginal)
}

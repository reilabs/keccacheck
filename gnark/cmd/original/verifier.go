package main

import (
	"reilabs/keccacheck/keccacheck"
	"reilabs/keccacheck/sumcheck"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
)

// VerifyKeccakF verifies a keccak-f permutation using GKR without a polynomial
// commitment scheme. Directly evaluates the input MLEs against the GKR output
// and checks equality in-circuit.
func VerifyKeccakF(api frontend.API, input, output, proof, r []frontend.Variable) {
	verifier := transcript.NewVerifier(proof)
	_, r, iota := keccacheck.VerifyGKR(api, verifier, r, output)
	eval_eq_r := sumcheck.EvalEq(api, r)
	for i := 0; i < 25; i++ {
		start := i * keccacheck.N
		end := start + keccacheck.N
		poly := input[64*start : 64*end]
		eval := sumcheck.EvalMleWithEq(api, poly, eval_eq_r)
		api.AssertIsEqual(eval, iota[i])
	}
}

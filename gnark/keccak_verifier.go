package main

import (
	"math/big"
	"reilabs/keccacheck/sumcheck"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
)

func VerifyKeccakF(api frontend.API, num_vars int, input, output []big.Int, proof []frontend.Variable) {
	instances := 1 << (num_vars - 6)
	verifer := transcript.NewVerifier(proof)

	r := make([]frontend.Variable, num_vars)

	for i := range num_vars {
		r[i] = verifer.Generate(api)
	}

	beta := make([]frontend.Variable, 25)

	for i := range 25 {
		beta[i] = verifer.Generate(api)
	}

	expected_sum := frontend.Variable(0)

	for i := range 25 {
		summand := sumcheck.EvalMle(api, sumcheck.ToPoly(api, output[(i*instances):(i*instances+instances)]), r)
		expected_sum = api.Add(expected_sum, api.Mul(summand, beta[i]))
	}
	sum := verifer.Read(api)

	api.AssertIsEqual(sum, expected_sum)

}

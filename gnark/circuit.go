package main

import (
	"github.com/consensys/gnark/frontend"
)

type KeccakfCircuit struct {
	Input  frontend.Variable `gnark:",public"`
	Output frontend.Variable `gnark:",public"`
}

func evalMle(api frontend.API, mle []frontend.Variable, r []frontend.Variable) frontend.Variable {
	n := len(r)
	size := 1 << n
	if len(mle) != size {
		panic("mle length must be 2^len(r)")
	}

	// Start from the full mle and reduce layer by layer
	coeffs := mle

	for i := 0; i < n; i++ {
		newSize := len(coeffs) / 2
		next := make([]frontend.Variable, newSize)
		oneMinusRi := api.Sub(1, r[i])
		for j := 0; j < newSize; j++ {
			left := api.Mul(oneMinusRi, coeffs[2*j])
			right := api.Mul(r[i], coeffs[2*j+1])
			next[j] = api.Add(left, right)
		}
		coeffs = next
	}

	return coeffs[0]
}

func (circuit *KeccakfCircuit) Define(api frontend.API) error {
	// 1. convert output to binary and treat as a MLE polynomial
	bits := api.ToBinary(circuit.Output, 1600)
	_, err := api.NewHint(
		KeccacheckHint,
		1,
		bits...,
	)

	// 2. evaluate output MLE polynomial on a random value r, store result as alpha
	r := []frontend.Variable{frontend.Variable(1), frontend.Variable(2), frontend.Variable(3), frontend.Variable(4), frontend.Variable(5), frontend.Variable(6)}
	beta := make([]frontend.Variable, 25)
	alpha := frontend.Variable(0)
	for i := 0; i < 25; i++ {
		beta[i] = frontend.Variable(i + 1)
		alpha = api.Add(alpha, api.Mul(beta[i], evalMle(api, bits[i*64:(i+1)*64], r)))
	}

	api.Println("alpha:", alpha)
	_, err = api.NewHint(
		KeccacheckHint,
		1,
		alpha,
	)

	// TODO:
	// 3. obtain GKR proof that alpha is the output of the MLE polynomial
	// 4. recursively verify GKR proof until we obtain a claim on the input bits
	// 5. conver input to binary and treat it as a MLE polynomial
	// 6. evaluate input MLE polynomial on subclaims to check if the entire proof is valid

	api.AssertIsEqual(api.Mul(circuit.Input, 2), circuit.Output)

	// c := frontend.Variable(hint[0])
	// api.AssertIsEqual(c, circuit.Output)

	if err != nil {
		panic(err)
	}

	return nil
}

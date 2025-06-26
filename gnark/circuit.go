package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/poseidon2"
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
			left := api.Mul(oneMinusRi, coeffs[j])
			right := api.Mul(r[i], coeffs[newSize+j])
			next[j] = api.Add(left, right)
		}
		coeffs = next
	}

	return coeffs[0]
}

func (circuit *KeccakfCircuit) Define(api frontend.API) error {
	// 1. convert output to binary and treat as 25 MLE polynomials
	bits := api.ToBinary(circuit.Output, 1600)

	// 2. obtain a pseudo-random value r
	_, err := poseidon2.NewPoseidon2FromParameters(api, 4, 8, 56)
	if err != nil {
		return err
	}
	r := make([]frontend.Variable, 6)
	for i := 0; i < 6; i++ {
		r[i] = frontend.Variable(i + 2)
	}

	// for i := 0; i < 6; i++ {
	// 	h.Reset()
	// 	h.Write(circuit.Output, frontend.Variable(i))
	// 	r[i] = h.Sum()
	// }

	// 3. calculate random linear combination beta of 25 output MLE polynomials
	//    evaluated on a random value r, store result as alpha
	alpha := frontend.Variable(0)
	beta := make([]frontend.Variable, 25)
	for i := 0; i < 25; i++ {
		beta[i] = frontend.Variable(i + 1)
		alpha = api.Add(alpha, api.Mul(beta[i], evalMle(api, bits[i*64:(i+1)*64], r)))
	}

	api.Println("r:")
	api.Println(r...)

	api.Println("alpha:", alpha)

	// TODO:
	// 4. obtain GKR proof that alpha is the output of the MLE polynomial

	_, err = api.NewHint(
		KeccacheckHint,
		1,
		alpha,
	)
	if err != nil {
		return err
	}

	// 5. recursively verify GKR proof until we obtain a claim on the input bits
	// 6. conver input to binary and treat it as a MLE polynomial
	// 7. evaluate input MLE polynomial on subclaims to check if the entire proof is valid

	api.AssertIsEqual(api.Mul(circuit.Input, 2), circuit.Output)

	// c := frontend.Variable(hint[0])
	// api.AssertIsEqual(c, circuit.Output)

	return nil
}

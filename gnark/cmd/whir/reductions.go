package main

import (
	"reilabs/keccacheck/keccacheck"
	"reilabs/keccacheck/sumcheck"
	"reilabs/keccacheck/transcript"
	"reilabs/keccacheck/whir"

	"github.com/consensys/gnark/frontend"
)

// ReduceInputWords verifies the input word reduction.
// Returns inputBRxRy (the final evaluation) and inputBeta.
func ReduceInputWords(
	api frontend.API,
	verifier *transcript.Verifier,
) (frontend.Variable, []frontend.Variable) {
	inputBeta := make([]frontend.Variable, 25)
	for i := range inputBeta {
		inputBeta[i] = verifier.Generate(api)
	}
	inputAlpha := make([]frontend.Variable, keccacheck.Log_N)
	for i := range inputAlpha {
		inputAlpha[i] = verifier.Generate(api)
	}

	inputC := verifier.Read(api)

	// Verify word-level sumcheck
	ic1, inputRx := sumcheck.VerifySumcheck(api, verifier, keccacheck.Log_N, 2, inputC)
	inputWordsRx := verifier.Read(api)
	inputEq := sumcheck.Eq(api, inputAlpha, inputRx)
	api.AssertIsEqual(ic1, api.Mul(inputWordsRx, inputEq))

	// Verify bit-level sumcheck
	ic2, inputRy := sumcheck.VerifySumcheck(api, verifier, 6, 2, inputWordsRx)
	inputBRxRy := verifier.Read(api)
	powers := keccacheck.PowersOfTwo()
	inputPowersEval := sumcheck.EvalMle(api, powers, inputRy)
	api.AssertIsEqual(ic2, api.Mul(inputPowersEval, inputBRxRy))

	return inputBRxRy, inputBeta
}

// VerifyBinaryCheck verifies that the input bits are boolean.
// Returns the batched binary evaluation and the binary beta coefficients.
func VerifyBinaryCheck(
	api frontend.API,
	verifier *transcript.Verifier,
	numVars int,
) (frontend.Variable, []frontend.Variable) {
	binaryBeta := make([]frontend.Variable, 25)
	for i := range binaryBeta {
		binaryBeta[i] = verifier.Generate(api)
	}
	binaryAlpha := make([]frontend.Variable, numVars)
	for i := range binaryAlpha {
		binaryAlpha[i] = verifier.Generate(api)
	}

	// Binary sumcheck: degree 3, starting sum = 0 (input bits are boolean)
	binaryFinalVal, binaryRx := sumcheck.VerifySumcheck(api, verifier, numVars, 3, frontend.Variable(0))

	// Read 25 individual evaluations at binaryRx
	binaryEvals := make([]frontend.Variable, 25)
	for i := range binaryEvals {
		binaryEvals[i] = verifier.Read(api)
	}

	// Verify: finalVal == eq(binaryAlpha, binaryRx) * sum_j(binaryBeta[j] * evals[j] * (1 - evals[j]))
	binaryEqVal := sumcheck.Eq(api, binaryAlpha, binaryRx)
	binaryChecksum := frontend.Variable(0)
	for j := 0; j < 25; j++ {
		term := api.Mul(binaryBeta[j], api.Mul(binaryEvals[j], api.Sub(1, binaryEvals[j])))
		binaryChecksum = api.Add(binaryChecksum, term)
	}
	api.AssertIsEqual(binaryFinalVal, api.Mul(binaryEqVal, binaryChecksum))

	// Compute batched binary evaluation
	binaryBatchedEval := frontend.Variable(0)
	for j := 0; j < 25; j++ {
		binaryBatchedEval = api.Add(binaryBatchedEval, api.Mul(binaryBeta[j], binaryEvals[j]))
	}

	return binaryBatchedEval, binaryBeta
}

// CombineClaims reads lane evaluations, verifies the round/binary/input claims,
// and returns the combined WHIR ML constraints.
func CombineClaims(
	api frontend.API,
	verifier *transcript.Verifier,
	outputBeta []frontend.Variable,
	iota []frontend.Variable,
	binaryBatchedEval frontend.Variable,
	binaryBeta []frontend.Variable,
	inputBRxRy frontend.Variable,
	inputBeta []frontend.Variable,
) []whir.MLConstraint {
	// Read 75 lane evaluations (25 lanes × 3 claim points)
	laneEvals := make([][3]frontend.Variable, 25)
	for k := 0; k < 25; k++ {
		laneEvals[k] = [3]frontend.Variable{
			verifier.Read(api),
			verifier.Read(api),
			verifier.Read(api),
		}
	}

	// Round claim: sum_k outputBeta[k] * laneEvals[k][0] == sum_k outputBeta[k] * iota[k]
	roundClaim := frontend.Variable(0)
	expectedRound := frontend.Variable(0)
	for k := 0; k < 25; k++ {
		roundClaim = api.Add(roundClaim, api.Mul(outputBeta[k], laneEvals[k][0]))
		expectedRound = api.Add(expectedRound, api.Mul(outputBeta[k], iota[k]))
	}
	api.AssertIsEqual(roundClaim, expectedRound)

	// Binary claim: sum_k binaryBeta[k] * laneEvals[k][1] == binaryBatchedEval
	binaryClaim := frontend.Variable(0)
	for k := 0; k < 25; k++ {
		binaryClaim = api.Add(binaryClaim, api.Mul(binaryBeta[k], laneEvals[k][1]))
	}
	api.AssertIsEqual(binaryClaim, binaryBatchedEval)

	// Input claim: sum_k inputBeta[k] * laneEvals[k][2] == inputBRxRy
	inputClaim := frontend.Variable(0)
	for k := 0; k < 25; k++ {
		inputClaim = api.Add(inputClaim, api.Mul(inputBeta[k], laneEvals[k][2]))
	}
	api.AssertIsEqual(inputClaim, inputBRxRy)

	// Build combined WHIR constraints
	gamma := verifier.Generate(api)
	gamma2 := api.Mul(gamma, gamma)

	constraints := make([]whir.MLConstraint, 25)
	for k := 0; k < 25; k++ {
		constraints[k] = whir.MLConstraint{
			Evaluation: api.Add(
				laneEvals[k][0],
				api.Add(
					api.Mul(gamma, laneEvals[k][1]),
					api.Mul(gamma2, laneEvals[k][2]),
				),
			),
		}
	}
	return constraints
}

package whir

import (
	"math/bits"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// It combines multiple polynomial evaluation claims into a single claim using
// Random Linear Combination (RLC) and runs the initial rounds of the Whir sumcheck.
//
// Parameters:
//   - batchingRandomness: The challenge scalar (alpha) used to fold batched polynomials.
//   - linearStatementEvaluations: Evaluations of the multilinear polynomials.
func initialSumcheck(
	api frontend.API,
	v *transcript.Verifier,
	batchingRandomness frontend.Variable,
	initialOODQueries []frontend.Variable,
	initialOODAnswers []frontend.Variable,
	whirParams WHIRParams,
	linearStatementEvaluations [][]frontend.Variable,
) (InitialSumcheckData, frontend.Variable, []frontend.Variable, error) {

	// 1. Generate random coefficients (beta) from the transcript for combining OOD answers
	// and linear statement evaluations into a single value.
	initialCombinationRandomness, err := GenerateCombinationRandomness(api, v, len(initialOODAnswers)+len(linearStatementEvaluations[0]))
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	// 2. Collapse the batch of linear statement evaluations into a single set of evaluations.
	// We compute: Combined[k] = Sum( Eval[j][k] * alpha^j )
	// This reduces the verification of 'batch_size' polynomials to a single virtual polynomial.
	combinedLinearStatementEvaluations := make([]frontend.Variable, len(linearStatementEvaluations[0])) //[0, 1, 2]
	for evaluationIndex := range len(linearStatementEvaluations[0]) {
		sum := frontend.Variable(0)
		multiplier := frontend.Variable(1)
		for j := range len(linearStatementEvaluations) {
			sum = api.Add(sum, api.Mul(linearStatementEvaluations[j][evaluationIndex], multiplier))
			multiplier = api.Mul(multiplier, batchingRandomness) // Power of alpha increases with batch index
		}
		combinedLinearStatementEvaluations[evaluationIndex] = sum
	}

	// 3. Combine the initial OOD answers and the newly combined statement evaluations
	// into a single target value using the combination randomness generated in step 1.
	OODAnswersAndStatmentEvaluations := append(initialOODAnswers, combinedLinearStatementEvaluations...)
	lastEval := DotProduct(api, initialCombinationRandomness, OODAnswersAndStatmentEvaluations)

	// 4. Run the core Whir sumcheck rounds to reduce the claim further.
	// This updates the 'lastEval' to the value claimed at the end of these rounds.
	initialSumcheckFoldingRandomness, lastEval, err := runWhirSumcheckRounds(api, lastEval, v, whirParams.FoldingFactorArray[0], 3)
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	return InitialSumcheckData{
		InitialOODQueries:            initialOODQueries,
		InitialCombinationRandomness: initialCombinationRandomness,
	}, lastEval, initialSumcheckFoldingRandomness, nil
}

// parseBatchedCommitment reads the Prover's commitments and generates Verifier challenges
// via the Fiat-Shamir heuristic
func parseBatchedCommitment(v *transcript.Verifier, api frontend.API, whir_params WHIRParams) (ParsedCommitment, error) {
	// 1. Read the Merkle Root hash committed by the prover.
	rootHash := v.Read(api)

	// 2. Generate Out-Of-Domain (OOD) query points (challenges) from the transcript.
	oodPoints := v.GenerateVector(api, 1)
	oodAnswers := make([][]frontend.Variable, whir_params.BatchSize)

	// 3. Read the Prover's answers to the OOD queries for the entire batch.
	for i := range whir_params.BatchSize {
		oodAnswer := v.ReadVector(api, 1)

		oodAnswers[i] = oodAnswer
	}

	commitment := ParsedCommitment{
		Root:               rootHash,
		oodPoints:          oodPoints,
		oodAnswers:         oodAnswers,
		batchingRandomness: v.GenerateVector(api, 1),
	}
	return commitment, nil
}

// generateFinalCoefficientsAndRandomnessPoints handles the final phase of the protocol,
// usually associated with the STIR (or FRI-like) folding finalization.
func generateFinalCoefficientsAndRandomnessPoints(api frontend.API, v *transcript.Verifier, whir_params WHIRParams, circuit Merkle, uapi *uints.BinaryField[uints.U64], domainSize int, expDomainGenerator frontend.Variable) ([]frontend.Variable, []frontend.Variable, error) {
	// 1. Read the final coefficients sent by the prover.
	finalCoefficients := v.GenerateVector(api, 1<<whir_params.FinalSumcheckRounds)

	// 3. Generate the final query points (indices) for the STIR protocol.
	// These determine which leaves of the Merkle tree will be opened.
	finalRandomnessPoints, err := GenerateStirChallengePoints(api, v, whir_params.FinalQueries, circuit.LeafIndexes[len(circuit.LeafIndexes)-1], domainSize, uapi, expDomainGenerator, whir_params.FoldingFactorArray[len(whir_params.FoldingFactorArray)-1])
	if err != nil {
		return nil, nil, err
	}

	return finalCoefficients, finalRandomnessPoints, nil
}

// rlcBatchedLeaves collapses a wide leaf structure (representing multiple batched polynomials)
// into a smaller size using Random Linear Combination.
//
// Input:
//   - leaves: A 2D array where each row represents a path or group of leaves.
//   - foldSize: The target size of the folded leaf (e.g., folding factor of the Merkle tree).
//   - batchSize: The number of polynomials being batched together.
//   - B: The folding randomness (scalar).
//
// Operation:
//
//	out[j] = sum_{b=0..batchSize-1} (B^b * leaf[b*foldSize + j])
//
// This effectively compresses the batch dimension, allowing the verifier to check
// a single folded Merkle path instead of 'batchSize' distinct paths.
func rlcBatchedLeaves(api frontend.API, leaves [][]frontend.Variable, foldSize int, batchSize int, B frontend.Variable) [][]frontend.Variable {
	collapsed := make([][]frontend.Variable, len(leaves))
	for i := range leaves {
		collapsed[i] = make([]frontend.Variable, foldSize)
		for j := 0; j < foldSize; j++ {
			sum := frontend.Variable(0)
			pow := frontend.Variable(1)

			// Iterate through the batch, accumulating the weighted sum
			for b := 0; b < batchSize; b++ {
				idx := b*foldSize + j
				sum = api.Add(sum, api.Mul(pow, leaves[i][idx]))
				pow = api.Mul(pow, B) // Scale power: B^0, B^1, B^2...
			}
			collapsed[i][j] = sum
		}
	}
	return collapsed
}

// GenerateCombinationRandomness generates the combination randomness for the given parameters.
// It generates a random scalar and expands it to the required length.
func GenerateCombinationRandomness(api frontend.API, v *transcript.Verifier, randomnessLength int) ([]frontend.Variable, error) {
	combRandomness := v.Generate(api)
	combinationRandomness := ExpandRandomness(api, combRandomness, randomnessLength)
	return combinationRandomness, nil

}

func runWhirSumcheckRounds(
	api frontend.API,
	lastEval frontend.Variable,
	verifier *transcript.Verifier,
	foldingFactor int,
	polynomialDegree int,
) ([]frontend.Variable, frontend.Variable, error) {
	foldingRandomness := make([]frontend.Variable, foldingFactor)

	for i := range foldingFactor {
		sumcheckPolynomial := verifier.ReadVector(api, uint(polynomialDegree))
		foldingRandomnessTemp := verifier.Generate(api)
		foldingRandomness[i] = foldingRandomnessTemp
		CheckSumOverBool(api, lastEval, sumcheckPolynomial)
		lastEval = EvaluateQuadraticPolynomialFromEvaluationList(api, sumcheckPolynomial, foldingRandomness[i])
	}
	return foldingRandomness, lastEval, nil
}

// GenerateStirChallengePoints generates the stir challenge points for the given parameters.
// It calculates the folding factor power and generates the stir challenges for the given leaf indexes.
func GenerateStirChallengePoints(
	api frontend.API,
	v *transcript.Verifier,
	NQueries int,
	leafIndexes []uints.U64,
	domainSize int,
	uapi *uints.BinaryField[uints.U64],
	expDomainGenerator frontend.Variable,
	foldingFactor int,
) ([]frontend.Variable, error) {
	foldingFactorPower := 1 << foldingFactor
	finalIndexes, err := getStirChallenges(api, v, NQueries, domainSize, foldingFactorPower)
	if err != nil {
		return nil, err
	}

	err = IsEqual(api, uapi, finalIndexes, leafIndexes)
	if err != nil {
		return nil, err
	}

	finalRandomnessPoints := make([]frontend.Variable, len(leafIndexes))

	for index := range leafIndexes {
		finalRandomnessPoints[index] = Exponent(api, uapi, expDomainGenerator, leafIndexes[index])
	}

	return finalRandomnessPoints, nil
}

func getStirChallenges(
	api frontend.API,
	verifier *transcript.Verifier,
	numQueries int,
	domainSize int,
	foldingFactorPower int,
) ([]frontend.Variable, error) {

	foldedDomainSize := domainSize / foldingFactorPower
	bitLength := bits.Len(uint(foldedDomainSize - 1))

	indexes := make([]frontend.Variable, numQueries)

	for i := 0; i < numQueries; i++ {
		challenge := verifier.Generate(api)
		challengeBits := api.ToBinary(challenge)
		indexes[i] = api.FromBinary(challengeBits[:bitLength]...)
	}

	return indexes, nil
}

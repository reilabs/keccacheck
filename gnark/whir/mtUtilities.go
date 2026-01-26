package whir

import (
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

// initialSumcheck performs the initial phase of the sumcheck protocol.
// It combines multiple polynomial evaluation claims into a single claim using
// Random Linear Combination (RLC) and runs the initial rounds of the Whir sumcheck.
//
// Parameters:
//   - batchingRandomness: The challenge scalar (alpha) used to fold batched polynomials.
//   - linearStatementEvaluations: Evaluations of the multilinear polynomials.
func initialSumcheck(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	batchingRandomness frontend.Variable,
	initialOODQueries []frontend.Variable,
	initialOODAnswers []frontend.Variable,
	whirParams WHIRParams,
	linearStatementEvaluations [][]frontend.Variable,
) (InitialSumcheckData, frontend.Variable, []frontend.Variable, error) {

	// 1. Generate random coefficients (beta) from the transcript for combining OOD answers
	// and linear statement evaluations into a single value.
	initialCombinationRandomness, err := GenerateCombinationRandomness(api, arthur, len(initialOODAnswers)+len(linearStatementEvaluations[0]))
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
	initialSumcheckFoldingRandomness, lastEval, err := runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[0], 3)
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	return InitialSumcheckData{
		InitialOODQueries:            initialOODQueries,
		InitialCombinationRandomness: initialCombinationRandomness,
	}, lastEval, initialSumcheckFoldingRandomness, nil
}

// parseBatchedCommitment reads the Prover's commitments and generates Verifier challenges
// via the Fiat-Shamir heuristic (using the 'arthur' transcript).
func parseBatchedCommitment(arthur gnarkNimue.Arthur, whir_params WHIRParams) (frontend.Variable, frontend.Variable, []frontend.Variable, [][]frontend.Variable, error) {
	// 1. Read the Merkle Root hash committed by the prover.
	rootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(rootHash); err != nil {
		return nil, nil, nil, [][]frontend.Variable{}, err
	}

	// 2. Generate Out-Of-Domain (OOD) query points (challenges) from the transcript.
	oodPoints := make([]frontend.Variable, 1)
	oodAnswers := make([][]frontend.Variable, whir_params.BatchSize)
	if err := arthur.FillChallengeScalars(oodPoints); err != nil {
		return nil, nil, nil, nil, err
	}

	// 3. Read the Prover's answers to the OOD queries for the entire batch.
	for i := range whir_params.BatchSize {
		oodAnswer := make([]frontend.Variable, 1)
		if err := arthur.FillNextScalars(oodAnswer); err != nil {
			return nil, nil, nil, nil, err
		}
		oodAnswers[i] = oodAnswer
	}

	// 4. Generate the batching randomness (alpha) used to combine the batched polynomials
	// in subsequent steps.
	batchingRandomness := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(batchingRandomness); err != nil {
		return nil, 0, nil, nil, err
	}
	return rootHash[0], batchingRandomness[0], oodPoints, oodAnswers, nil
}

// generateFinalCoefficientsAndRandomnessPoints handles the final phase of the protocol,
// usually associated with the STIR (or FRI-like) folding finalization.
func generateFinalCoefficientsAndRandomnessPoints(api frontend.API, arthur gnarkNimue.Arthur, whir_params WHIRParams, circuit Merkle, uapi *uints.BinaryField[uints.U64], sc *skyscraper.Skyscraper, domainSize int, expDomainGenerator frontend.Variable) ([]frontend.Variable, []frontend.Variable, error) {
	// 1. Read the final coefficients sent by the prover.
	finalCoefficients := make([]frontend.Variable, 1<<whir_params.FinalSumcheckRounds)
	if err := arthur.FillNextScalars(finalCoefficients); err != nil {
		return nil, nil, err
	}

	// 2. Enforce Proof of Work (PoW). This forces the prover to grind on the hash
	// to make the proof generation expensive enough to deter brute-force attacks on the transcript.
	if err := RunPoW(api, sc, arthur, whir_params.FinalPowBits); err != nil {
		return nil, nil, err
	}

	// 3. Generate the final query points (indices) for the STIR protocol.
	// These determine which leaves of the Merkle tree will be opened.
	finalRandomnessPoints, err := GenerateStirChallengePoints(api, arthur, whir_params.FinalQueries, circuit.LeafIndexes[len(circuit.LeafIndexes)-1], domainSize, uapi, expDomainGenerator, whir_params.FoldingFactorArray[len(whir_params.FoldingFactorArray)-1])
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
func GenerateCombinationRandomness(api frontend.API, arthur gnarkNimue.Arthur, randomnessLength int) ([]frontend.Variable, error) {
	combRandomnessGen := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(combRandomnessGen); err != nil {
		return nil, err
	}

	combinationRandomness := ExpandRandomness(api, combRandomnessGen[0], randomnessLength)
	return combinationRandomness, nil

}

func runWhirSumcheckRounds(
	api frontend.API,
	lastEval frontend.Variable,
	arthur gnarkNimue.Arthur,
	foldingFactor int,
	polynomialDegree int,
) ([]frontend.Variable, frontend.Variable, error) {
	sumcheckPolynomial := make([]frontend.Variable, polynomialDegree)
	foldingRandomness := make([]frontend.Variable, foldingFactor)
	foldingRandomnessTemp := make([]frontend.Variable, 1)

	for i := range foldingFactor {
		if err := arthur.FillNextScalars(sumcheckPolynomial); err != nil {
			return nil, nil, err
		}
		if err := arthur.FillChallengeScalars(foldingRandomnessTemp); err != nil {
			return nil, nil, err
		}
		foldingRandomness[i] = foldingRandomnessTemp[0]
		CheckSumOverBool(api, lastEval, sumcheckPolynomial)
		lastEval = EvaluateQuadraticPolynomialFromEvaluationList(api, sumcheckPolynomial, foldingRandomness[i])
	}
	return foldingRandomness, lastEval, nil
}

// RunPoW executes a proof-of-work challenge if the difficulty is greater than zero.
// This is used as part of the Fiat-Shamir transformation to prevent malicious prover behavior.
func RunPoW(api frontend.API, sc *skyscraper.Skyscraper, arthur gnarkNimue.Arthur, difficulty int) error {
	if difficulty > 0 {
		_, _, err := PoW(api, sc, arthur, difficulty)
		if err != nil {
			return err
		}
	}
	return nil
}

// GenerateStirChallengePoints generates the stir challenge points for the given parameters.
// It calculates the folding factor power and generates the stir challenges for the given leaf indexes.
func GenerateStirChallengePoints(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	NQueries int,
	leafIndexes []uints.U64,
	domainSize int,
	uapi *uints.BinaryField[uints.U64],
	expDomainGenerator frontend.Variable,
	foldingFactor int,
) ([]frontend.Variable, error) {
	foldingFactorPower := 1 << foldingFactor
	finalIndexes, err := getStirChallenges(api, arthur, NQueries, domainSize, foldingFactorPower)
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
	arthur gnarkNimue.Arthur,
	numQueries int,
	domainSize int,
	foldingFactorPower int,
) ([]frontend.Variable, error) {
	foldedDomainSize := domainSize / foldingFactorPower
	domainSizeBytes := (bits.Len(uint(foldedDomainSize*2-1)) - 1 + 7) / 8

	stirQueries := make([]uints.U8, domainSizeBytes*numQueries)
	if err := arthur.FillChallengeBytes(stirQueries); err != nil {
		return nil, err
	}

	bitLength := bits.Len(uint(foldedDomainSize)) - 1

	indexes := make([]frontend.Variable, numQueries)
	for i := range numQueries {
		var value frontend.Variable = 0
		for j := range domainSizeBytes {
			value = api.Add(stirQueries[j+i*domainSizeBytes].Val, api.Mul(value, 256))
		}

		bitsOfValue := api.ToBinary(value)
		indexes[i] = api.FromBinary(bitsOfValue[:bitLength]...)
	}

	return indexes, nil
}

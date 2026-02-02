package whir

import (
	"fmt"
	"math/big"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func VerifyWhir(
	api frontend.API,
	uapi *uints.BinaryField[uints.U64],
	proof []frontend.Variable,
	nVars uint,
	statements []Statement,
	merkleCommitment Merkle,
	params WHIRParams,
	leafIndexes []uints.U64,
) (totalFoldingRandomness []frontend.Variable, err error) {
	v := transcript.NewVerifier(proof)

	commitments := make([]ParsedCommitment, params.BatchSize)

	// The following are evaluation claims on the polynomials
	oodPoints := make([][]frontend.Variable, 0)
	oodAnswers := make([]frontend.Variable, 0)
	statementPoints := make([][]frontend.Variable, 0)

	for i := range params.BatchSize {
		commitment, err := parseBatchedCommitment(v, api, params)
		if err != nil {
			return nil, fmt.Errorf("unable to parse commitment: %w", err)
		}
		commitments[i] = commitment
	}
	for _, commitment := range commitments {
		for _, point := range commitment.OodPoints {
			mlPoint := ExpandFromUnivariate(api, point, params.MVParamsNumberOfVariables)
			oodPoints = append(oodPoints, mlPoint)
		}

		for _, answer := range commitment.OodAnswers {
			oodAnswers = append(oodAnswers, answer)
		}
	}

	for _, statement := range statements {
		for _, constraint := range statement.Constraints {
			oodPoints = append(statementPoints, constraint.Point)
		}
	}

	numPolynomials := len(commitments)
	numConstraints := len(oodPoints) + len(statements)

	constraintEvalsMatrix := make([][]frontend.Variable, numPolynomials)

	// Read the N×M evaluation matrix from transcript
	for i := 0; i < numPolynomials; i++ {
		row := make([]frontend.Variable, numConstraints)
		for j := 0; j < numConstraints; j++ {
			val := v.Read(api)
			row[j] = val
		}

		constraintEvalsMatrix[i] = row
	}

	// Step 2: Sample batching randomness γ (cryptographically bound to matrix via FS)
	batchingRandomness := v.Generate(api)

	allConstraints := make([]MLConstraint, len(oodPoints))

	// Step 3: Reconstruct combined constraints using RLC of the evaluation matrix
	// For each constraint j: combined_eval[j] = Σᵢ γⁱ·eval[i][j]
	for constraintIdx, info := range oodPoints {

		combinedEval := frontend.Variable(0)

		power := frontend.Variable(1)

		for _, polyEvals := range constraintEvalsMatrix {
			term := api.Mul(power, polyEvals[constraintIdx])
			combinedEval = api.Add(combinedEval, term)

			power = api.Mul(power, batchingRandomness)
		}

		allConstraints[constraintIdx] = MLConstraint{
			Point:      info,
			Evaluation: combinedEval,
		}
	}

	initialOODs := concatOodAnswers(api, oodPoints, batchingRandomness)

	// Perform the initial sumcheck
	initialSumcheckData, lastEval, initialSumcheckFoldingRandomness, err := initialSumcheck(api, v, batchingRandomness, initialOODs, oodAnswers, params, statementPoints)
	if err != nil {
		return
	}

	copyOfFirstLeaves := make([][][]frontend.Variable, len(merkleCommitment.Leaves))
	for i := range len(merkleCommitment.Leaves) {
		copyOfFirstLeaves[i] = make([][]frontend.Variable, len(merkleCommitment.Leaves[i]))
		for j := range len(merkleCommitment.Leaves[i]) {
			copyOfFirstLeaves[i][j] = make([]frontend.Variable, len(merkleCommitment.Leaves[i][j]))
			for k := range len(merkleCommitment.Leaves[i][j]) {
				copyOfFirstLeaves[i][j][k] = merkleCommitment.Leaves[i][j][k]
			}
		}
	}

	roundAnswers := make([][][]frontend.Variable, len(merkleCommitment.Leaves)+1)

	foldSize := 1 << params.FoldingFactorArray[0]
	collapsed := rlcBatchedLeaves(api, merkleCommitment.Leaves[0], foldSize, params.BatchSize, batchingRandomness)
	roundAnswers[0] = collapsed

	for i := range len(merkleCommitment.Leaves) {
		roundAnswers[i+1] = merkleCommitment.Leaves[i]
	}

	computedFold := computeFold(collapsed, initialSumcheckFoldingRandomness, api)

	mainRoundData := generateEmptyMainRoundData(params)
	expDomainGenerator := Exponent(api, uapi, params.StartingDomainBackingDomainGenerator, uints.NewU64(uint64(1<<params.FoldingFactorArray[0])))
	domainSize := params.DomainSize

	totalFoldingRandomness = initialSumcheckFoldingRandomness

	rootHashList := make([]frontend.Variable, len(params.RoundParametersOODSamples))

	for r := range params.ParamNRounds {
		rootHash := v.Generate(api)
		var roundOODAnswers []frontend.Variable

		rootHashList[r] = rootHash
		mainRoundData.OODPoints[r] = v.GenerateVector(api, uint(params.RoundParametersOODSamples[r]))
		roundOODAnswers = v.ReadVector(api, uint(params.RoundParametersOODSamples[r]))
		if err != nil {
			return
		}

		if err = RunPoW(api, v, uapi, params.PowBits[r]); err != nil {
			return
		}

		mainRoundData.StirChallengesPoints[r], err = getStirChallenges(api, v, params.RoundParametersNumOfQueries[r], domainSize, 1<<params.FoldingFactorArray[r])
		if err != nil {
			return
		}

		if r == 0 {
			err = IsEqual(api, uapi, mainRoundData.StirChallengesPoints[r], merkleCommitment.LeafIndexes[0])
			if err != nil {
				return
			}
			transcript.VerifyMerkleTreeProofs(api, uapi, merkleCommitment.LeafIndexes[0], merkleCommitment.Leaves[0], merkleCommitment.LeafSiblingHashes[0], merkleCommitment.AuthPaths[0], rootHash)
			if err != nil {
				return
			}
			mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(merkleCommitment.LeafIndexes[r]))
			for index := range merkleCommitment.LeafIndexes[r] {
				mainRoundData.StirChallengesPoints[r][index] = Exponent(api, uapi, expDomainGenerator, merkleCommitment.LeafIndexes[r][index])
			}
		} else {
			err = IsEqual(api, uapi, mainRoundData.StirChallengesPoints[r], merkleCommitment.LeafIndexes[r-1])
			if err != nil {
				return
			}
			transcript.VerifyMerkleTreeProofs(api, uapi, merkleCommitment.LeafIndexes[r-1], roundAnswers[r], merkleCommitment.LeafSiblingHashes[r-1], merkleCommitment.AuthPaths[r-1], rootHashList[r-1])
			if err != nil {
				return
			}
			mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(merkleCommitment.LeafIndexes[r-1]))
			for index := range merkleCommitment.LeafIndexes[r-1] {
				mainRoundData.StirChallengesPoints[r][index] = Exponent(api, uapi, expDomainGenerator, merkleCommitment.LeafIndexes[r-1][index])
			}
		}

		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(api, v, len(mainRoundData.OODPoints[r])+len(computedFold))
		if err != nil {
			return
		}

		lastEval = api.Add(lastEval, CalculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, lastEval, err = runWhirSumcheckRounds(api, lastEval, v, params.FoldingFactorArray[r], 3)
		if err != nil {
			return
		}

		computedFold = computeFold(merkleCommitment.Leaves[r], roundFoldingRandomness, api)
		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

		domainSize /= 2
		expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
	}

	finalCoefficients, finalRandomnessPoints, err := generateFinalCoefficientsAndRandomnessPoints(api, v, params, merkleCommitment, uapi, domainSize, expDomainGenerator)
	if err != nil {
		return
	}

	finalEvaluations := UnivarPoly(api, finalCoefficients, finalRandomnessPoints)

	for foldIndex := range computedFold {
		api.AssertIsEqual(computedFold[foldIndex], finalEvaluations[foldIndex])
	}

	finalSumcheckRandomness, lastEval, err := runWhirSumcheckRounds(api, lastEval, v, params.FinalSumcheckRounds, 3)
	if err != nil {
		return
	}

	totalFoldingRandomness = append(totalFoldingRandomness, finalSumcheckRandomness...)

	if params.FinalFoldingPowBits > 0 {
		_, _, err = PoW(api, v, uapi, params.FinalFoldingPowBits)
		if err != nil {
			return
		}
	}

	totalFoldingRandomness = Reverse(totalFoldingRandomness)

	linearStatementValuesAtPoints := make([]frontend.Variable, 0)

	for _, statement := range statements {

		for _, constraint := range statement.Constraints {
			linearStatementValuesAtPoints = append(linearStatementValuesAtPoints, constraint.Evaluation)
		}

	}
	evaluationOfWPoly := computeWPoly(
		api,
		params,
		initialSumcheckData,
		mainRoundData,
		totalFoldingRandomness,
		linearStatementValuesAtPoints,
	)

	api.AssertIsEqual(
		lastEval,
		api.Mul(evaluationOfWPoly, MultivarPoly(finalCoefficients, finalSumcheckRandomness, api)),
	)

	return totalFoldingRandomness, nil
}

// Newparams creates a new params instance from the given configuration.
// It processes the folding factors and calculates domain sizes based on the provided config.
func Newparams(cfg WHIRConfig) WHIRParams {
	startingDomainGen, _ := new(big.Int).SetString(cfg.DomainGenerator, 10)
	mvParamsNumberOfVariables := cfg.NVars
	var foldingFactor []int
	var finalSumcheckRounds int

	if len(cfg.FoldingFactor) > 1 {
		foldingFactor = append(cfg.FoldingFactor, cfg.FoldingFactor[len(cfg.FoldingFactor)-1])
		finalSumcheckRounds = mvParamsNumberOfVariables % foldingFactor[len(foldingFactor)-1]
	} else {
		foldingFactor = []int{4}
		finalSumcheckRounds = mvParamsNumberOfVariables % 4
	}
	domainSize := (2 << mvParamsNumberOfVariables) * (1 << cfg.Rate) / 2

	return WHIRParams{
		ParamNRounds:                         cfg.NRounds,
		FoldingFactorArray:                   foldingFactor,
		RoundParametersOODSamples:            cfg.OODSamples,
		RoundParametersNumOfQueries:          cfg.NumQueries,
		PowBits:                              cfg.PowBits,
		FinalQueries:                         cfg.FinalQueries,
		FinalPowBits:                         cfg.FinalPowBits,
		FinalFoldingPowBits:                  cfg.FinalFoldingPowBits,
		StartingDomainBackingDomainGenerator: *startingDomainGen,
		DomainSize:                           domainSize,
		CommittmentOODSamples:                1,
		FinalSumcheckRounds:                  finalSumcheckRounds,
		MVParamsNumberOfVariables:            mvParamsNumberOfVariables,
		BatchSize:                            cfg.BatchSize,
	}
}

func combineConstraints(api frontend.API, v *transcript.Verifier, claimedSum frontend.Variable, constraints []MLConstraint) ([]frontend.Variable, frontend.Variable) {
	randomness := v.Generate(api)
	rVector := ExpandRandomness(api, randomness, len(constraints))

	for i := range constraints {
		claimedSum = api.Add(claimedSum, api.Mul(rVector[i], constraints[i].Evaluation))
	}

	return rVector, claimedSum

}

// ExpandFromUnivariate converts a univariate evaluation point into a multilinear one.
//
// It maps a single point 'y' to a vector of coordinates:
// [y^(2^(n-1)), ..., y^4, y^2, y]
//
// This corresponds to the Big-Endian binary decomposition mapping used in
// protocols like Sumcheck or Spartan.
func ExpandFromUnivariate(api frontend.API, point frontend.Variable, numVariables int) []frontend.Variable {
	res := make([]frontend.Variable, numVariables)
	current := point

	// We iterate numVariables times.
	// In the Rust version, they generate [y, y^2, y^4...] and then reverse it.
	// Here, we simply fill the slice from the end (n-1) down to 0 to achieve
	// the same Big-Endian result: [HighestPower, ..., LowestPower].
	for i := 0; i < numVariables; i++ {
		// Store the current power at the "end" of the available slots
		res[numVariables-1-i] = current

		// Compute y^(2^k) for the next iteration (Squaring)
		current = api.Mul(current, current)
	}

	return res
}

// oodAnswers computes a Random Linear Combination (RLC) of multiple answer vectors.
// It flattens a 2D slice of variables into a single vector by applying increasing
// powers of a random challenge: Result = Σ (answers[i] * randomness^i).
func concatOodAnswers(
	api frontend.API,
	answers [][]frontend.Variable,
	randomness frontend.Variable,
) (result []frontend.Variable) {

	if len(answers) == 0 {
		return nil
	}

	multiplier := frontend.Variable(1)

	first := answers[0]
	result = make([]frontend.Variable, len(first))
	for j := range first {
		result[j] = api.Mul(first[j], multiplier)
	}

	for i := 1; i < len(answers); i++ {
		multiplier = api.Mul(multiplier, randomness)

		round := answers[i]
		for j := range round {
			term := api.Mul(round[j], multiplier)
			result[j] = api.Add(result[j], term)
		}
	}

	return result
}

func computeWPoly(
	api frontend.API,
	circuit WHIRParams,
	initialData InitialSumcheckData,
	mainRoundData MainRoundData,
	totalFoldingRandomness []frontend.Variable,
	linearStatementValuesAtPoints []frontend.Variable,
) frontend.Variable {
	numberVars := circuit.MVParamsNumberOfVariables

	value := frontend.Variable(0)
	for j := range initialData.InitialOODQueries {
		value = api.Add(value, api.Mul(initialData.InitialCombinationRandomness[j], EqPolyOutside(api, ExpandFromUnivariate(api, initialData.InitialOODQueries[j], numberVars), totalFoldingRandomness)))
	}

	for j, linearStatementValueAtPoint := range linearStatementValuesAtPoints {
		value = api.Add(value, api.Mul(initialData.InitialCombinationRandomness[len(initialData.InitialOODQueries)+j], linearStatementValueAtPoint))
	}
	for r := range mainRoundData.OODPoints {
		numberVars -= circuit.FoldingFactorArray[r]
		newTmpArr := append(mainRoundData.OODPoints[r], mainRoundData.StirChallengesPoints[r]...)

		sumOfClaims := frontend.Variable(0)
		for i := range newTmpArr {
			point := ExpandFromUnivariate(api, newTmpArr[i], numberVars)
			sumOfClaims = api.Add(sumOfClaims, api.Mul(EqPolyOutside(api, point, totalFoldingRandomness[0:numberVars]), mainRoundData.CombinationRandomness[r][i]))
		}
		value = api.Add(value, sumOfClaims)
	}

	return value
}

// RunPoW executes a proof-of-work challenge if the difficulty is greater than zero.
// This is used as part of the Fiat-Shamir transformation to prevent malicious prover behavior.
func RunPoW(api frontend.API, v *transcript.Verifier, uapi *uints.BinaryField[uints.U64], difficulty int) error {
	if difficulty > 0 {
		_, _, err := PoW(api, v, uapi, difficulty)
		if err != nil {
			return err
		}
	}
	return nil
}

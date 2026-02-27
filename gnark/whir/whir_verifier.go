package whir

import (
	"fmt"
	"math/bits"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func VerifyWhir(
	api frontend.API,
	uapi *uints.BinaryField[uints.U64],
	proof []frontend.Variable,
	hints []frontend.Variable,
	statements []Statement,
	params WHIRParams,
) (totalFoldingRandomness []frontend.Variable, err error) {
	v := transcript.NewVerifierWithHints(proof, hints)
	// api.Println(transcript.NewSponge().State[:]...)
	// Absorb domain separator: protocol_id (2 Fr) + session_id (1 Fr).
	// Mirrors spongefish's DomainSeparator::to_verifier which absorbs
	// protocol_id, session_id, and empty instance before any proof data.
	domainSep := ComputeDomainSeparator(params.Config)

	fmt.Println("Sponge absorbing domain seperators:", domainSep[:])
	for _, ds := range domainSep {
		v.Absorb(api, ds)
	}

	// Receive a single commitment covering all batch vectors.
	// Mirrors Rust irs_commit::receive_commitment: read root, generate OOD points,
	// read OOD answers flat (outDomainSamples * numVectors).
	commitment := receiveCommitment(v, api, params.CommittmentOODSamples, params.BatchSize)

	numVectors := params.BatchSize

	// Complete the constraint and evaluation matrix with OODs and their cross-terms.
	// For a single commitment all OOD values are already known; for multiple
	// commitments this loop reads cross-term evaluations from the transcript.
	numOODConstraints := 0
	var oodMatrix []frontend.Variable
	vectorOffset := 0
	committedOODRows := commitment.OodAnswers // flat: outDomainSamples * numVectorsPerCommitment
	numVectorsPerCommitment := params.BatchSize
	for i := 0; i < params.CommittmentOODSamples; i++ {
		for j := 0; j < numVectors; j++ {
			if j >= vectorOffset && j < numVectorsPerCommitment+vectorOffset {
				oodMatrix = append(oodMatrix, committedOODRows[i*numVectorsPerCommitment+(j-vectorOffset)])
			} else {
				// Cross-term: read from transcript (absorb into sponge).
				oodMatrix = append(oodMatrix, v.Read(api))
			}
		}
		numOODConstraints++
	}

	fmt.Println("numOODConstraints:", numOODConstraints)
	fmt.Println("oodMatrix length:", len(oodMatrix))
	api.Println(oodMatrix...)
	fmt.Println("oodPoints:", commitment.OodPoints)

	// Extract OOD multilinear points from the univariate OOD challenge points
	oodPoints := make([][]frontend.Variable, 0, len(commitment.OodPoints))
	for _, point := range commitment.OodPoints {
		mlPoint := ExpandFromUnivariate(api, point, params.MVParamsNumberOfVariables)
		oodPoints = append(oodPoints, mlPoint)
	}

	// Random linear combination of the vectors.
	vectorRlcCoeffs := geometricChallenge(api, v, numVectors)
	api.Println(vectorRlcCoeffs...)

	// Random linear combination of the constraints.
	numLinearForms := len(statements)
	constraintRlcCoeffs := geometricChallenge(api, v, numOODConstraints+numLinearForms)
	oodsRlcCoeffs := constraintRlcCoeffs[:numOODConstraints]
	initialFormRlcCoeffs := constraintRlcCoeffs[numOODConstraints:]

	// Compute "the sum" (mirrors Rust whir::verifier lines 110-118)
	// the_sum = Σ(initialFormRlcCoeff * dot(vectorRlcCoeffs, evaluationRow))
	//         + Σ(oodsRlcCoeff * dot(vectorRlcCoeffs, oodsRow))
	theSum := frontend.Variable(0)
	for i, rlcCoeff := range initialFormRlcCoeffs {
		evaluationRow := make([]frontend.Variable, params.BatchSize)
		for j := range evaluationRow {
			evaluationRow[j] = statements[i].Constraints[j].Evaluation
		}
		theSum = api.Add(theSum, api.Mul(rlcCoeff, DotProduct(api, vectorRlcCoeffs, evaluationRow)))
	}
	for i, rlcCoeff := range oodsRlcCoeffs {
		oodsRow := oodMatrix[i*numVectors : (i+1)*numVectors]
		theSum = api.Add(theSum, api.Mul(rlcCoeff, DotProduct(api, vectorRlcCoeffs, oodsRow)))
	}

	// Perform the initial sumcheck
	initialSumcheckData, lastEval, initialSumcheckFoldingRandomness, err := initialSumcheck(api, v, theSum, commitment.OodPoints, oodsRlcCoeffs, initialFormRlcCoeffs, params)
	if err != nil {
		return
	}

	foldSize := 1 << params.FoldingFactorArray[0]
	numQueries := params.RoundParametersNumOfQueries[0]

	// Read initial leaf values from hints (numQueries leaves, each batchSize*foldSize elements)
	// Mirrors Rust: prover_hint_ark() in irs_commit.verify()
	initialLeaves := readLeavesFromHints(v, numQueries, params.BatchSize*foldSize)
	// api.Println(initialLeaves[0]...)
	// Collapse via vector RLC, then fold
	collapsed := rlcBatchedLeaves(api, initialLeaves, foldSize, params.BatchSize, vectorRlcCoeffs[1])
	computedFold := computeFold(collapsed, initialSumcheckFoldingRandomness, api)

	mainRoundData := generateEmptyMainRoundData(params)
	expDomainGenerator := ExponentVar(api, params.StartingDomainBackingDomainGenerator, frontend.Variable(1<<params.FoldingFactorArray[0]), bits.Len(uint(params.DomainSize)))
	domainSize := params.DomainSize

	totalFoldingRandomness = initialSumcheckFoldingRandomness

	for r := range params.ParamNRounds {
		// Mirrors Rust irs_commit::receive_commitment: read root hash (absorb), squeeze OOD points, read OOD answers.
		rootHash := v.Read(api)
		var roundOODAnswers []frontend.Variable

		mainRoundData.OODPoints[r] = v.GenerateVector(api, uint(params.RoundParametersOODSamples[r]))
		roundOODAnswers = v.ReadVector(api, uint(params.RoundParametersOODSamples[r]))
		if err != nil {
			return
		}

		if err = RunPoW(api, v, uapi, params.PowBits[r]); err != nil {
			return
		}

		// Generate STIR challenge indices from sponge
		stirIndexes, err2 := getStirChallenges(api, v, params.RoundParametersNumOfQueries[r], domainSize, 1<<params.FoldingFactorArray[r])
		if err2 != nil {
			err = err2
			return
		}

		// Verify Merkle paths for previously committed leaves
		// Reads sibling hashes from hints. Uses the initial commitment root
		// for round 0, or the previous round's root for subsequent rounds.
		if r == 0 {
			treeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[0]))) - 1
			verifyMerklePaths(api, v, initialLeaves, stirIndexes, commitment.Root, treeHeight)
		} else {
			prevFoldSize := 1 << params.FoldingFactorArray[r-1]
			prevNumQueries := params.RoundParametersNumOfQueries[r]
			prevTreeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[r]))) - 1

			// Read leaf values for this round's opening from hints
			roundLeaves := readLeavesFromHints(v, prevNumQueries, prevFoldSize)
			verifyMerklePaths(api, v, roundLeaves, stirIndexes, rootHash, prevTreeHeight)

			// Update computedFold for this round's leaves
			computedFold = computeFold(roundLeaves, totalFoldingRandomness[len(totalFoldingRandomness)-params.FoldingFactorArray[r-1]:], api)
		}

		// Compute domain evaluation points from indices
		numBits := bits.Len(uint(domainSize - 1))
		mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(stirIndexes))
		for index, idx := range stirIndexes {
			mainRoundData.StirChallengesPoints[r][index] = ExponentVar(api, expDomainGenerator, idx, numBits)
		}

		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(api, v, len(mainRoundData.OODPoints[r])+len(computedFold))
		if err != nil {
			return
		}

		lastEval = api.Add(lastEval, CalculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, lastEval, err = runWhirSumcheckRounds(api, lastEval, v, params.FoldingFactorArray[r])
		if err != nil {
			return
		}

		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

		domainSize /= 2
		expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
	}

	finalCoefficients, finalRandomnessPoints, finalIndexes, err := generateFinalCoefficientsAndRandomnessPoints(api, v, params, domainSize, expDomainGenerator)
	if err != nil {
		return
	}

	finalEvaluations := UnivarPoly(api, finalCoefficients, finalRandomnessPoints)

	for foldIndex := range computedFold {
		api.AssertIsEqual(computedFold[foldIndex], finalEvaluations[foldIndex])
	}

	finalSumcheckRandomness, lastEval, err := runWhirSumcheckRounds(api, lastEval, v, params.FinalSumcheckRounds)
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

	// Read final Merkle opening from hints and verify
	lastFoldingFactor := params.FoldingFactorArray[len(params.FoldingFactorArray)-1]
	finalLeaves := readLeavesFromHints(v, params.FinalQueries, 1<<lastFoldingFactor)
	finalTreeHeight := bits.Len(uint(domainSize/(1<<lastFoldingFactor))) - 1
	// The final opening is against the last round's root (or initial commitment if 0 rounds)
	// For now, verify against the last commitment root stored in the transcript
	if params.ParamNRounds > 0 {
		// Last round's rootHash was stored; re-derive it from transcript state
		// Actually, the final opening verification is handled by generateFinalCoefficientsAndRandomnessPoints
		// which already verified the final STIR challenges
	}
	verifyMerklePaths(api, v, finalLeaves, finalIndexes, commitment.Root, finalTreeHeight)

	totalFoldingRandomness = Reverse(totalFoldingRandomness)

	// Read deferred evaluations from hints: one per linear form (statement).
	// Mirrors Rust: prover_hint_ark() for deferred constraint weights.
	deferredEvals := v.ReadHintVector(uint(len(statements)))

	evaluationOfWPoly := computeWPoly(
		api,
		params,
		initialSumcheckData,
		mainRoundData,
		totalFoldingRandomness,
		deferredEvals,
	)

	api.AssertIsEqual(
		lastEval,
		api.Mul(evaluationOfWPoly, MultivarPoly(finalCoefficients, finalSumcheckRandomness, api)),
	)

	return totalFoldingRandomness, nil
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

package whir

import (
	"math/big"
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
		OodPoints:          oodPoints,
		OodAnswers:         oodAnswers,
		BatchingRandomness: v.GenerateVector(api, 1),
	}
	return commitment, nil
}

func parseCommitment(v *transcript.Verifier, api frontend.API, whir_params WHIRParams) ParsedCommitment {
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
		OodPoints:          oodPoints,
		OodAnswers:         oodAnswers,
		BatchingRandomness: frontend.Variable(0),
	}
	return commitment
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

func generateEmptyMainRoundData(circuit WHIRParams) MainRoundData {
	return MainRoundData{
		OODPoints:             make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		StirChallengesPoints:  make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		CombinationRandomness: make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
	}
}

func computeFold(leaves [][]frontend.Variable, foldingRandomness []frontend.Variable, api frontend.API) []frontend.Variable {
	computedFold := make([]frontend.Variable, len(leaves))
	for j := range leaves {
		computedFold[j] = MultivarPoly(leaves[j], foldingRandomness, api)
	}
	return computedFold
}

func PoW(api frontend.API, v *transcript.Verifier, uapi *uints.BinaryField[uints.U64], difficulty int) ([]uints.U8, []uints.U8, error) {
	challenges := v.GenerateBytes(api, uapi, 32)

	nonce := v.ReadBytes(api, uapi, 8)
	challengeFieldElement := LittleEndianFromUints(api, challenges)
	nonceFieldElement := BigEndianFromUints(api, nonce)
	err := CheckPoW(api, challengeFieldElement, nonceFieldElement, difficulty)
	if err != nil {
		return nil, nil, err
	}
	return challenges, nonce, nil
}

func CheckPoW(api frontend.API, challenge frontend.Variable, nonce frontend.Variable, difficulty int) error {
	hash := transcript.HashNode(api, []frontend.Variable{challenge, nonce})

	d0, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	d1, _ := new(big.Int).SetString("10944121435919637611123202872628637544274182200208017171849102093287904247808", 10)
	d2, _ := new(big.Int).SetString("5472060717959818805561601436314318772137091100104008585924551046643952123904", 10)
	d3, _ := new(big.Int).SetString("2736030358979909402780800718157159386068545550052004292962275523321976061952", 10)
	d4, _ := new(big.Int).SetString("1368015179489954701390400359078579693034272775026002146481137761660988030976", 10)
	d5, _ := new(big.Int).SetString("684007589744977350695200179539289846517136387513001073240568880830494015488", 10)
	d6, _ := new(big.Int).SetString("342003794872488675347600089769644923258568193756500536620284440415247007744", 10)
	d7, _ := new(big.Int).SetString("171001897436244337673800044884822461629284096878250268310142220207623503872", 10)
	d8, _ := new(big.Int).SetString("85500948718122168836900022442411230814642048439125134155071110103811751936", 10)
	d9, _ := new(big.Int).SetString("42750474359061084418450011221205615407321024219562567077535555051905875968", 10)
	d10, _ := new(big.Int).SetString("21375237179530542209225005610602807703660512109781283538767777525952937984", 10)
	d11, _ := new(big.Int).SetString("10687618589765271104612502805301403851830256054890641769383888762976468992", 10)
	d12, _ := new(big.Int).SetString("5343809294882635552306251402650701925915128027445320884691944381488234496", 10)
	d13, _ := new(big.Int).SetString("2671904647441317776153125701325350962957564013722660442345972190744117248", 10)
	d14, _ := new(big.Int).SetString("1335952323720658888076562850662675481478782006861330221172986095372058624", 10)
	d15, _ := new(big.Int).SetString("667976161860329444038281425331337740739391003430665110586493047686029312", 10)
	d16, _ := new(big.Int).SetString("333988080930164722019140712665668870369695501715332555293246523843014656", 10)
	d17, _ := new(big.Int).SetString("166994040465082361009570356332834435184847750857666277646623261921507328", 10)
	d18, _ := new(big.Int).SetString("83497020232541180504785178166417217592423875428833138823311630960753664", 10)
	d19, _ := new(big.Int).SetString("41748510116270590252392589083208608796211937714416569411655815480376832", 10)
	d20, _ := new(big.Int).SetString("20874255058135295126196294541604304398105968857208284705827907740188416", 10)
	d21, _ := new(big.Int).SetString("10437127529067647563098147270802152199052984428604142352913953870094208", 10)
	d22, _ := new(big.Int).SetString("5218563764533823781549073635401076099526492214302071176456976935047104", 10)
	d23, _ := new(big.Int).SetString("2609281882266911890774536817700538049763246107151035588228488467523552", 10)
	d24, _ := new(big.Int).SetString("1304640941133455945387268408850269024881623053575517794114244233761776", 10)
	d25, _ := new(big.Int).SetString("652320470566727972693634204425134512440811526787758897057122116880888", 10)
	d26, _ := new(big.Int).SetString("326160235283363986346817102212567256220405763393879448528561058440444", 10)
	d27, _ := new(big.Int).SetString("163080117641681993173408551106283628110202881696939724264280529220222", 10)

	var arr = [28]*big.Int{d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27}
	api.AssertIsLessOrEqual(hash, arr[difficulty])
	return nil
}

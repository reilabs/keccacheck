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
	params WHIRParams,
) (totalFoldingRandomness []frontend.Variable, err error) {
	v := transcript.NewVerifier(proof)

	commitments := make([]ParsedCommitment, params.BatchSize)

	allWeights := make([][]frontend.Variable, params.BatchSize)
	for i := range params.BatchSize {
		commitment, err := parseBatchedCommitment(v, api, params)

		if err != nil {
			return nil, fmt.Errorf("Unable to parse commitment: %w", err)
		}
		commitments[i] = commitment
	}

	for i, commitment := range commitments {
		for _, point := range commitment.OodPoints {
			mlPoint := ExpandFromUnivariate(api, point, params.MVParamsNumberOfVariables)
			allWeights[i] = mlPoint
		}
	}

	return nil, fmt.Errorf("Not yet implemented")
}

// Create a random linear combination of constraints
// Returns the randomness used and the combined claimed sum
func combineConstraints(api frontend.API, v *transcript.Verifier, claimedSum frontend.Variable, constraints []MLConstraint) ([]frontend.Variable, frontend.Variable) {
	randomness := v.Generate(api)
	rVector := ExpandRandomness(api, randomness, len(constraints))

	for i := range constraints {
		claimedSum = api.Add(claimedSum, api.Mul(rVector[i], constraints[i].evalution))
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

// NewWhirParams creates a new WHIRParams instance from the given configuration.
// It processes the folding factors and calculates domain sizes based on the provided config.
func NewWhirParams(cfg WHIRConfig) WHIRParams {
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

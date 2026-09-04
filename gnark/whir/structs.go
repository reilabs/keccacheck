package whir

import (
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

// SoundnessType defines the soundness guarantee for the proof system.
type SoundnessType int

const (
	UniqueDecoding SoundnessType = iota
	ProvableList
	ConjectureList
)

// FoldingFactor defines the folding strategy per round.
type FoldingFactor struct {
	// Constant: same factor every round. ConstantFromSecondRound: first round
	// uses FirstRound, subsequent rounds use Factor.
	Factor        int
	FirstRound    int // only used when VariableFirst is true
	VariableFirst bool
}

// ConstantFoldingFactor creates a FoldingFactor with the same value every round.
func ConstantFoldingFactor(factor int) FoldingFactor {
	return FoldingFactor{Factor: factor}
}

// ConstantFromSecondRoundFoldingFactor creates a FoldingFactor where the first
// round uses firstRound and subsequent rounds use factor.
func ConstantFromSecondRoundFoldingFactor(firstRound, factor int) FoldingFactor {
	return FoldingFactor{Factor: factor, FirstRound: firstRound, VariableFirst: true}
}

// AtRound returns the folding factor for the given round index.
func (ff FoldingFactor) AtRound(round int) int {
	if ff.VariableFirst && round == 0 {
		return ff.FirstRound
	}
	return ff.Factor
}

// ComputeNumberOfRounds returns (numRounds, finalSumcheckRounds).
func (ff FoldingFactor) ComputeNumberOfRounds(numVariables int) (int, int) {
	if ff.VariableFirst {
		nvExceptFirst := numVariables - ff.FirstRound
		if nvExceptFirst < ff.Factor {
			return 0, nvExceptFirst
		}
		finalSumcheckRounds := nvExceptFirst % ff.Factor
		return (nvExceptFirst - finalSumcheckRounds) / ff.Factor, finalSumcheckRounds
	}
	finalSumcheckRounds := numVariables % ff.Factor
	return (numVariables-finalSumcheckRounds)/ff.Factor - 1, finalSumcheckRounds
}

type ParsedCommitment struct {
	Root       frontend.Variable
	OodPoints  []frontend.Variable
	OodAnswers []frontend.Variable // flat: out_domain_samples * num_vectors
}

type Statement struct {
	Constraints []MLConstraint
	NVars       int
}

type WHIRParams struct {
	Config                               ProtocolConfig
	ParamNRounds                         int
	FoldingFactorArray                   []int
	RoundParametersOODSamples            []int
	RoundParametersNumOfQueries          []int
	PowBits                              []int
	FinalQueries                         int
	FinalPowBits                         int
	FinalFoldingPowBits                  int
	StartingDomainBackingDomainGenerator frontend.Variable
	DomainSize                           int
	CommittmentOODSamples                int
	FinalSumcheckRounds                  int
	MVParamsNumberOfVariables            int
	BatchSize                            int
}

type InitialSumcheckData struct {
	InitialOODQueries            []frontend.Variable
	InitialCombinationRandomness []frontend.Variable
}

type MLConstraint struct {
	Point      []frontend.Variable
	Evaluation frontend.Variable
}

type MainRoundData struct {
	OODPoints             [][]frontend.Variable
	StirChallengesPoints  [][]frontend.Variable
	CombinationRandomness [][]frontend.Variable
}

// ComputeWhirProofFrs returns the exact number of field elements consumed from
// the WHIR transcript verifier (narg string) during ReceiveCommitment + VerifyWhir.
// This traces every Read/ReadVector call on the transcript deterministically.
func ComputeWhirProofFrs(params WHIRParams) int {
	count := 0

	// ReceiveCommitment: root hash + OOD answers
	count += 1 + params.CommittmentOODSamples*params.BatchSize

	// Initial sumcheck: runWhirSumcheckRounds(FoldingFactorArray[0])
	// Each round reads c0, c2 = 2 elements
	count += 2 * params.FoldingFactorArray[0]

	// Main rounds
	for r := range params.ParamNRounds {
		count += 1                                   // root hash
		count += params.RoundParametersOODSamples[r] // OOD answers
		if params.PowBits[r] > 0 {
			count += 1 // PoW nonce
		}
		count += 2 * params.FoldingFactorArray[r+1] // round sumcheck
	}

	// Final vector
	count += 1 << params.FinalSumcheckRounds

	// Final PoW
	if params.FinalPowBits > 0 {
		count += 1
	}

	// Final sumcheck
	count += 2 * params.FinalSumcheckRounds

	// Final folding PoW
	if params.FinalFoldingPowBits > 0 {
		count += 1
	}

	return count
}

// HintBlock describes a single block in the WHIR hint stream.
// Type 0 = Vec (variable-length field element array), Type 1 = Hash (single field element).
type HintBlock struct {
	Type  int // 0=Vec, 1=Hash
	Count int // number of field elements (always 1 for Hash)
}

// ComputeHintBlocks returns the ordered sequence of hint blocks produced during
// VerifyWhir. All other hint-related computations (block types, byte lengths,
// field element counts) are derived from this single traversal.
func ComputeHintBlocks(params WHIRParams, numStatements int) []HintBlock {
	var blocks []HintBlock
	domainSize := params.DomainSize

	// Initial leaves Vec
	initialCount := params.RoundParametersNumOfQueries[0] * params.BatchSize * (1 << params.FoldingFactorArray[0])
	blocks = append(blocks, HintBlock{Type: 0, Count: initialCount})

	for r := range params.ParamNRounds {
		if r == 0 {
			// Round 0: Merkle paths on initial leaves (no new Vec)
			treeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[0]))) - 1
			for range params.RoundParametersNumOfQueries[0] * treeHeight {
				blocks = append(blocks, HintBlock{Type: 1, Count: 1})
			}
		} else {
			// Round r>0: leaves Vec + Merkle paths
			vecCount := params.RoundParametersNumOfQueries[r] * (1 << params.FoldingFactorArray[r])
			blocks = append(blocks, HintBlock{Type: 0, Count: vecCount})
			treeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[r]))) - 1
			for range params.RoundParametersNumOfQueries[r] * treeHeight {
				blocks = append(blocks, HintBlock{Type: 1, Count: 1})
			}
		}
		domainSize /= 2
	}

	// Final leaves Vec + Merkle paths
	lastFoldingFactor := params.FoldingFactorArray[len(params.FoldingFactorArray)-1]
	if params.ParamNRounds > 0 {
		blocks = append(blocks, HintBlock{Type: 0, Count: params.FinalQueries * (1 << lastFoldingFactor)})
	} else {
		blocks = append(blocks, HintBlock{Type: 0, Count: params.FinalQueries * params.BatchSize * (1 << lastFoldingFactor)})
	}
	finalTreeHeight := bits.Len(uint(domainSize/(1<<lastFoldingFactor))) - 1
	for range params.FinalQueries * finalTreeHeight {
		blocks = append(blocks, HintBlock{Type: 1, Count: 1})
	}

	// Deferred evals Vec
	blocks = append(blocks, HintBlock{Type: 0, Count: numStatements})

	return blocks
}

// ComputeHintBlockTypes returns the block type sequence (0=Vec, 1=Hash)
// for parsing the raw hint byte stream.
func ComputeHintBlockTypes(params WHIRParams) []int {
	blocks := ComputeHintBlocks(params, 1)
	types := make([]int, len(blocks))
	for i, b := range blocks {
		types[i] = b.Type
	}
	return types
}

// ComputeWhirHintFrs returns the total number of field elements across all hint
// blocks. This is the output size for a single bulk hint call.
func ComputeWhirHintFrs(params WHIRParams, numStatements int) int {
	total := 0
	for _, b := range ComputeHintBlocks(params, numStatements) {
		total += b.Count
	}
	return total
}

// ComputeWhirHintBytes returns the total byte length of the WHIR hint stream.
// Vec blocks are 8 (length prefix) + count*32 bytes; Hash blocks are 32 bytes.
func ComputeWhirHintBytes(params WHIRParams, numStatements int) int {
	bytes := 0
	for _, b := range ComputeHintBlocks(params, numStatements) {
		if b.Type == 0 {
			bytes += 8 + b.Count*32
		} else {
			bytes += 32
		}
	}
	return bytes
}

// ComputeWhirBytes returns the total byte length of the WHIR proof portion
// (narg string + hints), computed deterministically from params.
func ComputeWhirBytes(params WHIRParams, numStatements int) int {
	nargBytes := 8 + ComputeWhirProofFrs(params)*32
	hintBytes := 8 + ComputeWhirHintBytes(params, numStatements)
	return nargBytes + hintBytes
}

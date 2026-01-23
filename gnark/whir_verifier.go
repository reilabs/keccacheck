package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func VerifyWhir(
	api frontend.API,
	uapi *uints.BinaryField[uints.U64],
	circuit Merkle,
	firstRound Merkle,
	whirParams WHIRParams,
	linearStatementEvaluations [][]frontend.Variable,
	linearStatementValuesAtPoints []frontend.Variable,
	batchingRandomness frontend.Variable,
	initialOODQueries []frontend.Variable,
	initialOODAnswers [][]frontend.Variable,
	rootHashes frontend.Variable,
) (totalFoldingRandomness []frontend.Variable, err error) {

	return nil, fmt.Errorf("Not yet implemented")
}

type Merkle struct {
	Leaves            [][][]frontend.Variable
	LeafIndexes       [][]uints.U64
	LeafSiblingHashes [][]frontend.Variable
	AuthPaths         [][][]frontend.Variable
}

type WHIRParams struct {
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

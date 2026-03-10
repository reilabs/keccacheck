package main

import (
	"reilabs/keccacheck/sumcheck"
	"reilabs/keccacheck/transcript"
	"reilabs/keccacheck/whir"

	"github.com/consensys/gnark/frontend"
)

// VerifyKeccakFWHIR verifies a keccak-f permutation using GKR with a WHIR
// polynomial commitment. It reduces the GKR output, binary, and input claims
// into polynomial constraints that are then verified via WHIR.
func VerifyKeccakFWHIR(
	api frontend.API,
	output, proof, alpha []frontend.Variable,
	whirProof []frontend.Variable,
	hintInputs []frontend.Variable,
	whirParams whir.WHIRParams,
) {
	// Initialize WHIR transcript and receive commitment (mirrors Rust: config.receive_commitment)
	whirVerifier := transcript.NewVerifier(whirProof)
	domainSep := whir.ComputeDomainSeparator(whirParams.Config)
	for _, ds := range domainSep {
		whirVerifier.Absorb(api, ds)
	}
	whirCommitment := whir.ReceiveCommitment(whirVerifier, api, whirParams.CommittmentOODSamples, whirParams.BatchSize)

	// Absorb the WHIR commitment root hash into the keccak verifier transcript
	// (mirrors Rust: verifier.absorb(Fr::from_le_bytes_mod_order(&root.0)))
	verifier := transcript.NewVerifier(proof)
	verifier.Absorb(api, whirCommitment.Root)

	beta, alpha, iota := VerifyGKR(api, verifier, alpha, output)
	outputBeta := make([]frontend.Variable, 25)
	copy(outputBeta, beta)

	// --- Binary claim verification ---
	binaryBatchedEval, binaryBeta := VerifyBinaryCheck(api, verifier, NUM_VARS)

	// --- Input word reduction ---
	inputBRxRy, inputBeta := ReduceInputWords(api, verifier)

	// Combine round/binary/input claims and build WHIR constraints
	constraints := CombineClaims(api, verifier, outputBeta, iota, binaryBatchedEval, binaryBeta, inputBRxRy, inputBeta)
	statements := []whir.Statement{{
		Constraints: constraints,
		NVars:       NUM_VARS,
	}}
	hr := whir.NewHintReader(api, hintInputs, ReadVecHint, ReadHashHint)
	whir.VerifyWhir(api, whirVerifier, whirCommitment, hr, statements, whirParams)
}

// VerifyKeccakF verifies a keccak-f permutation using GKR without a polynomial
// commitment scheme. Directly evaluates the input MLEs against the GKR output
// and checks equality in-circuit.
func VerifyKeccakF(api frontend.API, input, output, proof, r []frontend.Variable) {
	verifier := transcript.NewVerifier(proof)
	_, r, iota := VerifyGKR(api, verifier, r, output)
	eval_eq_r := sumcheck.EvalEq(api, r)
	for i := 0; i < 25; i++ {
		start := i * N
		end := start + N
		poly := input[64*start : 64*end]
		eval := sumcheck.EvalMleWithEq(api, poly, eval_eq_r)
		api.AssertIsEqual(eval, iota[i])
	}
}

var COLUMNS = 5
var ROWS = 5
var STATE = COLUMNS * ROWS

var ROUND_CONSTANTS = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

var PI = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

var halfString = "10944121435919637611123202872628637544274182200208017171849102093287904247809"

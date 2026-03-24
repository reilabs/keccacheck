package main

import (
	"reilabs/keccacheck/keccacheck"
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
	allWhirHints []frontend.Variable,
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
	verifier := transcript.NewVerifier(proof)
	verifier.Absorb(api, whirCommitment.Root)

	beta, alpha, iota := keccacheck.VerifyGKR(api, verifier, alpha, output)
	outputBeta := make([]frontend.Variable, 25)
	copy(outputBeta, beta)

	// --- Binary claim verification ---
	binaryBatchedEval, binaryBeta := VerifyBinaryCheck(api, verifier, keccacheck.NUM_VARS)

	// --- Input word reduction ---
	inputBRxRy, inputBeta := ReduceInputWords(api, verifier)

	// Combine round/binary/input claims and build WHIR constraints
	constraints := CombineClaims(api, verifier, outputBeta, iota, binaryBatchedEval, binaryBeta, inputBRxRy, inputBeta)
	statements := []whir.Statement{{
		Constraints: constraints,
		NVars:       keccacheck.NUM_VARS,
	}}
	hr := whir.NewPrecomputedHints(allWhirHints)
	whir.VerifyWhir(api, whirVerifier, whirCommitment, hr, statements, whirParams)
}

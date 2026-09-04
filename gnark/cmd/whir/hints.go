package main

import (
	"encoding/binary"
	"math/big"
	"reilabs/keccacheck/keccacheck"
	"sync"
	"unsafe"
)

// parsedProof holds the three proof components extracted from the FFI result.
type parsedProof struct {
	gkrElements []*big.Int
	whirNargFrs []*big.Int
	// hintBlocks[i] holds the pre-parsed field elements for hint call i.
	hintBlocks [][]*big.Int
}

// proveCache caches the parsed FFI result so that the three extraction hints
// (GKR, WHIR proof, WHIR hints) share a single FFI call.
var proveCache *parsedProof
var proveMu sync.Mutex

// getOrComputeProof calls the Rust FFI if needed and caches the parsed result.
func getOrComputeProof(inputs []*big.Int) *parsedProof {
	proveMu.Lock()
	defer proveMu.Unlock()
	if proveCache != nil {
		return proveCache
	}

	ptr := keccacheck.KeccacheckProve(inputs)
	result := (*keccacheck.KeccacheckResult)(ptr)

	// The combined proof buffer contains GKR proof bytes followed by WHIR proof bytes.
	allBytes := unsafe.Slice((*byte)(result.ProofPtr), proofByteLen)
	gkrByteLen := keccacheck.WHIRGKRProofLen * 32

	// GKR proof elements
	gkrElements := keccacheck.GetBigInt4FromBytes(allBytes[:gkrByteLen])

	// Parse raw WHIR byte stream: [narg_len:8 LE][narg bytes][hints_len:8 LE][hints bytes]
	whirBytes := allBytes[gkrByteLen:]

	nargByteLen := int(binary.LittleEndian.Uint64(whirBytes[0:8]))

	nargFrs := keccacheck.GetBigInt4FromBytes(whirBytes[8 : 8+nargByteLen])
	hintsStart := 8 + nargByteLen
	hintsByteLen := int(binary.LittleEndian.Uint64(whirBytes[hintsStart : hintsStart+8]))
	hints := make([]byte, hintsByteLen)
	copy(hints, whirBytes[hintsStart+8:hintsStart+8+hintsByteLen])

	// Pre-parse hint stream into indexed blocks using hintBlockTypes.
	blocks := make([][]*big.Int, len(hintBlockTypes))
	off := 0
	for i, bt := range hintBlockTypes {
		if bt == 0 {
			count := int(binary.LittleEndian.Uint64(hints[off : off+8]))
			off += 8
			blocks[i] = keccacheck.GetBigInt4FromBytes(hints[off : off+count*32])
			off += count * 32
		} else {
			blocks[i] = keccacheck.GetBigInt4FromBytes(hints[off : off+32])
			off += 32
		}
	}

	proveCache = &parsedProof{
		gkrElements: gkrElements,
		whirNargFrs: nargFrs,
		hintBlocks:  blocks,
	}
	return proveCache
}

// ResetProveCache clears the cached FFI result. Call between proof generations
// when the witness changes.
func ResetProveCache() {
	proveMu.Lock()
	defer proveMu.Unlock()
	proveCache = nil
}

// GKRProofHint extracts the GKR proof field elements from the FFI result.
func GKRProofHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	p := getOrComputeProof(inputs)
	for i, v := range p.gkrElements {
		outputs[i].Set(v)
	}
	return nil
}

// WhirProofHint extracts the WHIR narg_string from the FFI result,
// packed into Fr elements (32 bytes per Fr).
func WhirProofHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	p := getOrComputeProof(inputs)
	for i, v := range p.whirNargFrs {
		outputs[i].Set(v)
	}
	return nil
}

// hintBlockTypes holds the pre-computed block type sequence (0=Vec, 1=Hash)
// derived from WHIRParams. Must be set before solving via SetHintBlockTypes.
var hintBlockTypes []int

// proofByteLen holds the total byte length of the combined proof buffer
// (GKR proof bytes + WHIR proof bytes). Set at compile time from params.
var proofByteLen int

func SetHintBlockTypes(blockTypes []int) {
	hintBlockTypes = blockTypes
}

func SetProofByteLen(n int) {
	proofByteLen = n
}

// AllWhirHintsHint returns all hint block data flattened into a single output vector.
// This replaces the previous per-block ReadVecHint/ReadHashHint calls, reducing
// ~7000 hint calls (each marshaling the full input array) to a single call.
func AllWhirHintsHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	p := getOrComputeProof(inputs)
	idx := 0
	for _, block := range p.hintBlocks {
		for _, v := range block {
			outputs[idx].Set(v)
			idx++
		}
	}
	return nil
}

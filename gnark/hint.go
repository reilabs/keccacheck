package main

import (
	"encoding/binary"
	"math/big"
	"sync"
	"unsafe"
)

/*
#cgo LDFLAGS: ./libkeccak.a -ldl -lm
#include "./bindings.h"
*/
import "C"

// Takes input and output words and returns a pointer to an
// array of bytes the keccacheck rounds of the input, the last 25 words of the
// array returned should match the ouput that is feed to the function
func KeccacheckInit(inputs []*big.Int) unsafe.Pointer {
	bytes := make([]byte, (len(inputs))*8)
	for i, input := range inputs {
		input.FillBytes(bytes[i*8 : (i+1)*8])
	}
	len := C.uintptr_t(len(bytes))
	ptr := (*C.uint8_t)(C.CBytes(bytes))
	return C.keccacheck_init(ptr, len)
}

func KeccacheckFree(ptr unsafe.Pointer, len int) {
	C.keccacheck_free(ptr, C.uintptr_t(len))
}

func KeccacheckProve(inputs []*big.Int) unsafe.Pointer {
	r := inputs[0:Log_N]
	r_bytes := make([]byte, 32*Log_N)
	for i, r_i := range r {
		r_i.FillBytes(r_bytes[i*32 : (i+1)*32])
	}

	r_ptr := (*C.uint8_t)(C.CBytes(r_bytes))
	inputs = inputs[Log_N:]
	instances := C.uintptr_t(len(inputs) / 25)

	bytes := make([]byte, (len(inputs))*8)
	for i, input := range inputs {
		input.FillBytes(bytes[i*8 : (i+1)*8])
	}
	ptr := (*C.uint8_t)(C.CBytes(bytes))
	return C.keccacheck_prove(ptr, instances, r_ptr)
}

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

	ptr := KeccacheckProve(inputs)
	result := (*KeccacheckResult)(ptr)

	// The combined proof buffer contains GKR proof bytes followed by WHIR proof bytes.
	allBytes := unsafe.Slice((*byte)(result.ProofPtr), proofByteLen)
	gkrByteLen := MaxGKRProofLen * 32

	// GKR proof elements
	gkrElements := getBigInt4FromBytes(allBytes[:gkrByteLen])

	// Parse raw WHIR byte stream: [narg_len:8 LE][narg bytes][hints_len:8 LE][hints bytes]
	whirBytes := allBytes[gkrByteLen:]

	nargByteLen := int(binary.LittleEndian.Uint64(whirBytes[0:8]))

	nargFrs := getBigInt4FromBytes(whirBytes[8 : 8+nargByteLen])
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
			blocks[i] = getBigInt4FromBytes(hints[off : off+count*32])
			off += count * 32
		} else {
			blocks[i] = getBigInt4FromBytes(hints[off : off+32])
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

// SetHintBlockTypes computes and stores the block type sequence from WHIRParams.
// Called before proof solving so the offset table can be built.
func SetHintBlockTypes(blockTypes []int) {
	hintBlockTypes = blockTypes
}

// SetProofByteLen stores the total combined proof buffer byte length.
func SetProofByteLen(n int) {
	proofByteLen = n
}

// ReadVecHint returns the pre-parsed Vec block at callIndex.
func ReadVecHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	callIndex := int(inputs[len(inputs)-2].Int64())
	p := getOrComputeProof(inputs[:len(inputs)-2])
	for i, v := range p.hintBlocks[callIndex] {
		outputs[i].Set(v)
	}
	return nil
}

// ReadHashHint returns the pre-parsed Hash block at callIndex.
func ReadHashHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	callIndex := int(inputs[len(inputs)-2].Int64())
	p := getOrComputeProof(inputs[:len(inputs)-2])
	outputs[0].Set(p.hintBlocks[callIndex][0])
	return nil
}

func KeccacheckProofFree(proof, input, output unsafe.Pointer, proofLen, instances uint) {
	C.keccacheck_proof_free(proof, C.uintptr_t(proofLen), input, output, C.uintptr_t(instances))
}

func FreeProofHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	proof := unsafe.Pointer(uintptr(inputs[0].Uint64()))
	inp := unsafe.Pointer(uintptr(inputs[1].Uint64()))
	out := unsafe.Pointer(uintptr(inputs[2].Uint64()))
	proofLen := uint(inputs[3].Uint64())
	instances := uint(inputs[4].Uint64())

	KeccacheckProofFree(proof, inp, out, proofLen, instances)

	return nil
}

// HintKeccacheckInit wraps the KeccacheckInit Go/C function into a gnark hint function.
func KeccacheckInitHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {

	ptr := KeccacheckInit(inputs)

	words := unsafe.Slice((*uint64)(ptr), 600)

	for i := 0; i < 600; i++ {
		results[i].SetUint64(words[i])
	}

	return nil
}

// getBigInt4FromBytes interprets a byte slice as a sequence of field elements,
// each stored as 4 little-endian uint64 limbs (32 bytes), matching getBigInt4Slice.
func getBigInt4FromBytes(data []byte) []*big.Int {
	length := len(data) / 32
	bigInts := make([]*big.Int, length)
	for i := 0; i < length; i++ {
		fe := new(big.Int)
		for j := 3; j >= 0; j-- {
			limb := binary.LittleEndian.Uint64(data[i*32+j*8 : i*32+j*8+8])
			fe.Lsh(fe, 64)
			fe.Add(fe, new(big.Int).SetUint64(limb))
		}
		bigInts[i] = fe
	}
	return bigInts
}

package main

import (
	"encoding/binary"
	"math/big"
	"unsafe"
)

/*
#cgo LDFLAGS: ./libkeccak.a -ldl
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
	r_bytes := make([]byte, 32*(Log_N))
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
	whirHints   []byte
}

// proveCache caches the parsed FFI result so that the three extraction hints
// (GKR, WHIR proof, WHIR hints) share a single FFI call. The gnark solver
// evaluates hints in a single goroutine, so a simple global is safe.
var proveCache *parsedProof

// getOrComputeProof calls the Rust FFI if needed and caches the parsed result.
func getOrComputeProof(inputs []*big.Int) *parsedProof {
	if proveCache != nil {
		return proveCache
	}

	ptr := KeccacheckProve(inputs)
	result := (*KeccacheckResult)(ptr)

	// GKR proof elements
	gkrElements := getBigInt4Slice(result.ProofPtr, int(result.ProofLen))

	// Parse raw WHIR byte stream: [narg_len:8 LE][narg bytes][hints_len:8 LE][hints bytes]
	whirBytes := unsafe.Slice((*byte)(result.WhirProofPtr), int(result.WhirProofLen))

	nargByteLen := int(binary.LittleEndian.Uint64(whirBytes[0:8]))
	nargFrs := packBytesToFr(whirBytes[8 : 8+nargByteLen])

	hintsStart := 8 + nargByteLen
	hintsByteLen := int(binary.LittleEndian.Uint64(whirBytes[hintsStart : hintsStart+8]))
	hints := make([]byte, hintsByteLen)
	copy(hints, whirBytes[hintsStart+8:hintsStart+8+hintsByteLen])

	proveCache = &parsedProof{
		gkrElements: gkrElements[1:result.ProofLen],
		whirNargFrs: nargFrs,
		whirHints:   hints,
	}
	return proveCache
}

// ResetProveCache clears the cached FFI result. Call between proof generations
// when the witness changes.
func ResetProveCache() {
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
// packed into Fr elements (31 bytes per Fr).
func WhirProofHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	p := getOrComputeProof(inputs)
	for i, v := range p.whirNargFrs {
		outputs[i].Set(v)
	}
	return nil
}

// WhirHintsHint extracts the WHIR hints from the FFI result as individual
// byte values (Merkle siblings, leaf values, deferred evaluations).
func WhirHintsHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	p := getOrComputeProof(inputs)
	for i, b := range p.whirHints {
		outputs[i].SetUint64(uint64(b))
	}
	return nil
}

func KeccacheckProofFree(proof, whirProof, input, output unsafe.Pointer, whirProofLen, instances, proofLen uint) {
	C.keccacheck_proof_free(proof, whirProof, C.size_t(whirProofLen), input, output, C.size_t(instances), C.size_t(proofLen))
}

func FreeProofHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	proof := unsafe.Pointer(uintptr(inputs[0].Uint64()))
	whirProof := unsafe.Pointer(uintptr(inputs[1].Uint64()))
	whirProofLen := uint(inputs[2].Uint64())
	in := unsafe.Pointer(uintptr(inputs[3].Uint64()))
	out := unsafe.Pointer(uintptr(inputs[4].Uint64()))
	instances := uint(inputs[5].Uint64())
	proofLen := uint(inputs[6].Uint64())

	KeccacheckProofFree(proof, whirProof, in, out, whirProofLen, instances, proofLen)

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

// bytesPerFr is the number of bytes packed into each Fr element (must match
// the Rust BYTES_PER_FR constant in protocol_utils.rs).
const bytesPerFr = 31

// frCountForBytes returns the number of Fr elements needed to pack byteLen bytes.
func frCountForBytes(byteLen int) int {
	return (byteLen + bytesPerFr - 1) / bytesPerFr
}

// packBytesToFr packs a byte slice into big.Int field elements, 31 bytes per
// element using little-endian byte order (matching Rust pack_bytes_to_fr).
func packBytesToFr(data []byte) []*big.Int {
	n := frCountForBytes(len(data))
	result := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		start := i * bytesPerFr
		end := start + bytesPerFr
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]
		// big.Int.SetBytes expects big-endian, so reverse the LE chunk
		reversed := make([]byte, len(chunk))
		for j := range chunk {
			reversed[len(chunk)-1-j] = chunk[j]
		}
		result[i] = new(big.Int).SetBytes(reversed)
	}
	return result
}

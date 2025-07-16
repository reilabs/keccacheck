package main

import (
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
	r := inputs[0 : 6+Log_N]
	r_bytes := make([]byte, 32*(6+Log_N))
	for i, r_i := range r {
		r_i.FillBytes(r_bytes[i*32 : (i+1)*32])
	}

	r_ptr := (*C.uint8_t)(C.CBytes(r_bytes))
	inputs = inputs[6+Log_N:]
	instances := C.uintptr_t(len(inputs) / 25)

	bytes := make([]byte, (len(inputs))*8)
	for i, input := range inputs {
		input.FillBytes(bytes[i*8 : (i+1)*8])
	}
	ptr := (*C.uint8_t)(C.CBytes(bytes))
	return C.keccacheck_prove(ptr, instances, r_ptr)
}

func KeccacheckProveHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	ptr := KeccacheckProve(inputs)
	proof_len := (552 * (Log_N + 6)) + 2929
	result := (*KeccacheckResult)(ptr)

	proof := getBigInt4Slice(result.ProofPtr, proof_len)

	for i := 0; i < proof_len; i++ {
		outputs[i].Set(proof[i])
	}

	return nil
}

func KeccacheckProofFree(proof, input, output unsafe.Pointer, instances uint) {
	C.keccacheck_proof_free(proof, input, output, C.size_t(instances))
}

func FreeProofHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	// Suppose inputs[0] = proof_ptr, inputs[1] = input_ptr, inputs[2] = output_ptr, inputs[3] = instances
	proof := unsafe.Pointer(uintptr(inputs[0].Uint64()))
	in := unsafe.Pointer(uintptr(inputs[1].Uint64()))
	out := unsafe.Pointer(uintptr(inputs[2].Uint64()))
	instances := uint(inputs[3].Uint64())

	KeccacheckProofFree(proof, in, out, instances)

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

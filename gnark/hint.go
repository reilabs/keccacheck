package main

import (
	"fmt"
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
func KeccacheckInit(inputs []*big.Int, outputs []*big.Int) unsafe.Pointer {
	bytes := make([]byte, (len(inputs)+len(outputs))*8)
	for i, input := range inputs {
		input.FillBytes(bytes[i*8 : (i+1)*8])
	}
	for i, output := range outputs {
		j := i + len(inputs)
		output.FillBytes(bytes[j*8 : (j+1)*8])
	}

	len := C.uintptr_t(len(bytes))
	ptr := (*C.uint8_t)(C.CBytes(bytes))
	return C.keccacheck_init(ptr, len)
}

func KeccacheckFree(ptr unsafe.Pointer, len int) {
	C.keccacheck_free(ptr, C.uintptr_t(len))
}

func KeccacheckProve(inputs []*big.Int) unsafe.Pointer {
	instances := C.uintptr_t(len(inputs) / 25)
	bytes := make([]byte, (len(inputs))*8)
	for i, input := range inputs {
		input.FillBytes(bytes[i*8 : (i+1)*8])
	}
	ptr := (*C.uint8_t)(C.CBytes(bytes))
	return C.keccacheck_prove(ptr, instances)
}

func KeccacheckProveHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	ptr := KeccacheckProve(inputs)

	// Convert pointer to uintptr -> uint64 -> *big.Int
	ptrInt := new(big.Int).SetUint64(uint64(uintptr(ptr)))

	// Store in first output slot
	outputs[0].Set(ptrInt)

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

// KeccacheckHint is a gnark hint function that calls the C keccacheck_init and keccacheck_free routines.
func KeccacheckHint(field *big.Int, inputs, outputs []*big.Int) error {
	fmt.Println("field elements", len(inputs))

	return nil
}

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

// KeccacheckHint is a gnark hint function that calls the C keccacheck_init and keccacheck_free routines.
func KeccacheckHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	inputBytes := inputs[0].Bytes()
	inputLen := C.uintptr_t(len(inputBytes))
	inputPtr := (*C.uint8_t)(C.CBytes(inputBytes))
	defer C.free(unsafe.Pointer(inputPtr))

	var outLen C.uintptr_t
	retPtr := C.keccacheck_init(inputPtr, inputLen, &outLen)
	defer C.keccacheck_free(retPtr, outLen)

	// Copy the result from C memory to Go []byte
	result := C.GoBytes(unsafe.Pointer(retPtr), C.int(outLen))
	outputs[0] = new(big.Int).SetBytes(result)

	return nil
}

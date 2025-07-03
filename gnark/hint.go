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
// array of bytes containing those words
//
// i.e. 5 input words and 5 output words will make a byte array of length 80
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

func KeccacheckFree(ptr unsafe.Pointer) {
	// Calls rust box dropping so we don't need to know the
	// size of the memory chunk we are freeing
	C.keccacheck_free(ptr)
}

// KeccacheckHint is a gnark hint function that calls the C keccacheck_init and keccacheck_free routines.
func KeccacheckHint(field *big.Int, inputs, outputs []*big.Int) error {
	fmt.Println("field elements", len(inputs))

	return nil
}

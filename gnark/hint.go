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
	C.keccacheck_free(ptr)
}

// KeccacheckHint is a gnark hint function that calls the C keccacheck_init and keccacheck_free routines.
func KeccacheckHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	fmt.Println("field elements", len(inputs))

	// inputBytes := make([]byte, len(inputs)*4)
	// for i := range inputs {
	// 	inputs[i].FillBytes(inputBytes[i*4 : (i+1)*4])
	// }
	// inputLen := C.uintptr_t(len(inputBytes))
	// inputPtr := (*C.uint8_t)(C.CBytes(inputBytes))
	// defer C.free(unsafe.Pointer(inputPtr))

	// var outLen C.uintptr_t
	// retPtr := C.keccacheck_init(inputPtr, inputLen, &outLen)
	// defer C.keccacheck_free(retPtr, outLen)

	// // Copy the result from C memory to Go []byte
	// result := C.GoBytes(unsafe.Pointer(retPtr), C.int(outLen))
	// outputs[0] = new(big.Int).SetBytes(result)

	return nil
}

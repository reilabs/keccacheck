package keccacheck

import (
	"encoding/binary"
	"math/big"
	"unsafe"
)

/*
#cgo LDFLAGS: ${SRCDIR}/../libkeccak.a -ldl -lm
#include "../bindings.h"
*/
import "C"

// KeccacheckInit takes input words and returns a pointer to the
// keccacheck rounds of the input. The last 25 words of the
// returned array should match the output.
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

// GetBigInt4FromBytes interprets a byte slice as a sequence of field elements,
// each stored as 4 little-endian uint64 limbs (32 bytes).
func GetBigInt4FromBytes(data []byte) []*big.Int {
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

package main

import (
	"math/big"
	"unsafe"

	"github.com/consensys/gnark/frontend"
)

type KeccacheckResult struct {
	ProofPtr  unsafe.Pointer
	InputPtr  unsafe.Pointer
	OutputPtr unsafe.Pointer
}

func getBigIntSlice(ptr unsafe.Pointer, length int) []*big.Int {
	u64slice := unsafe.Slice((*uint64)(ptr), length)

	bigInts := make([]*big.Int, length)
	for i := 0; i < length; i++ {
		bigInts[i] = new(big.Int).SetUint64(u64slice[i])
	}

	return bigInts
}

func getU64Slice(ptr unsafe.Pointer, length int) []uint64 {
	slice := unsafe.Slice((*uint64)(ptr), length)
	return slice
}

func getFSlice(ptr unsafe.Pointer, length int) []frontend.Variable {
	u64slice := getU64Slice(ptr, length*4) // get []uint64

	variables := make([]frontend.Variable, length)

	for i := 0; i < length; i++ {
		fe := new(big.Int)
		for j := 3; j >= 0; j-- { // reconstruct little-endian
			fe.Lsh(fe, 64)
			fe.Add(fe, new(big.Int).SetUint64(u64slice[i*4+j]))
		}
		variables[i] = fe // store directly as frontend.Variable
	}

	return variables
}

func getBigInt4Slice(ptr unsafe.Pointer, length int) []*big.Int {
	u64slice := getU64Slice(ptr, length*4) // assuming each big.Int is 4 uint64s

	bigInts := make([]*big.Int, length)

	for i := 0; i < length; i++ {
		fe := new(big.Int)
		for j := 3; j >= 0; j-- { // little-endian
			fe.Lsh(fe, 64)
			fe.Add(fe, new(big.Int).SetUint64(u64slice[i*4+j]))
		}
		bigInts[i] = fe
	}

	return bigInts
}

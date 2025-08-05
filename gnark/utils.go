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

func decompose_IO(input []*big.Int, output []uint64) ([25 * N]frontend.Variable, [25 * N]frontend.Variable, [25 * 64 * N]frontend.Variable, [25 * 64 * N]frontend.Variable) {
	var inputDSized [64 * 25 * N]frontend.Variable
	var inputSized [25 * N]frontend.Variable
	var outputDSized [64 * 25 * N]frontend.Variable
	var outputSized [25 * N]frontend.Variable

	for i := 0; i < 25; i++ {
		for instance := 0; instance < N; instance++ {
			inputSized[instance*25+i] = input[instance*25+i]
			w := input[instance*25+i]
			for j := 0; j < 64; j++ {
				bit := w.Bit(j)
				inputDSized[64*(i*N+instance)+j] = bit
			}
		}
	}

	for i := 0; i < 25; i++ {
		for instance := 0; instance < N; instance++ {
			w := output[575*N+i*N+instance]
			outputSized[i*N+instance] = w
			for j := 0; j < 64; j++ {
				bit := (w >> j) & 1
				flatIndex := 64*(i*N+instance) + j
				outputDSized[flatIndex] = bit
			}
		}
	}

	return inputSized, outputSized, inputDSized, outputDSized

}

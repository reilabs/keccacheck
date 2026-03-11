package keccacheck

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

func GetU64Slice(ptr unsafe.Pointer, length int) []uint64 {
	slice := unsafe.Slice((*uint64)(ptr), length)
	return slice
}

func PrepareTestIO() ([]*big.Int, []uint64) {
	inputs := make([]*big.Int, 25*N)
	for i := range inputs {
		inputs[i] = big.NewInt(int64(i))
	}

	output_ptr := KeccacheckInit(inputs)
	outputs := unsafe.Slice((*uint64)(output_ptr), 600*N)
	return inputs, outputs
}

// InitCircuitFields prepares circuit fields when input bits are accessed directly.
func InitCircuitFields(input []*big.Int, output []uint64) (
	[]frontend.Variable, []frontend.Variable, []frontend.Variable) {

	inSize := 25 * N
	bitSize := 64 * 25 * N

	inputSized := make([]frontend.Variable, inSize)
	inputDSized := make([]frontend.Variable, bitSize)
	outputSized := make([]frontend.Variable, inSize)

	for i := 0; i < 25; i++ {
		for instance := 0; instance < N; instance++ {
			idx := instance*25 + i
			w := input[idx]
			inputSized[idx] = w

			base := 64 * (i*N + instance)
			for j := 0; j < 64; j++ {
				inputDSized[base+j] = w.Bit(j)
			}
		}
	}

	for i := 0; i < 25; i++ {
		for instance := 0; instance < N; instance++ {
			outputSized[i*N+instance] = output[575*N+i*N+instance]
		}
	}

	return inputSized, inputDSized, outputSized
}

// InitCircuitFieldsWHIR prepares circuit fields when input bits are verified via WHIR.
func InitCircuitFieldsWHIR(input []*big.Int, output []uint64) (
	[]frontend.Variable, []frontend.Variable) {

	inSize := 25 * N

	inputSized := make([]frontend.Variable, inSize)
	outputSized := make([]frontend.Variable, inSize)

	for i := 0; i < 25; i++ {
		for instance := 0; instance < N; instance++ {
			idx := instance*25 + i
			inputSized[idx] = input[idx]
		}
	}

	for i := 0; i < 25; i++ {
		for instance := 0; instance < N; instance++ {
			outputSized[i*N+instance] = output[575*N+i*N+instance]
		}
	}

	return inputSized, outputSized
}

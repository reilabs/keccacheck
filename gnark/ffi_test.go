package main

import (
	"fmt"
	"math/big"
	"testing"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type KeccacheckResult struct {
	ProofPtr  unsafe.Pointer
	InputPtr  unsafe.Pointer
	OutputPtr unsafe.Pointer
}

func TestKeccakInit(t *testing.T) {
	n := 16

	inputs := make([]*big.Int, 25*n)
	for i := range inputs {
		inputs[i] = big.NewInt(0)
	}
	outputs := make([]*big.Int, len(outputValues)*n)
	for i := range n {
		for j, val := range outputValues {
			outputs[i*len(outputValues)+j] = new(big.Int).SetUint64(val)
		}
	}
	ptr := KeccacheckInit(inputs, outputs)
	words := unsafe.Slice((*uint64)(ptr), 600*n)
	for i := range n {
		for j := range 25 {
			expected := outputValues[j]
			actual := words[600*i+575+j]
			if actual != expected {
				t.Errorf("Expected word 600 to be %#x, got %#x", expected, actual)
			}
		}
	}

	KeccacheckFree(ptr, 600*n)
}

func TestKeccakProve(t *testing.T) {
	log_n := 1
	n := 1 << log_n

	inputs := make([]*big.Int, 25*n)
	for i := range inputs {
		inputs[i] = big.NewInt(0)
	}

	ptr := KeccacheckProve(inputs)
	result := (*KeccacheckResult)(ptr)

	input := getU64Slice(result.InputPtr, 25*n)

	for i := range 25 * n {
		if input[i] != 0 {
			t.Errorf("Expected input word  %#x to be 0, got %#x", i, input[i])
		}
	}

	output := getU64Slice(result.OutputPtr, 25*n)

	for j := range 25 {
		for i := range n {
			expected := outputValues[j]
			actual := output[j*n+i]
			if actual != expected {
				t.Errorf("Expected word to be %#x, got %#x", expected, actual)
			}
		}
	}
	proof := getFSlice(result.ProofPtr, (552*(log_n+6) + 2929))

	fmt.Println(proof[6792].String())

}

func getU64Slice(ptr unsafe.Pointer, length int) []uint64 {
	slice := unsafe.Slice((*uint64)(ptr), length)
	return slice
}

func getFSlice(ptr unsafe.Pointer, length int) []fr.Element {
	u64slice := getU64Slice(ptr, length*4) // get []uint64

	frSlice := make([]fr.Element, length)

	for i := 0; i < length; i++ {
		fe := new(big.Int)
		for j := 3; j >= 0; j-- { // reconstruct little-endian
			fe.Lsh(fe, 64)
			fe.Add(fe, new(big.Int).SetUint64(u64slice[i*4+j]))
		}
		frSlice[i].SetBigInt(fe) // handles Montgomery reduction
	}

	return frSlice
}

// Output values represent the expected output of
// the KeccakF permutation function on an array of Zeroes
var outputValues = []uint64{
	0xF1258F7940E1DDE7,
	0x84D5CCF933C0478A,
	0xD598261EA65AA9EE,
	0xBD1547306F80494D,
	0x8B284E056253D057,
	0xFF97A42D7F8E6FD4,
	0x90FEE5A0A44647C4,
	0x8C5BDA0CD6192E76,
	0xAD30A6F71B19059C,
	0x30935AB7D08FFC64,
	0xEB5AA93F2317D635,
	0xA9A6E6260D712103,
	0x81A57C16DBCF555F,
	0x43B831CD0347C826,
	0x01F22F1A11A5569F,
	0x05E5635A21D9AE61,
	0x64BEFEF28CC970F2,
	0x613670957BC46611,
	0xB87C5A554FD00ECB,
	0x8C3EE88A1CCF32C8,
	0x940C7922AE3A2614,
	0x1841F924A2C509E4,
	0x16F53526E70465C2,
	0x75F644E97F30A13B,
	0xEAF1FF7B5CECA249,
}

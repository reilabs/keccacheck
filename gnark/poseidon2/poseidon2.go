package poseidon2

import (
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

func Compress(api frontend.API, input []frontend.Variable, RC16_0 [][16]frontend.Variable, RC16_1 []frontend.Variable, RC16_2 [][16]frontend.Variable) frontend.Variable {
	if len(input) <= 16 {
		var state [16]frontend.Variable
		// Fill with input, zero-pad the rest
		for i := 0; i < len(input); i++ {
			state[i] = input[i]
		}
		for i := len(input); i < 16; i++ {
			state[i] = frontend.Variable(0)
		}
		Permute16(api, &state)
		return state[0]
	} else {
		var state [16]frontend.Variable

		// Compute largest power of 16 < len(input)
		n := len(input)
		log2 := bits.Len(uint(n - 1))
		power := 4 * ((log2 - 1) / 4)
		chunk := 1 << power

		for i := 0; i < 16 && len(input) > 0; i++ {
			currentChunkSize := chunk
			if currentChunkSize > len(input) {
				currentChunkSize = len(input)
			}
			state[i] = Compress(api, input[:currentChunkSize], RC16_0, RC16_1, RC16_2)
			input = input[currentChunkSize:]
		}
		// Fill remaining slots with zero if less than 16 chunks
		for i := len(input) / chunk; i < 16; i++ {
			state[i] = frontend.Variable(0)
		}
		Permute16(api, &state)
		return state[0]
	}
}

func Permute3(api frontend.API, state *[3]frontend.Variable) {
	RC30 := parseTwoDimensionArray(first_full_rc3)
	RC32 := parseTwoDimensionArray(second_full_rc3)
	RC31 := parseOneDimensionArray(partial_rc3)
	MatFull3(api, state)

	// RC3.0 rounds
	for _, rc := range RC30 {
		for i := 0; i < 3; i++ {
			state[i] = api.Add(state[i], rc[i])
		}
		for i := 0; i < 3; i++ {
			state[i] = Sbox(api, state[i])
		}
		MatFull3(api, state)
	}

	// RC3.1 rounds
	for _, rc := range RC31 {
		state[0] = api.Add(state[0], rc)
		state[0] = Sbox(api, state[0])

		// sum = Σ state[i]
		sum := frontend.Variable(0)
		for i := 0; i < 3; i++ {
			sum = api.Add(sum, state[i])
		}

		// double state[2]
		state[2] = api.Add(state[2], state[2])

		// add sum to each slot
		for i := 0; i < 3; i++ {
			state[i] = api.Add(state[i], sum)
		}
	}

	// RC3.2 rounds
	for _, rc := range RC32 {
		for i := 0; i < 3; i++ {
			state[i] = api.Add(state[i], rc[i])
		}
		for i := 0; i < 3; i++ {
			state[i] = Sbox(api, state[i])
		}
		MatFull3(api, state)
	}
}

func Permute16(api frontend.API, state *[16]frontend.Variable,
) {

	RC16_0 := parseTwoDimensionArray(first_full_rc16)
	RC16_2 := parseTwoDimensionArray(second_full_rc16)
	RC16_1 := parseOneDimensionArray(partial_rc16)
	// Full round
	MatFull16(api, state)

	// First set of full rounds
	for _, rc := range RC16_0 {
		// Add round constants
		for i := 0; i < 16; i++ {
			state[i] = api.Add(state[i], rc[i])
		}

		// Apply S-box x^5 to all
		for i := 0; i < 16; i++ {
			state[i] = Sbox(api, state[i])
		}

		// Full round
		MatFull16(api, state)
	}

	// Partial rounds
	for _, rc := range RC16_1 {
		// Add rc to state[0]
		state[0] = api.Add(state[0], rc)

		// Apply S-box x^5 only to state[0]
		state[0] = Sbox(api, state[0])

		// Partial round mixing
		MatPartial16(api, state)
	}

	// Final set of full rounds
	for _, rc := range RC16_2 {
		// Add round constants
		for i := 0; i < 16; i++ {
			state[i] = api.Add(state[i], rc[i])
		}

		// Apply S-box x^5 to all
		for i := 0; i < 16; i++ {
			state[i] = Sbox(api, state[i])
		}

		// Full round
		MatFull16(api, state)
	}
}

func MatFull3(api frontend.API, state *[3]frontend.Variable) {

	sum := frontend.Variable(0)
	for _, s := range state {
		sum = api.Add(sum, s)
	}
	for i, s := range state {
		state[i] = api.Add(sum, s)
	}
}

func matFull4(api frontend.API, state []frontend.Variable) {
	if len(state) != 4 {
		panic("matFull4 requires state of length 4")
	}
	t0 := api.Add(state[0], state[1])
	t1 := api.Add(state[2], state[3])

	t2 := api.Add(Double(api, state[1]), t1)
	t3 := api.Add(Double(api, state[3]), t0)

	t4 := api.Add(Double(api, Double(api, t1)), t3)
	t5 := api.Add(Double(api, Double(api, t0)), t2)

	t6 := api.Add(t3, t5)
	t7 := api.Add(t2, t4)

	state[0] = t6
	state[1] = t5
	state[2] = t7
	state[3] = t4
}

func MatFull16(api frontend.API, state *[16]frontend.Variable) {

	sum := make([]frontend.Variable, 4)
	for i := 0; i < 4; i++ {
		sum[i] = frontend.Variable(0) // initialize sum = [0; 4]
	}

	// First pass: apply matFull4 and accumulate into sum
	for i := 0; i < 4; i++ {
		chunk := state[i*4 : (i+1)*4]

		matFull4(api, chunk)

		for j := 0; j < 4; j++ {
			sum[j] = api.Add(sum[j], chunk[j])
		}
	}

	// Second pass: add sum[j] to each chunk[j]
	for i := 0; i < 4; i++ {
		chunk := state[i*4 : (i+1)*4]
		for j := 0; j < 4; j++ {
			chunk[j] = api.Add(chunk[j], sum[j])
		}
	}
}

func MatPartial16(api frontend.API, state *[16]frontend.Variable) {
	// Compute sum = Σ state[i]
	sum := frontend.Variable(0)
	for i := 0; i < 16; i++ {
		sum = api.Add(sum, state[i])
	}
	// 0
	state[0] = frontend.Variable(0)

	// 1: no change

	// 2
	state[2] = Double(api, state[2])

	// 3
	state[3] = api.Add(state[3], Double(api, state[3]))

	// 4
	tmp := Double(api, state[4])
	tmp = Double(api, tmp)
	state[4] = tmp

	// 5
	tmp = Double(api, state[5])
	tmp = Double(api, tmp)
	state[5] = api.Add(state[5], tmp)

	// 6
	tmp = Double(api, state[6])
	tmp2 := Double(api, tmp)
	state[6] = api.Add(tmp, tmp2)

	// 7
	t := state[7]
	tmp = Double(api, state[7])
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	state[7] = api.Sub(tmp, t)

	// 8
	tmp = Double(api, state[8])
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	state[8] = tmp

	// 9
	tmp = Double(api, state[9])
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	state[9] = api.Add(state[9], tmp)

	// 10
	tmp = Double(api, state[10])
	tmp2 = Double(api, tmp)
	tmp2 = Double(api, tmp2)
	state[10] = api.Add(tmp, tmp2)

	// 11
	t = state[11]
	tmp = Double(api, state[11])
	tmp2 = Double(api, tmp)
	tmp2 = Double(api, tmp2)
	tmp3 := api.Add(tmp, tmp2)
	state[11] = api.Add(tmp3, t)

	// 13
	t1 := state[12]
	tmp = Double(api, state[12])
	t2 := tmp
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	tmp = api.Sub(tmp, t1)
	tmp = api.Sub(tmp, t2)
	state[12] = tmp

	// 14
	tmp = Double(api, state[13])
	t2 = tmp
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	tmp = api.Sub(tmp, t2)
	state[13] = tmp

	// 16
	tmp = Double(api, state[14])
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	state[14] = tmp

	// 17
	t = state[15]
	tmp = Double(api, state[15])
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	tmp = Double(api, tmp)
	state[15] = api.Add(tmp, t)

	// Add sum back to each slot
	for i := 0; i < 16; i++ {
		state[i] = api.Add(state[i], sum)
	}
}

func Sbox(api frontend.API, x frontend.Variable) frontend.Variable {
	x2 := api.Mul(x, x)
	x4 := api.Mul(x2, x2)
	x5 := api.Mul(x, x4)
	return x5
}

func Double(api frontend.API, x frontend.Variable) frontend.Variable {
	return api.Add(x, x)
}

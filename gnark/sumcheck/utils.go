package sumcheck

import (
	"github.com/consensys/gnark/frontend"
)

func EvalMle(api frontend.API, mle []frontend.Variable, r []frontend.Variable) frontend.Variable {
	n := len(r)
	size := 1 << n
	if len(mle) != size {
		panic("mle length must be 2^len(r)")
	}

	// Start from the full mle and reduce layer by layer
	coeffs := mle

	for i := 0; i < n; i++ {
		newSize := len(coeffs) / 2
		next := make([]frontend.Variable, newSize)
		oneMinusRi := api.Sub(1, r[i])
		for j := 0; j < newSize; j++ {
			left := api.Mul(oneMinusRi, coeffs[j])
			right := api.Mul(r[i], coeffs[newSize+j])
			next[j] = api.Add(left, right)
		}
		coeffs = next
	}

	return coeffs[0]
}

func EvalMleWithEq(api frontend.API, mle []frontend.Variable, eq []frontend.Variable) frontend.Variable {
	if len(mle) != len(eq) {
		panic("mle and eq must have the same length")
	}

	acc := api.Mul(eq[0], mle[0])
	for i := 1; i < len(mle); i++ {
		acc = api.Add(acc, api.Mul(eq[i], mle[i]))
	}

	return acc
}

func Eq(api frontend.API, a, b []frontend.Variable) frontend.Variable {
	if len(a) != len(b) {
		panic("a and b must have the same length")
	}
	res := frontend.Variable(1)

	for i := range a {
		term1 := api.Mul(a[i], b[i])
		term2 := api.Mul(api.Sub(1, a[i]), api.Sub(1, b[i]))
		res = api.Mul(res, api.Add(term1, term2))
	}
	return res
}

func ToPoly(api frontend.API, x []frontend.Variable) []frontend.Variable {
	res := make([]frontend.Variable, 0, len(x)*64)
	for _, el := range x {
		bits := api.ToBinary(el, 64)
		// bits[0] = LSB, bits[63] = MSB

		// If you want LSB-first:
		res = append(res, bits[:]...)
	}
	return res
}

func Rot(api frontend.API, n int, a, b []frontend.Variable) frontend.Variable {
	lenA := len(a)
	prefix := lenA - 6

	// r = calculate_evaluations_over_boolean_hypercube_for_rot(&a[prefix..], n)
	r := CalculateEvaluationsOverBooleanHypercubeForRot(api, a[prefix:], n)

	// result = eval_mle(&r, &b[prefix..])
	result := EvalMle(api, r, b[prefix:])

	// Compute the product term
	prod := frontend.Variable(1)
	for i := 0; i < prefix; i++ {
		x := a[i]
		y := b[i]
		xy := api.Mul(x, y)
		oneMinusX := api.Sub(1, x)
		oneMinusY := api.Sub(1, y)
		oneMinusXoneMinusY := api.Mul(oneMinusX, oneMinusY)
		sum := api.Add(xy, oneMinusXoneMinusY)
		prod = api.Mul(prod, sum)
	}

	// Return result * prod
	return api.Mul(result, prod)
}

func EvalEq(api frontend.API, r []frontend.Variable) []frontend.Variable {
	n := len(r)

	eq := []frontend.Variable{
		api.Sub(1, r[0]), // x_0 = 0
		r[0],             // x_0 = 1
	}
	for i := 1; i < n; i++ {
		ri := r[i]
		oneMinusRi := api.Sub(1, ri)

		newEq := make([]frontend.Variable, 0, len(eq)*2)
		for _, v := range eq {
			newEq = append(newEq, api.Mul(v, oneMinusRi)) // x_i = 0
			newEq = append(newEq, api.Mul(v, ri))         // x_i = 1
		}
		eq = newEq
	}

	return eq
}
func CalculateEvaluationsOverBooleanHypercubeForRot(api frontend.API, r []frontend.Variable, i int) []frontend.Variable {
	eq := EvalEq(api, r)
	return DeriveRotEvaluationsFromEq(api, &eq, RHO_OFFSETS[i])
}

/// List of evaluations for rot_i(r, x) over the boolean hypercube
// pub fn calculate_evaluations_over_boolean_hypercube_for_rot(r: &[Fr], i: usize) -> Vec<Fr> {
//     let eq = calculate_evaluations_over_boolean_hypercube_for_eq(r);
//     derive_rot_evaluations_from_eq(&eq, RHO_OFFSETS[i] as usize)
// }

func DeriveRotEvaluationsFromEq(api frontend.API, eq *[]frontend.Variable, size int) []frontend.Variable {
	result := make([]frontend.Variable, len(*eq))
	instances := len(*eq) / 64

	for instance := range instances {
		for i := range 64 {
			result[instance*64+i] = (*eq)[instance*64+(i+size)%64]
		}
	}
	return result
}

func Xor(api frontend.API, a, b frontend.Variable) frontend.Variable {
	ab := api.Mul(a, b)
	return api.Sub(api.Sub(api.Add(a, b), ab), ab)
}

func AddCol(j, add int) int {
	col := j % 5
	row := j - col
	return ((col+add)%5 + row)
}

var RHO_OFFSETS = [25]int{
	0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
}

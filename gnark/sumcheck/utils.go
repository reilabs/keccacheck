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
		for j := 0; j < newSize; j++ {
			diff := api.Sub(coeffs[newSize+j], coeffs[j])
			next[j] = api.Add(coeffs[j], api.Mul(r[i], diff))
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
		// a*b + (1-a)(1-b) = 2ab - a - b + 1
		ab := api.Mul(a[i], b[i])
		term := api.Add(api.Add(ab, ab), api.Sub(api.Sub(1, a[i]), b[i]))
		res = api.Mul(res, term)
	}
	return res
}

func ToPoly(api frontend.API, x []frontend.Variable) []frontend.Variable {
	res := make([]frontend.Variable, 0, len(x)*64)
	for _, el := range x {
		bits := api.ToBinary(el, 64)

		res = append(res, bits[:]...)
	}
	return res
}

func Rot(api frontend.API, n int, eq_a_suffix, eq_b_suffix []frontend.Variable, prefixEq frontend.Variable) frontend.Variable {
	// r = calculate_evaluations_over_boolean_hypercube_for_rot(&a[prefix..], n)
	r := CalculateEvaluationsOverBooleanHypercubeForRot(api, eq_a_suffix, n)

	// result = eval_mle(&r, &b[prefix..])
	result := EvalMleWithEq(api, r, eq_b_suffix)

	// Return result * precomputed prefix eq product
	return api.Mul(result, prefixEq)
}

// PrefixEq computes eq(a[0:prefix], b[0:prefix]) as a single scalar.
// This is factored out so callers can compute it once and reuse across
// multiple Rot calls with the same prefix vectors.
func PrefixEq(api frontend.API, a, b []frontend.Variable, prefix int) frontend.Variable {
	prod := frontend.Variable(1)
	for i := 0; i < prefix; i++ {
		ab := api.Mul(a[i], b[i])
		term := api.Add(api.Add(ab, ab), api.Sub(api.Sub(1, a[i]), b[i]))
		prod = api.Mul(prod, term)
	}
	return prod
}

func EvalEq(api frontend.API, r []frontend.Variable) []frontend.Variable {
	n := len(r)
	if n == 0 {
		return []frontend.Variable{frontend.Variable(1)}
	}

	eq := []frontend.Variable{
		api.Sub(1, r[0]),
		r[0],
	}
	for i := 1; i < n; i++ {
		oneMinusRi := api.Sub(1, r[i])

		newEq := make([]frontend.Variable, 0, len(eq)*2)
		for _, v := range eq {
			lo := api.Mul(v, oneMinusRi)
			hi := api.Sub(v, lo) // v*r = v - v*(1-r), free linear combination
			newEq = append(newEq, lo)
			newEq = append(newEq, hi)
		}
		eq = newEq
	}

	return eq
}
func CalculateEvaluationsOverBooleanHypercubeForRot(api frontend.API, r []frontend.Variable, i int) []frontend.Variable {
	return DeriveRotEvaluationsFromEq(api, &r, RHO_OFFSETS[i])
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

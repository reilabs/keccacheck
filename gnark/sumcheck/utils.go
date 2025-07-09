package sumcheck

import (
	"fmt"
	"math/big"

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

func ToPoly(api frontend.API, x []big.Int) []frontend.Variable {
	res := make([]frontend.Variable, 0, len(x)*64)

	one := frontend.Variable(1)
	zero := frontend.Variable(0)

	for idx, el := range x {
		if el.BitLen() > 64 {
			panic(fmt.Sprintf("ToPoly: element at index %d exceeds 64 bits (bit length = %d)", idx, el.BitLen()))
		}
		for i := 0; i < 64; i++ {
			if el.Bit(i) == 1 {
				res = append(res, one)
			} else {
				res = append(res, zero)
			}
		}
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

func CalculateEvaluationsOverBooleanHypercubeForEq(api frontend.API, r []frontend.Variable) []frontend.Variable {
	size := 1 << len(r)
	result := make([]frontend.Variable, size)
	for i := range result {
		result[i] = frontend.Variable(0)
	}
	EvalEq(api, &r, &result, frontend.Variable(1))
	return result
}

func CalculateEvaluationsOverBooleanHypercubeForRot(api frontend.API, r []frontend.Variable, i int) []frontend.Variable {
	eq := CalculateEvaluationsOverBooleanHypercubeForEq(api, r)
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
func EvalEq(api frontend.API, eval, out *[]frontend.Variable, scalar frontend.Variable) {
	size := len(*out)
	if len(*eval) > 0 {
		x := (*eval)[0]
		tail := (*eval)[1:]

		mid := size / 2
		o0 := (*out)[:mid]
		o1 := (*out)[mid:]

		s1 := api.Mul(scalar, x)
		s0 := api.Sub(scalar, s1)

		EvalEq(api, &tail, &o0, s0)
		EvalEq(api, &tail, &o1, s1)
	} else {
		(*out)[0] = api.Add((*out)[0], scalar)
	}
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

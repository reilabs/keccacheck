package sumcheck

import "github.com/consensys/gnark/frontend"

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

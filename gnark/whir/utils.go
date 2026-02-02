package whir

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func IsEqual(api frontend.API, uapi *uints.BinaryField[uints.U64], indexes []frontend.Variable, merkleIndexes []uints.U64) error {
	api.AssertIsEqual(len(indexes), len(merkleIndexes))

	merkleVars := make([]frontend.Variable, len(merkleIndexes))
	for i, index := range merkleIndexes {
		merkleVars[i] = uapi.ToValue(index)
	}

	for i := range indexes {
		api.AssertIsEqual(indexes[i], merkleVars[i])
	}

	return nil
}

func Exponent(api frontend.API, uapi *uints.BinaryField[uints.U64], X frontend.Variable, Y uints.U64) frontend.Variable {
	output := frontend.Variable(1)
	bits := api.ToBinary(uapi.ToValue(Y))
	multiply := frontend.Variable(X)
	for i := range bits {
		output = api.Select(bits[i], api.Mul(output, multiply), output)
		multiply = api.Mul(multiply, multiply)
	}
	return output
}

// Given some randomeness r, return a vector r^0, r^1,...r^{len-1}
func ExpandRandomness(api frontend.API, base frontend.Variable, len int) []frontend.Variable {
	res := make([]frontend.Variable, len)
	acc := frontend.Variable(1)
	for i := range len {
		res[i] = acc
		acc = api.Mul(acc, base)
	}
	return res
}

func DotProduct(api frontend.API, a []frontend.Variable, b []frontend.Variable) frontend.Variable {
	var acc = frontend.Variable(0)
	for i := range a {
		acc = api.Add(acc, api.Mul(a[i], b[i]))
	}
	return acc
}

func CheckSumOverBool(api frontend.API, value frontend.Variable, polyEvals []frontend.Variable) {
	sumOverBools := api.Add(polyEvals[0], polyEvals[1])
	api.AssertIsEqual(value, sumOverBools)
}

// EvaluateQuadraticPolynomialFromEvaluationList performs Lagrange interpolation on a
// quadratic polynomial P(x) defined by evaluations over the domain {0, 1, 2}.
//
// Given the input vector E = [P(0), P(1), P(2)], it computes the value P(r)
// for an arbitrary point 'r' by deriving the coefficients a, b, c such that:
//
//	P(x) = ax^2 + bx + c
//
// The coefficients are computed as:
//
//	c = P(0)
//	b = (-P(2) + 4P(1) - 3P(0)) / 2
//	a = ( P(2) - 2P(1) +  P(0)) / 2
//
// This allows the verifier to evaluate the polynomial at a random challenge point
// using only the evaluations provided by the prover.
func EvaluateQuadraticPolynomialFromEvaluationList(api frontend.API, evaluations []frontend.Variable, point frontend.Variable) (ans frontend.Variable) {
	inv2 := api.Inverse(2)
	b0 := evaluations[0]
	b1 := api.Mul(api.Add(api.Neg(evaluations[2]), api.Mul(4, evaluations[1]), api.Mul(-3, evaluations[0])), inv2)
	b2 := api.Mul(api.Add(evaluations[2], api.Mul(-2, evaluations[1]), evaluations[0]), inv2)
	return api.Add(api.Mul(point, point, b2), api.Mul(point, b1), b0)
}

func MultivarPoly(coefs []frontend.Variable, vars []frontend.Variable, api frontend.API) frontend.Variable {
	if len(vars) == 0 {
		return coefs[0]
	}
	deg_zero := MultivarPoly(coefs[:len(coefs)/2], vars[:len(vars)-1], api)
	deg_one := api.Mul(vars[len(vars)-1], MultivarPoly(coefs[len(coefs)/2:], vars[:len(vars)-1], api))
	return api.Add(deg_zero, deg_one)
}

func UnivarPoly(api frontend.API, coefficients []frontend.Variable, points []frontend.Variable) []frontend.Variable {
	if len(points) == 0 {
		return coefficients
	}

	results := make([]frontend.Variable, len(points))
	for j := range points {
		ans := frontend.Variable(0)
		for i := range coefficients {
			ans = api.Add(api.Mul(ans, points[j]), coefficients[len(coefficients)-1-i])
		}
		results[j] = ans
	}
	return results
}

func EqPolyOutside(api frontend.API, coords []frontend.Variable, point []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(1)
	for i := range coords {
		acc = api.Mul(acc, api.Add(api.Mul(coords[i], point[i]), api.Mul(api.Sub(frontend.Variable(1), coords[i]), api.Sub(frontend.Variable(1), point[i]))))
	}
	return acc
}

func Reverse[T any](s []T) []T {
	res := make([]T, len(s))
	copy(res, s)
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		res[i], res[j] = s[j], s[i]
	}
	return res
}

// calculateShiftValue returns the dot product of the concatenated OOD answers
// and folded values against a vector of random challenges.
// Used to verify random linear combinations in FRI-based protocols.
func CalculateShiftValue(oodAnswers []frontend.Variable, combinationRandomness []frontend.Variable, computedFold []frontend.Variable, api frontend.API) frontend.Variable {
	return DotProduct(api, append(oodAnswers, computedFold...), combinationRandomness)
}

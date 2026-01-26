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

func EvaluateQuadraticPolynomialFromEvaluationList(api frontend.API, evaluations []frontend.Variable, point frontend.Variable) (ans frontend.Variable) {
	inv2 := api.Inverse(2)
	b0 := evaluations[0]
	b1 := api.Mul(api.Add(api.Neg(evaluations[2]), api.Mul(4, evaluations[1]), api.Mul(-3, evaluations[0])), inv2)
	b2 := api.Mul(api.Add(evaluations[2], api.Mul(-2, evaluations[1]), evaluations[0]), inv2)
	return api.Add(api.Mul(point, point, b2), api.Mul(point, b1), b0)
}

package sumcheck

import (
	"math/big"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
)

var halfString = "10944121435919637611123202872628637544274182200208017171849102093287904247809"

// Verify sumcheck for $N$-degree univariate polynomials.
// I.e. N = 1 for linear, 2 for quadratic, etc.
func VerifySumcheck(api frontend.API, verifier *transcript.Verifier, num_polys int, degree int, e frontend.Variable) (frontend.Variable, []frontend.Variable) {
	half, ok := new(big.Int).SetString(halfString, 10)
	if !ok {
		panic("Could not parse the half string")
	}
	rs := make([]frontend.Variable, num_polys)

	for i := 0; i < num_polys; i++ {
		// get an array of size degree from the transcript
		p := make([]frontend.Variable, degree)
		for j := range degree {
			p[j] = verifier.Read(api)
		}
		sum := frontend.Variable(0)
		for j := range degree {
			sum = api.Add(sum, p[j])
		}
		p0 := api.Mul(half, api.Sub(e, sum))

		// add randomness to randomness vector
		r := verifier.Generate(api)
		rs[i] = r

		// p(r) = p0 + p[0] ⋅ r + p[1] ⋅ r^2 + ...
		acc := p[degree-1]
		for j := degree - 2; j >= 0; j-- {
			acc = api.Add(p[j], api.Mul(r, acc))
		}
		e = api.Add(p0, api.Mul(r, acc))
	}
	return e, rs
}

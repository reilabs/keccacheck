package main

import (
	"C"
	"log"
	"math/big"
	"reilabs/keccacheck/sumcheck"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
)

func VerifyKeccakF(api frontend.API, num_vars int, input, output, proof, r []frontend.Variable) {
	instances := 1 << (num_vars - 6)
	verifier := transcript.NewVerifier(proof)

	beta := make([]frontend.Variable, 25)

	for i := range 25 {
		beta[i] = verifier.Generate(api)
	}

	expected_sum := frontend.Variable(0)

	eval_eq_r := sumcheck.EvalEq(api, r)
	for i := range 25 {
		summand := sumcheck.EvalMleWithEq(api, output[(64*(i*instances)):64*(i*instances+instances)], eval_eq_r)
		expected_sum = api.Add(expected_sum, api.Mul(summand, beta[i]))
	}
	sum := verifier.Read(api)

	api.AssertIsEqual(sum, expected_sum)
	iota := make([]frontend.Variable, 25)

	for i := 23; i >= 0; i-- {
		r, iota = VerifyRound(api, verifier, num_vars, &r, &beta, sum, ROUND_CONSTANTS[i])
		if i != 0 {
			sum = frontend.Variable(0)
			for j := range beta {
				beta[j] = verifier.Generate(api)
				sum = api.Add(api.Mul(beta[j], iota[j]), sum)
			}
		}
	}
	eval_eq_r = sumcheck.EvalEq(api, r)
	for i := 0; i < 25; i++ {
		start := i * instances
		end := start + instances
		poly := input[64*start : 64*end]
		eval := sumcheck.EvalMleWithEq(api, poly, eval_eq_r)
		api.AssertIsEqual(eval, iota[i])
	}

}

func VerifyRound(api frontend.API, verifier *transcript.Verifier, numVars int, alpha *[]frontend.Variable, beta *[]frontend.Variable, sum frontend.Variable, rc uint64) ([]frontend.Variable, []frontend.Variable) {
	ve, vrsIota := sumcheck.VerifySumcheck(api, verifier, numVars, 3, sum)

	chi00 := verifier.Read(api)
	chiRlc := verifier.Read(api)
	eEq := sumcheck.Eq(api, *alpha, vrsIota)
	rcPoly := sumcheck.ToPoly(api, []frontend.Variable{big.NewInt(0).SetUint64(rc)})
	eRc := sumcheck.EvalMle(api, rcPoly, vrsIota[len(vrsIota)-6:])
	xorVal := sumcheck.Xor(api, chi00, eRc)
	inner := api.Add(api.Mul((*beta)[0], xorVal), chiRlc)
	api.AssertIsEqual(api.Mul(eEq, inner), ve)

	x := verifier.Generate(api)
	y := verifier.Generate(api)
	(*beta)[0] = api.Mul((*beta)[0], x)
	for i := 1; i < len(*beta); i++ {
		(*beta)[i] = api.Mul((*beta)[i], y)
	}
	expectedSum := api.Add(api.Mul((*beta)[0], chi00), api.Mul(y, chiRlc))

	// Verify chi
	ve, vrsChi := sumcheck.VerifySumcheck(api, verifier, numVars, 4, expectedSum)
	pi := make([]frontend.Variable, 25)
	for i := 0; i < 25; i++ {
		pi[i] = verifier.Read(api)
	}

	eEq = sumcheck.Eq(api, vrsIota, vrsChi)
	checksumPi := frontend.Variable(0)
	for i := 0; i < len(pi); i++ {
		term := sumcheck.Xor(
			api,
			pi[i],
			api.Mul(
				api.Sub(frontend.Variable(1), pi[sumcheck.AddCol(i, 1)]),
				pi[sumcheck.AddCol(i, 2)],
			),
		)
		checksumPi = api.Add(checksumPi, api.Mul(eEq, (*beta)[i], term))
	}
	api.AssertIsEqual(checksumPi, ve)

	rho := make([]frontend.Variable, len(pi))
	copy(rho, pi)

	stripPi(pi, rho)

	// --- Combine subclaims on rho ---
	expectedSum = frontend.Variable(0)
	for i := 0; i < len(*beta); i++ {
		(*beta)[i] = verifier.Generate(api)
		expectedSum = api.Add(expectedSum, api.Mul((*beta)[i], rho[i]))
	}
	// --- Verify rho ---
	ve, vrsRho := sumcheck.VerifySumcheck(api, verifier, numVars, 2, expectedSum)

	// Read theta
	theta := make([]frontend.Variable, 25)
	for i := 0; i < 25; i++ {
		theta[i] = verifier.Read(api)
	}

	// Compute e_eq and e_rot for chi

	eRot := make([]frontend.Variable, 25)
	prefix := len(vrsChi) - 6
	eq_vrsChi_prefix := sumcheck.EvalEq(api, vrsChi[prefix:])
	eq_vrsRhoPrefix := sumcheck.EvalEq(api, vrsRho[prefix:])
	for i := 0; i < 25; i++ {
		eRot[i] = sumcheck.Rot(api, i, vrsChi, vrsRho, eq_vrsChi_prefix, eq_vrsRhoPrefix)
	}

	// Compute checksum for rho verification
	checksum := frontend.Variable(0)
	for i := 0; i < 25; i++ {
		term := api.Mul((*beta)[i], eRot[i], theta[i])
		checksum = api.Add(checksum, term)
	}
	api.AssertIsEqual(checksum, ve)

	// --- combine subclaims on theta, change base ---
	thetaXorBase := make([]frontend.Variable, len(theta))
	for i := range theta {
		// theta_xor_base[i] = 1 - theta[i] - theta[i]
		// equivalent to 1 - 2*theta[i]
		doubleTheta := api.Add(theta[i], theta[i])
		thetaXorBase[i] = api.Sub(frontend.Variable(1), doubleTheta)
	}

	expectedSum = frontend.Variable(0)
	for i := 0; i < len(*beta); i++ {
		(*beta)[i] = verifier.Generate(api)
		expectedSum = api.Add(expectedSum, api.Mul((*beta)[i], thetaXorBase[i]))
	}

	// --- verify theta ---
	ve, vrsTheta := sumcheck.VerifySumcheck(api, verifier, numVars, 3, expectedSum)

	// read ai and d vectors (length 5 each)
	ai := make([]frontend.Variable, 5)
	d := make([]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		ai[i] = verifier.Read(api)
	}
	for i := 0; i < 5; i++ {
		d[i] = verifier.Read(api)
	}

	eEq = sumcheck.Eq(api, vrsRho, vrsTheta)

	// checksum = sum_{j=0}^4 eEq * d[j] * ai[j]
	checksum = frontend.Variable(0)
	for j := 0; j < 5; j++ {
		term := api.Mul(eEq, d[j], ai[j])
		checksum = api.Add(checksum, term)
	}
	api.AssertIsEqual(checksum, ve)

	// --- combine subclaims on theta d ---
	expectedSum = frontend.Variable(0)
	betaD := make([]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		betaD[i] = verifier.Generate(api)
		expectedSum = api.Add(expectedSum, api.Mul(betaD[i], d[i]))
	}

	// --- verify theta d ---
	ve, vrsD := sumcheck.VerifySumcheck(api, verifier, numVars, 3, expectedSum)

	// read c and rot_c vectors (length 5 each)
	c := make([]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		c[i] = verifier.Read(api)
	}
	rotC := make([]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		rotC[i] = verifier.Read(api)
	}

	eEq = sumcheck.Eq(api, vrsTheta, vrsD)

	checksum = frontend.Variable(0)
	for j := 0; j < len(c); j++ {
		idx1 := (j + 4) % 5
		idx2 := (j + 1) % 5
		term := api.Mul(betaD[j], eEq, c[idx1], rotC[idx2])
		checksum = api.Add(checksum, term)
	}
	api.AssertIsEqual(ve, checksum)

	// --- combine subclaims on theta c and rot_c ---
	expectedSum = frontend.Variable(0)
	betaC := make([]frontend.Variable, 5)
	betaRotC := make([]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		betaC[i] = verifier.Generate(api)
		expectedSum = api.Add(expectedSum, api.Mul(betaC[i], c[i]))
	}
	for i := 0; i < 5; i++ {
		betaRotC[i] = verifier.Generate(api)
		expectedSum = api.Add(expectedSum, api.Mul(betaRotC[i], rotC[i]))
	}

	// --- verify theta c ---
	ve, vrsC := sumcheck.VerifySumcheck(api, verifier, numVars, 6, expectedSum)

	// read a vector (length 25)
	a := make([]frontend.Variable, 25)
	for i := 0; i < 25; i++ {
		a[i] = verifier.Read(api)
	}

	prefix = len(vrsD) - 6
	eq_vrsD_prefix := sumcheck.EvalEq(api, vrsD[prefix:])
	eq_vrsCPrefix := sumcheck.EvalEq(api, vrsC[prefix:])
	eEq = sumcheck.Eq(api, vrsD, vrsC)
	eRot_1 := sumcheck.Rot(api, 1, vrsD, vrsC, eq_vrsD_prefix, eq_vrsCPrefix)

	checksum = frontend.Variable(0)
	for j := 0; j < 5; j++ {
		product := frontend.Variable(1)
		for i := 0; i < 5; i++ {
			product = api.Mul(product, a[i*5+j])
		}
		checksum = api.Add(checksum, api.Mul(betaC[j], eEq, product))
		checksum = api.Add(checksum, api.Mul(betaRotC[j], eRot_1, product))
	}
	api.AssertIsEqual(ve, checksum)

	// --- combine claims on a from theta and theta c ---
	expectedSum = frontend.Variable(0)
	betaA := make([]frontend.Variable, len(a))

	for i, val := range ai {
		b := verifier.Generate(api)
		for j := 0; j < 5; j++ {
			idx := j*5 + i
			(*beta)[idx] = api.Mul((*beta)[idx], b)
		}
		expectedSum = api.Add(expectedSum, api.Mul(b, val))
	}

	for i := range betaA {
		betaA[i] = verifier.Generate(api)
		expectedSum = api.Add(expectedSum, api.Mul(betaA[i], a[i]))
	}

	// --- verify theta a ---
	ve, vrsA := sumcheck.VerifySumcheck(api, verifier, numVars, 2, expectedSum)

	// read iota vector (length 25)
	iota := make([]frontend.Variable, 25)
	for i := 0; i < 25; i++ {
		iota[i] = verifier.Read(api)
	}

	eEqAi := sumcheck.Eq(api, vrsTheta, vrsA)
	eEqA := sumcheck.Eq(api, vrsC, vrsA)

	checksum = frontend.Variable(0)
	for j := 0; j < len(iota); j++ {
		term := api.Add(
			api.Mul((*beta)[j], eEqAi, iota[j]),
			api.Mul(betaA[j], eEqA, iota[j]),
		)
		checksum = api.Add(checksum, term)
	}
	api.AssertIsEqual(ve, checksum)

	// --- change iota base ---
	half, ok := new(big.Int).SetString(halfString, 10)
	if !ok {
		panic("Could not parse the half string")
	}
	for i := range iota {
		val := api.Sub(frontend.Variable(1), iota[i])
		iota[i] = api.Mul(half, val)
	}

	return vrsA, iota

}

func stripPi[T any](pi []T, rho []T) {
	if len(pi) != len(rho) {
		log.Panicf("pi and rho length mismatch: %d vs %d", len(pi), len(rho))
	}
	if len(rho)%STATE != 0 {
		log.Panicf("rho length (%d) not a multiple of STATE (%d)", len(rho), STATE)
	}
	instances := len(rho) / STATE

	lastStart := instances
	lastEnd := instances * 2

	for i := 0; i < 24; i++ {
		targetStart := instances * PI[i]
		targetEnd := instances * (PI[i] + 1)

		copy(rho[lastStart:lastEnd], pi[targetStart:targetEnd])

		lastStart = targetStart
		lastEnd = targetEnd
	}
}

var COLUMNS = 5
var ROWS = 5
var STATE = COLUMNS * ROWS

var ROUND_CONSTANTS = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

var PI = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

var halfString = "10944121435919637611123202872628637544274182200208017171849102093287904247809"

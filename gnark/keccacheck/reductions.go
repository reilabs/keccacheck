package keccacheck

import (
	"log"
	"math/big"
	"reilabs/keccacheck/sumcheck"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
)

// VerifyGKR absorbs challenges, computes the expected output sum, reduces output
// words to input bits, and verifies all 24 rounds. Returns the final beta,
// alpha, and iota from round verification.
func VerifyGKR(
	api frontend.API,
	verifier *transcript.Verifier,
	alpha []frontend.Variable,
	output []frontend.Variable,
) ([]frontend.Variable, []frontend.Variable, []frontend.Variable) {
	for _, challenge := range alpha {
		verifier.Absorb(api, challenge)
	}
	beta := make([]frontend.Variable, 25)

	for i := range 25 {
		beta[i] = verifier.Generate(api)
	}

	expected_sum := frontend.Variable(0)
	eval_eq_r := sumcheck.EvalEq(api, alpha)
	for i := range 25 {
		summand := sumcheck.EvalMleWithEq(api, output[(i*N):(i*N+N)], eval_eq_r)
		expected_sum = api.Add(expected_sum, api.Mul(summand, beta[i]))
	}

	sum := verifier.Read(api)
	api.AssertIsEqual(sum, expected_sum)

	// Reduce claims on output words to claims on input bits
	alpha, sum = ReduceOutputWords(api, verifier, alpha, sum)

	iota := make([]frontend.Variable, 25)

	for i := 23; i >= 0; i-- {
		alpha, iota = VerifyRound(api, verifier, NUM_VARS, &alpha, &beta, sum, ROUND_CONSTANTS[i])
		if i != 0 {
			sum = frontend.Variable(0)
			for j := range beta {
				beta[j] = verifier.Generate(api)
				sum = api.Add(api.Mul(beta[j], iota[j]), sum)
			}
		}
	}

	return beta, alpha, iota
}

// ReduceOutputWords reduces claims on output words to a claim on input bits.
// Returns the updated alpha and sum for the round loop.
func ReduceOutputWords(
	api frontend.API,
	verifier *transcript.Verifier,
	alpha []frontend.Variable,
	sum frontend.Variable,
) ([]frontend.Variable, frontend.Variable) {
	c_1, r_x := sumcheck.VerifySumcheck(api, verifier, Log_N, 2, sum)
	words_r_x := verifier.Read(api)
	eq_r_alpha_x := sumcheck.Eq(api, r_x, alpha)
	api.AssertIsEqual(c_1, api.Mul(words_r_x, eq_r_alpha_x))

	c_2, r_y := sumcheck.VerifySumcheck(api, verifier, 6, 2, words_r_x)
	b_r_x_r_y := verifier.Read(api)

	powers := PowersOfTwo()
	powers_eval := sumcheck.EvalMle(api, powers, r_y)
	api.AssertIsEqual(c_2, api.Mul(powers_eval, b_r_x_r_y))

	newAlpha := append(r_x, r_y...)
	return newAlpha, b_r_x_r_y
}

// PowersOfTwo returns a slice of 2^i for i in 0..63.
func PowersOfTwo() []frontend.Variable {
	powers := make([]frontend.Variable, 1<<6)
	for i := 0; i < 1<<6; i++ {
		powers[i] = frontend.Variable(uint64(1) << uint(i))
	}
	return powers
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
	eq_vrsChi_suffix := sumcheck.EvalEq(api, vrsChi[prefix:])
	eq_vrsRhoSuffix := sumcheck.EvalEq(api, vrsRho[prefix:])
	rotPrefixEq := sumcheck.PrefixEq(api, vrsChi, vrsRho, prefix)
	for i := 0; i < 25; i++ {
		eRot[i] = sumcheck.Rot(api, i, eq_vrsChi_suffix, eq_vrsRhoSuffix, rotPrefixEq)
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
	eq_vrsD_suffix := sumcheck.EvalEq(api, vrsD[prefix:])
	eq_vrsCsuffix := sumcheck.EvalEq(api, vrsC[prefix:])
	thetaCPrefixEq := sumcheck.PrefixEq(api, vrsD, vrsC, prefix)
	eEq = sumcheck.Eq(api, vrsD, vrsC)
	eRot_1 := sumcheck.Rot(api, 1, eq_vrsD_suffix, eq_vrsCsuffix, thetaCPrefixEq)

	checksum = frontend.Variable(0)
	for j := 0; j < 5; j++ {
		product := frontend.Variable(1)
		for i := 0; i < 5; i++ {
			product = api.Mul(product, a[i*5+j])
		}
		combined := api.Add(api.Mul(betaC[j], eEq), api.Mul(betaRotC[j], eRot_1))
		checksum = api.Add(checksum, api.Mul(combined, product))
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
	half, ok := new(big.Int).SetString(HalfString, 10)
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

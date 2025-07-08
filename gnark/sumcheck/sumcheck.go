package sumcheck

import (
	"reilabs/keccacheck/sponge"

	"github.com/consensys/gnark/frontend"
)

type SumcheckVerifier struct {
	sponge sponge.Sponge
}

func (verifier *SumcheckVerifier) verify_sumcheck(proof []frontend.Variable) {
}

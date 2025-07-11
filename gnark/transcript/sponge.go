package transcript

import (
	"fmt"
	"math/big"
	"reilabs/keccacheck/poseidon2"

	"github.com/consensys/gnark/frontend"
)

var initStrings = [3]string{
	"2867665590057683943387987502116419498891846156328125724",
	"17997256069650684234135964296173026564613294187689219101164463450718816256962",
	"23490056820540387704221111928924589790986076392885762195133186689225695129646",
}

type SpongeState uint8

const (
	Initial SpongeState = iota
	Absorbing
	Squeezing
	Full
)

type Sponge struct {
	State  [3]frontend.Variable
	sponge SpongeState
}

func NewSponge() *Sponge {
	var state [3]frontend.Variable

	for i, s := range initStrings {
		c, ok := new(big.Int).SetString(s, 10)
		if !ok {
			panic(fmt.Sprintf("invalid string for big.Int: %s", s))
		}
		state[i] = c
	}

	return &Sponge{
		State:  state,
		sponge: Initial,
	}
}

func (s *Sponge) absorb(api frontend.API, value frontend.Variable) {
	switch s.sponge {
	case Initial:
		s.State[0] = api.Add(value, s.State[0])
		s.sponge = Absorbing

	case Absorbing:
		s.State[1] = api.Add(value, s.State[1])
		s.sponge = Full

	case Squeezing, Full:
		poseidon2.Permute3(api, &s.State)
		s.State[0] = api.Add(value, s.State[0])
		s.sponge = Absorbing
	}

}

func (s *Sponge) Squeeze(api frontend.API) frontend.Variable {
	switch s.sponge {
	case Initial:
		s.sponge = Squeezing
		return s.State[0]

	case Squeezing:
		s.sponge = Full
		return s.State[1]

	case Absorbing, Full:
		poseidon2.Permute3(api, &s.State)
		s.sponge = Squeezing
		return s.State[0]

	}
	panic("this cannot happen")
}

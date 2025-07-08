package transcript

import "github.com/consensys/gnark/frontend"

type Verifier struct {
	sponge Sponge
	Proof  []frontend.Variable
	index  int
}

// NewVerifier initializes a new verifier with a sponge and proof elements.
func NewVerifier(proof []frontend.Variable) *Verifier {
	return &Verifier{
		sponge: *NewSponge(),
		Proof:  proof,
		index:  0,
	}
}

// Generate squeezes a value from the sponge.
func (v *Verifier) Generate(api frontend.API) frontend.Variable {
	return v.sponge.Squeeze(api)
}

// Read reveals the next value and absorbs it into the sponge.
func (v *Verifier) Read(api frontend.API) frontend.Variable {
	value := v.Reveal()
	v.sponge.absorb(api, value)
	return value
}

// Reveal gets the next element from the proof slice.
func (v *Verifier) Reveal() frontend.Variable {
	if v.index >= len(v.Proof) {
		panic("Ran out of proof elements.")
	}
	value := v.Proof[v.index]
	v.index++
	return value
}

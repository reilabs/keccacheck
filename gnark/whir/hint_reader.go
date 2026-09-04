package whir

import (
	"github.com/consensys/gnark/frontend"
)

// PrecomputedHints provides indexed access to a flat vector of precomputed hint
// data. It replaces the old HintReader which issued per-element NewHint calls.
// ReadVec and ReadHash simply advance through the flat slice.
type PrecomputedHints struct {
	flat   []frontend.Variable
	offset int
}

// NewPrecomputedHints wraps a flat hint vector for sequential consumption.
func NewPrecomputedHints(flat []frontend.Variable) *PrecomputedHints {
	return &PrecomputedHints{flat: flat}
}

// ReadVec reads n field elements from the precomputed hint data.
func (p *PrecomputedHints) ReadVec(n int) []frontend.Variable {
	result := p.flat[p.offset : p.offset+n]
	p.offset += n
	return result
}

// ReadHash reads a single field element from the precomputed hint data.
func (p *PrecomputedHints) ReadHash() frontend.Variable {
	result := p.flat[p.offset]
	p.offset++
	return result
}

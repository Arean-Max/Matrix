package quasigroup

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const Order = 256

// Quasigroup represents a finite non-associative, non-commutative quasigroup of order 256.
// The underlying Cayley table forms an order-256 Latin square.
type Quasigroup struct {
	Table         [Order][Order]uint8
	LeftDivision  [Order][Order]uint8 // x \ z = y such that x * y = z
	RightDivision [Order][Order]uint8 // z / y = x such that x * y = z
}

// GenerateIsotopicQuasigroup builds a non-associative Latin square using two affine S-boxes
// and an isotopic permutation: x * y = P(S1(x) + S2(y) mod 256).
func GenerateIsotopicQuasigroup(seed []byte) (*Quasigroup, error) {
	s1 := generatePermutation(seed, 0x1B)
	s2 := generatePermutation(seed, 0x3D)
	p := generatePermutation(seed, 0x5F)

	q := &Quasigroup{}
	for x := 0; x < Order; x++ {
		for y := 0; y < Order; y++ {
			sum := uint8((uint16(s1[x]) + uint16(s2[y])) % Order)
			val := p[sum]
			q.Table[x][y] = val
			q.LeftDivision[x][val] = uint8(y)
			q.RightDivision[val][y] = uint8(x)
		}
	}

	if err := q.ValidateLatinSquare(); err != nil {
		return nil, fmt.Errorf("generated table violates Latin square property: %w", err)
	}

	if !q.VerifyNonAssociativity() {
		return nil, errors.New("generated quasigroup is degenerate (associative)")
	}

	return q, nil
}

// Multiply evaluates x * y in the quasigroup.
func (q *Quasigroup) Multiply(x, y uint8) uint8 {
	return q.Table[x][y]
}

// LeftDiv solves x * y = z for y.
func (q *Quasigroup) LeftDiv(x, z uint8) uint8 {
	return q.LeftDivision[x][z]
}

// RightDiv solves x * y = z for x.
func (q *Quasigroup) RightDiv(z, y uint8) uint8 {
	return q.RightDivision[z][y]
}

// ValidateLatinSquare checks that every row and every column contains each element 0..255 exactly once.
func (q *Quasigroup) ValidateLatinSquare() error {
	for r := 0; r < Order; r++ {
		var rowSeen [Order]bool
		for c := 0; c < Order; c++ {
			val := q.Table[r][c]
			if rowSeen[val] {
				return fmt.Errorf("duplicate value %d in row %d at column %d", val, r, c)
			}
			rowSeen[val] = true
		}
	}

	for c := 0; c < Order; c++ {
		var colSeen [Order]bool
		for r := 0; r < Order; r++ {
			val := q.Table[r][c]
			if colSeen[val] {
				return fmt.Errorf("duplicate value %d in col %d at row %d", val, c, r)
			}
			colSeen[val] = true
		}
	}

	return nil
}

// VerifyNonAssociativity confirms (x * y) * z != x * (y * z) for at least one triple.
func (q *Quasigroup) VerifyNonAssociativity() bool {
	nonAssociativeCount := 0
	samples := 512

	for i := 0; i < samples; i++ {
		x := uint8((i * 17) % Order)
		y := uint8((i*31 + 7) % Order)
		z := uint8((i*43 + 13) % Order)

		lhs := q.Multiply(q.Multiply(x, y), z)
		rhs := q.Multiply(x, q.Multiply(y, z))

		if lhs != rhs {
			nonAssociativeCount++
		}
	}

	return nonAssociativeCount > (samples * 8 / 10)
}

// ExportBytes serializes the 65,536-byte Cayley table.
func (q *Quasigroup) ExportBytes() []byte {
	buf := make([]byte, Order*Order)
	for r := 0; r < Order; r++ {
		copy(buf[r*Order:(r+1)*Order], q.Table[r][:])
	}
	return buf
}

// ImportBytes reconstructs a Quasigroup from raw 65,536-byte table.
func ImportBytes(buf []byte) (*Quasigroup, error) {
	if len(buf) != Order*Order {
		return nil, fmt.Errorf("invalid buffer size: got %d, expected %d", len(buf), Order*Order)
	}
	q := &Quasigroup{}
	for r := 0; r < Order; r++ {
		for c := 0; c < Order; c++ {
			val := buf[r*Order+c]
			q.Table[r][c] = val
			q.LeftDivision[r][val] = uint8(c)
			q.RightDivision[val][c] = uint8(r)
		}
	}
	if err := q.ValidateLatinSquare(); err != nil {
		return nil, err
	}
	return q, nil
}

// ExportCHeader emits a C/C++ static header containing the Cayley lookup table.
func (q *Quasigroup) ExportCHeader(varName string) string {
	var sb strings.Builder
	sb.WriteString("// Generated Non-Associative Quasigroup Table (Order 256)\n")
	sb.WriteString("#pragma once\n#include <stdint.h>\n\n")
	sb.WriteString(fmt.Sprintf("alignas(64) static const uint8_t %s[256][256] = {\n", varName))

	for r := 0; r < Order; r++ {
		sb.WriteString("    {")
		for c := 0; c < Order; c++ {
			sb.WriteString(fmt.Sprintf("0x%02X", q.Table[r][c]))
			if c < Order-1 {
				sb.WriteString(", ")
			}
		}
		if r < Order-1 {
			sb.WriteString("},\n")
		} else {
			sb.WriteString("}\n")
		}
	}
	sb.WriteString("};\n")
	return sb.String()
}

// ExtractCarvedDiagonals extracts dynamic diagonal elements to be streamed from the server (Section 2.11.8).
func (q *Quasigroup) ExtractCarvedDiagonals() ([]byte, [Order]uint8) {
	carved := make([]byte, Order)
	var original [Order]uint8
	for i := 0; i < Order; i++ {
		original[i] = q.Table[i][i]
		carved[i] = q.Table[i][i]
		// In client binary, the diagonal is zeroed out until Dn arrives
		q.Table[i][i] = 0x00
	}
	return carved, original
}

// RestoreCarvedDiagonals re-inserts the dynamic diagonal received from server.
func (q *Quasigroup) RestoreCarvedDiagonals(diagonals []byte) error {
	if len(diagonals) != Order {
		return fmt.Errorf("invalid diagonal length: got %d, expected %d", len(diagonals), Order)
	}
	for i := 0; i < Order; i++ {
		q.Table[i][i] = diagonals[i]
		q.LeftDivision[i][diagonals[i]] = uint8(i)
		q.RightDivision[diagonals[i]][i] = uint8(i)
	}
	return nil
}

// generatePermutation generates a bijective 256-element S-box from a seed and tweak.
func generatePermutation(seed []byte, tweak byte) [Order]uint8 {
	var s [Order]uint8
	for i := 0; i < Order; i++ {
		s[i] = uint8(i)
	}

	var state uint64 = 0x8546702987498231 ^ uint64(tweak)
	if len(seed) >= 8 {
		state ^= binary.LittleEndian.Uint64(seed[:8])
	} else if len(seed) > 0 {
		var tmp [8]byte
		copy(tmp[:], seed)
		state ^= binary.LittleEndian.Uint64(tmp[:])
	} else {
		var randBytes [8]byte
		_, _ = rand.Read(randBytes[:])
		state ^= binary.LittleEndian.Uint64(randBytes[:])
	}

	// Fisher-Yates shuffle with 64-bit LCG
	for i := Order - 1; i > 0; i-- {
		state = state*6364136223846793005 + 1442695040888963407
		j := int((state >> 32) % uint64(i+1))
		s[i], s[j] = s[j], s[i]
	}

	return s
}

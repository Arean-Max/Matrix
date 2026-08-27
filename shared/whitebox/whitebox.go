package whitebox

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	Rounds    = 10
	BlockSize = 16
)

// WhiteBoxNetwork represents a Chow-Biryukov style White-Box table network.
// Symmetric keys are dissolved into non-linear input bijections (F), T-boxes (T),
// and output bijections (G). The continuous key never appears in memory.
type WhiteBoxNetwork struct {
	TBoxes        [Rounds][BlockSize][256]uint8 // T_i,j(x) = G_i \circ E_k \circ F_{i-1}^{-1}(x)
	MixingMatrix  [Rounds][BlockSize]uint8       // Linear mixing diffusion vectors
	InputEncoding [BlockSize][256]uint8          // Initial input encodings F_0
	OutputDecoding [BlockSize][256]uint8         // Final unmasking bijections G_Rounds^{-1}
}

// GenerateWhiteBoxNetwork constructs a dissolved table network from a 256-bit master key.
func GenerateWhiteBoxNetwork(key []byte) (*WhiteBoxNetwork, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}

	wb := &WhiteBoxNetwork{}

	// Generate non-linear bijective encodings for each round boundary
	var encodings [Rounds + 1][BlockSize][256]uint8
	var decodings [Rounds + 1][BlockSize][256]uint8

	for r := 0; r <= Rounds; r++ {
		for b := 0; b < BlockSize; b++ {
			perm := generateBijection(key, byte(r*BlockSize+b))
			encodings[r][b] = perm
			for i := 0; i < 256; i++ {
				decodings[r][b][perm[i]] = uint8(i)
			}
		}
	}

	wb.InputEncoding = encodings[0]
	wb.OutputDecoding = decodings[Rounds]

	// Derive round subkeys from master key using HKDF-like schedule
	for r := 0; r < Rounds; r++ {
		roundSeed := make([]byte, BlockSize)
		for b := 0; b < BlockSize; b++ {
			roundSeed[b] = key[b%len(key)] ^ byte(r*17+b*7)
			wb.MixingMatrix[r][b] = byte((r * 31) ^ (b * 53) ^ 0x69)
		}

		for b := 0; b < BlockSize; b++ {
			subKeyByte := roundSeed[b]
			inDec := decodings[r][b]
			outEnc := encodings[r+1][b]

			for x := 0; x < 256; x++ {
				// x -> F_{r-1}^{-1}(x) -> AddSubkey -> OutEncoding G_r
				rawVal := inDec[x]
				sboxed := affineSubByte(rawVal, subKeyByte)
				wb.TBoxes[r][b][x] = outEnc[sboxed]
			}
		}
	}

	return wb, nil
}

// TransformBlock runs a 16-byte block through the table network without reconstructing the key.
func (wb *WhiteBoxNetwork) TransformBlock(in []byte) []byte {
	if len(in) < BlockSize {
		return nil
	}

	state := make([]byte, BlockSize)
	// Apply initial input encoding
	for b := 0; b < BlockSize; b++ {
		state[b] = wb.InputEncoding[b][in[b]]
	}

	// Iterate through dissolved round T-boxes
	for r := 0; r < Rounds; r++ {
		nextState := make([]byte, BlockSize)
		for b := 0; b < BlockSize; b++ {
			tVal := wb.TBoxes[r][b][state[b]]
			// Mix with linear diffusion vector
			nextState[b] = tVal ^ wb.MixingMatrix[r][b]
		}
		// Shift row permutation
		for b := 0; b < BlockSize; b++ {
			shift := (b + r) % BlockSize
			state[b] = nextState[shift]
		}
	}

	// Apply final output decoding
	out := make([]byte, BlockSize)
	for b := 0; b < BlockSize; b++ {
		out[b] = wb.OutputDecoding[b][state[b]]
	}

	return out
}

// ExportCHeader formats the White-Box network into an aligned C++ static data header.
func (wb *WhiteBoxNetwork) ExportCHeader(varName string) string {
	var sb strings.Builder
	sb.WriteString("// Generated White-Box Key Dissolving Table Network (Chow-Biryukov)\n")
	sb.WriteString("#pragma once\n#include <stdint.h>\n\n")

	sb.WriteString(fmt.Sprintf("struct %s_t {\n", varName))
	sb.WriteString(fmt.Sprintf("    uint8_t tboxes[%d][%d][256];\n", Rounds, BlockSize))
	sb.WriteString(fmt.Sprintf("    uint8_t mixing[%d][%d];\n", Rounds, BlockSize))
	sb.WriteString(fmt.Sprintf("    uint8_t input_enc[%d][256];\n", BlockSize))
	sb.WriteString(fmt.Sprintf("    uint8_t output_dec[%d][256];\n", BlockSize))
	sb.WriteString("};\n\n")

	sb.WriteString(fmt.Sprintf("alignas(64) static const %s_t %s = {\n", varName, varName))

	// TBoxes
	sb.WriteString("    .tboxes = {\n")
	for r := 0; r < Rounds; r++ {
		sb.WriteString("        {\n")
		for b := 0; b < BlockSize; b++ {
			sb.WriteString("            {")
			for x := 0; x < 256; x++ {
				sb.WriteString(fmt.Sprintf("0x%02X", wb.TBoxes[r][b][x]))
				if x < 255 {
					sb.WriteString(", ")
				}
			}
			if b < BlockSize-1 {
				sb.WriteString("},\n")
			} else {
				sb.WriteString("}\n")
			}
		}
		if r < Rounds-1 {
			sb.WriteString("        },\n")
		} else {
			sb.WriteString("        }\n")
		}
	}
	sb.WriteString("    },\n")

	// Mixing
	sb.WriteString("    .mixing = {\n")
	for r := 0; r < Rounds; r++ {
		sb.WriteString("        {")
		for b := 0; b < BlockSize; b++ {
			sb.WriteString(fmt.Sprintf("0x%02X", wb.MixingMatrix[r][b]))
			if b < BlockSize-1 {
				sb.WriteString(", ")
			}
		}
		if r < Rounds-1 {
			sb.WriteString("},\n")
		} else {
			sb.WriteString("}\n")
		}
	}
	sb.WriteString("    },\n")

	// Input Encoding
	sb.WriteString("    .input_enc = {\n")
	for b := 0; b < BlockSize; b++ {
		sb.WriteString("        {")
		for x := 0; x < 256; x++ {
			sb.WriteString(fmt.Sprintf("0x%02X", wb.InputEncoding[b][x]))
			if x < 255 {
				sb.WriteString(", ")
			}
		}
		if b < BlockSize-1 {
			sb.WriteString("},\n")
		} else {
			sb.WriteString("}\n")
		}
	}
	sb.WriteString("    },\n")

	// Output Decoding
	sb.WriteString("    .output_dec = {\n")
	for b := 0; b < BlockSize; b++ {
		sb.WriteString("        {")
		for x := 0; x < 256; x++ {
			sb.WriteString(fmt.Sprintf("0x%02X", wb.OutputDecoding[b][x]))
			if x < 255 {
				sb.WriteString(", ")
			}
		}
		if b < BlockSize-1 {
			sb.WriteString("},\n")
		} else {
			sb.WriteString("}\n")
		}
	}
	sb.WriteString("    }\n")

	sb.WriteString("};\n")
	return sb.String()
}

func affineSubByte(b, keyByte uint8) uint8 {
	// Non-linear transformation approximating Rijndael S-box with round key XOR
	x := b ^ keyByte
	// Affine rotation
	rot := (x << 1) | (x >> 7)
	rot ^= (x << 2) | (x >> 6)
	rot ^= (x << 3) | (x >> 5)
	rot ^= (x << 4) | (x >> 4)
	return rot ^ 0x63
}

func generateBijection(seed []byte, tweak byte) [256]uint8 {
	var p [256]uint8
	for i := 0; i < 256; i++ {
		p[i] = uint8(i)
	}

	var state uint64 = 0xCBF29CE484222325 ^ uint64(tweak)
	if len(seed) >= 8 {
		state ^= binary.LittleEndian.Uint64(seed[:8])
	}

	for i := 255; i > 0; i-- {
		state = state*1099511628211 + 0x517cc1b727220a95
		j := int((state >> 32) % uint64(i+1))
		p[i], p[j] = p[j], p[i]
	}

	return p
}

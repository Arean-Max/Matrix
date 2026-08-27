package whitebox

import (
	"bytes"
	"testing"
)

func TestWhiteBoxGenerationAndTransformation(t *testing.T) {
	key := bytes.Repeat([]byte{0x7A}, 32)
	wb, err := GenerateWhiteBoxNetwork(key)
	if err != nil {
		t.Fatalf("failed to generate whitebox network: %v", err)
	}

	block := []byte("1234567890abcdef") // 16 bytes
	transformed := wb.TransformBlock(block)
	if len(transformed) != BlockSize {
		t.Fatalf("expected transformed block length %d, got %d", BlockSize, len(transformed))
	}

	// Deterministic transformation for same input
	transformed2 := wb.TransformBlock(block)
	if !bytes.Equal(transformed, transformed2) {
		t.Fatal("expected deterministic output for identical input block")
	}

	// Different input produces different output
	differentBlock := []byte("1234567890abcdeg")
	transformed3 := wb.TransformBlock(differentBlock)
	if bytes.Equal(transformed, transformed3) {
		t.Fatal("expected distinct outputs for distinct inputs")
	}

	header := wb.ExportCHeader("wb_network")
	if len(header) == 0 {
		t.Fatal("exported C header is empty")
	}
}

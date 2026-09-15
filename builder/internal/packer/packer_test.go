package packer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackerPathAAndPathB(t *testing.T) {
	tempDir := t.TempDir()
	sampleInput := filepath.Join(tempDir, "sample.dll")
	_ = os.WriteFile(sampleInput, []byte("MZ\x90\x00\x03\x00\x00\x00test-pe-payload"), 0755)

	outA := filepath.Join(tempDir, "out_a.bin")
	resA, err := PackTarget(PackOptions{
		Mode:       ModePathA,
		InputFile:  sampleInput,
		OutputFile: outA,
	})
	if err != nil {
		t.Fatalf("Path A packaging failed: %v", err)
	}
	if resA.Mode != ModePathA {
		t.Fatalf("expected ModePathA, got %s", resA.Mode)
	}

	// Verify whitebox header was generated
	wbHeader := filepath.Join(tempDir, "whitebox_tables.h")
	if _, err := os.Stat(wbHeader); os.IsNotExist(err) {
		t.Fatal("expected whitebox_tables.h to be generated")
	}

	outB := filepath.Join(tempDir, "out_b.bin")
	resB, err := PackTarget(PackOptions{
		Mode:       ModePathB,
		InputFile:  sampleInput,
		OutputFile: outB,
	})
	if err != nil {
		t.Fatalf("Path B packaging failed: %v", err)
	}
	if resB.WarningMessage == "" {
		t.Fatal("expected Path B to have warning message regarding EDR risk")
	}
}

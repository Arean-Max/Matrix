package quasigroup

import (
	"testing"
)

func TestQuasigroupGenerationAndProperties(t *testing.T) {
	seed := []byte("test-event-horizon-seed-001")
	q, err := GenerateIsotopicQuasigroup(seed)
	if err != nil {
		t.Fatalf("failed to generate quasigroup: %v", err)
	}

	if err := q.ValidateLatinSquare(); err != nil {
		t.Fatalf("latin square validation failed: %v", err)
	}

	if !q.VerifyNonAssociativity() {
		t.Fatal("expected quasigroup to be non-associative")
	}

	// Test division operations (Cayley inverse properties)
	for x := 0; x < Order; x += 17 {
		for y := 0; y < Order; y += 23 {
			ux := uint8(x)
			uy := uint8(y)
			z := q.Multiply(ux, uy)

			// Left division: ux \ z should give uy
			if q.LeftDiv(ux, z) != uy {
				t.Fatalf("left div failed: %d \\ %d != %d", ux, z, uy)
			}

			// Right division: z / uy should give ux
			if q.RightDiv(z, uy) != ux {
				t.Fatalf("right div failed: %d / %d != %d", z, uy, ux)
			}
		}
	}
}

func TestQuasigroupCarvedDiagonals(t *testing.T) {
	seed := []byte("carved-diagonal-seed")
	q, err := GenerateIsotopicQuasigroup(seed)
	if err != nil {
		t.Fatalf("failed to generate quasigroup: %v", err)
	}

	carved, original := q.ExtractCarvedDiagonals()
	for i := 0; i < Order; i++ {
		if q.Table[i][i] != 0 {
			t.Fatalf("expected carved diagonal to be 0 at [%d][%d], got %d", i, i, q.Table[i][i])
		}
		if carved[i] != original[i] {
			t.Fatalf("mismatched carved value at index %d", i)
		}
	}

	if err := q.RestoreCarvedDiagonals(carved); err != nil {
		t.Fatalf("failed to restore carved diagonals: %v", err)
	}

	if err := q.ValidateLatinSquare(); err != nil {
		t.Fatalf("restored table fails Latin square validation: %v", err)
	}
}

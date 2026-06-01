package wire

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidHex(t *testing.T) {
	if !ValidHex("00ff", 2) {
		t.Fatal("valid hex rejected")
	}
	if ValidHex("00FG", 2) {
		t.Fatal("uppercase/invalid accepted")
	}
	if ValidHex("0f", 2) {
		t.Fatal("wrong length accepted")
	}
	if !ValidFingerprint(strings.Repeat("ab", 32)) {
		t.Fatal("valid fingerprint rejected")
	}
	if ValidFingerprint(strings.Repeat("ab", 31)) {
		t.Fatal("short fingerprint accepted")
	}
}

func TestValidCode(t *testing.T) {
	if !ValidCode("12345678") {
		t.Fatal("valid code rejected")
	}
	for _, c := range []string{"1234567", "123456789", "1234567a", "", "1234 678"} {
		if ValidCode(c) {
			t.Fatalf("invalid code %q accepted", c)
		}
	}
}

func TestValidB64(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if !ValidB64(valid, 32) {
		t.Fatal("valid base64 rejected")
	}
	if ValidB64(valid, 31) {
		t.Fatal("wrong size accepted")
	}
	if ValidB64("!!!", 2) {
		t.Fatal("malformed base64 accepted")
	}
}

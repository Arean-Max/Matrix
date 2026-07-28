package trustd

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadLineLimited(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("{\"ok\":true}\n"), 64)
	line, err := readLineLimited(r, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != "{\"ok\":true}\n" {
		t.Fatalf("line = %q", line)
	}
}

func TestReadLineLimitedRejectsOversize(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", 2048)+"\n"), 64)
	if _, err := readLineLimited(r, 256); err == nil {
		t.Fatal("oversize line accepted")
	}
}

func TestReadLineLimitedEOF(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("partial"), 64)
	if _, err := readLineLimited(r, 1024); err == nil {
		t.Fatal("unterminated line accepted")
	}
}

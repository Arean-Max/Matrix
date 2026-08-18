package packaging

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testID = "demo-payload"

func sealTest(t *testing.T) ([]byte, *Provision, []byte) {
	t.Helper()
	payload := []byte("payload bytes: the actual thing being protected")
	container, prov, err := Seal(payload, testID, "Demo payload", "eh-builder test", 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	return container, prov, payload
}

func TestSealOpenRoundTrip(t *testing.T) {
	container, prov, payload := sealTest(t)

	hdr, _, err := Inspect(container)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.ID != testID || hdr.Version != Version || hdr.Builder != "eh-builder test" ||
		hdr.CreatedAt != 1700000000 || !strings.HasPrefix(string(container), Magic) {
		t.Fatalf("header = %+v", hdr)
	}

	key, err := prov.KeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	got, gotHdr, err := Open(container, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) || gotHdr.SHA256 != hdr.SHA256 {
		t.Fatal("payload mismatch")
	}
}

func TestOpenRejections(t *testing.T) {
	container, prov, _ := sealTest(t)
	key, _ := prov.KeyBytes()

	t.Run("wrong key", func(t *testing.T) {
		if _, _, err := Open(container, bytes.Repeat([]byte{7}, KeyLen)); err == nil {
			t.Fatal("wrong key accepted")
		}
	})
	t.Run("short key", func(t *testing.T) {
		if _, _, err := Open(container, key[:16]); err == nil {
			t.Fatal("short key accepted")
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		bad := append([]byte(nil), container...)
		bad[len(bad)-1] ^= 0x01
		if _, _, err := Open(bad, key); err == nil {
			t.Fatal("tampered payload accepted")
		}
	})
	t.Run("tampered header", func(t *testing.T) {
		bad := bytes.Replace(container, []byte(testID), []byte("evil-payload"), 1)
		if _, _, err := Open(bad, key); err == nil {
			t.Fatal("relabelled container accepted")
		}
	})
	t.Run("bad magic", func(t *testing.T) {
		if _, _, err := Open([]byte("NOPE1\n{}"), key); err == nil {
			t.Fatal("bad magic accepted")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		if _, _, err := Open(container[:len(Magic)+2], key); err == nil {
			t.Fatal("truncated container accepted")
		}
	})
	t.Run("unknown header field", func(t *testing.T) {
		hdr := Header{Version: 1, ID: testID, Name: "x", SHA256: strings.Repeat("00", 32)}
		hj, _ := json.Marshal(hdr)
		hj = append(hj[:len(hj)-1], []byte(`,"extra":1}`)...)
		bad := append([]byte(Magic), hj...)
		bad = append(bad, '\n')
		if _, _, err := Inspect(bad); err == nil {
			t.Fatal("unknown header field accepted")
		}
	})
}

func TestSealValidation(t *testing.T) {
	if _, _, err := Seal([]byte("x"), "Bad ID", "n", "", 0); err == nil {
		t.Fatal("bad id accepted")
	}
	if _, _, err := Seal([]byte("x"), testID, "", "", 0); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, _, err := Seal([]byte("x"), testID, strings.Repeat("n", 129), "", 0); err == nil {
		t.Fatal("long name accepted")
	}
}

func TestParseProvision(t *testing.T) {
	_, prov, _ := sealTest(t)
	raw, err := json.Marshal(prov)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseProvision(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != prov.ID || got.SHA256 != prov.SHA256 {
		t.Fatalf("provision = %+v", got)
	}

	cases := map[string]string{
		"bad json":    `{"version":1,`,
		"version":     `{"version":2,"id":"a","name":"n","sha256":"` + strings.Repeat("00", 32) + `","key":"` + prov.Key + `"}`,
		"bad id":      `{"version":1,"id":"A","name":"n","sha256":"` + strings.Repeat("00", 32) + `","key":"` + prov.Key + `"}`,
		"bad sha":     `{"version":1,"id":"a","name":"n","sha256":"zz","key":"` + prov.Key + `"}`,
		"short key":   `{"version":1,"id":"a","name":"n","sha256":"` + strings.Repeat("00", 32) + `","key":"AAAA"}`,
		"unknown fld": `{"version":1,"id":"a","name":"n","sha256":"` + strings.Repeat("00", 32) + `","key":"` + prov.Key + `","extra":1}`,
	}
	for name, body := range cases {
		if _, err := ParseProvision([]byte(body)); err == nil {
			t.Fatalf("%s accepted", name)
		} else if !errors.Is(err, ErrFormat) {
			t.Fatalf("%s: error = %v, want ErrFormat", name, err)
		}
	}
}

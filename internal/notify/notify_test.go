package notify

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"eventhorizon/internal/cryptox"
)

func TestWebhookDeliveryAndSignature(t *testing.T) {
	secret := "hook-secret"
	var gotBody []byte
	var gotSig string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-EH-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := New(2*time.Second, secret)

	n.client = srv.Client()

	ev := Event{Event: "oob.issued", LicenseID: "lic1", Customer: "Acme", Code: "12345678", IssuedAt: 100, ExpiresAt: 200}
	if err := n.Send(context.Background(), "webhook:"+srv.URL, ev); err != nil {
		t.Fatal(err)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("bad body: %v", err)
	}
	if decoded["code"] != "12345678" || decoded["license_id"] != "lic1" {
		t.Fatalf("body mismatch: %v", decoded)
	}
	want := hex.EncodeToString(cryptox.HMAC([]byte(secret), gotBody))
	if gotSig != want {
		t.Fatalf("signature mismatch: %q vs %q", gotSig, want)
	}
}

func TestManualAndUnsupported(t *testing.T) {
	n := New(time.Second, "")
	for _, target := range []string{"", "manual"} {
		if err := n.Send(context.Background(), target, Event{}); err != ErrManual {
			t.Fatalf("target %q: want ErrManual, got %v", target, err)
		}
	}
	if err := n.Send(context.Background(), "sms:+123", Event{}); err == nil {
		t.Fatal("unsupported channel accepted")
	}
	if err := n.Send(context.Background(), "webhook:http://insecure.example", Event{}); err == nil {
		t.Fatal("plain http webhook accepted")
	}
}

func TestWebhookFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	n := New(time.Second, "")
	n.client = srv.Client()
	if err := n.Send(context.Background(), "webhook:"+srv.URL, Event{}); err == nil {
		t.Fatal("500 response treated as success")
	}
}

func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	n := New(time.Second, "")
	req, err := http.NewRequest(http.MethodPost, "https://example.com/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.client.CheckRedirect(req, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy = %v, want ErrUseLastResponse", err)
	}
}

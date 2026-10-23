package api

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"eventhorizon/internal/wire"
)

func TestRequestIDEchoAndErrorReference(t *testing.T) {
	e := testAPI(t)
	req, err := http.NewRequest(http.MethodGet, e.ts.URL+"/admin/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Request-ID", "client-request-42")
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Header.Get("X-Request-ID"); got != "client-request-42" {
		t.Fatalf("header id = %q", got)
	}
	var body wire.ErrorBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.RequestID != "client-request-42" {
		t.Fatalf("body request id = %q", body.Error.RequestID)
	}
}

func TestInvalidRequestIDIsReplaced(t *testing.T) {
	e := testAPI(t)
	req, err := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Request-ID", "bad id")
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got := resp.Header.Get("X-Request-ID")
	if got == "bad id" || len(got) < 8 {
		t.Fatalf("request id was not replaced: %q", got)
	}
}

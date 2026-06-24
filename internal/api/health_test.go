package api

import (
	"net/http"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	e := testAPI(t)

	resp, raw := e.do(t, http.MethodGet, "/api/v1/health", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %d %s", resp.StatusCode, raw)
	}
	var body map[string]any
	decodeInto(t, raw, &body)
	if body["ok"] != true || body["version"] == "" {
		t.Fatalf("health body = %s", raw)
	}
}

func TestReady(t *testing.T) {
	e := testAPI(t)
	resp, raw := e.do(t, http.MethodGet, "/api/v1/ready", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (body %s)", resp.StatusCode, raw)
	}
	var body map[string]any
	decodeInto(t, raw, &body)
	if body["ok"] != true || body["database"] != "ok" || body["attestation"] != "embedded" || body["attestation_mode"] != "auto" {
		t.Fatalf("ready body = %v", body)
	}
}

func TestReadyDatabaseUnavailable(t *testing.T) {
	e := testAPI(t)
	if err := e.srv.store.Close(); err != nil {
		t.Fatal(err)
	}
	resp, raw := e.do(t, http.MethodGet, "/api/v1/ready", "", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d (body %s)", resp.StatusCode, raw)
	}
	var body map[string]any
	decodeInto(t, raw, &body)
	if body["ok"] != false || body["database"] != "unavailable" || body["request_id"] == "" {
		t.Fatalf("ready body = %v", body)
	}
}

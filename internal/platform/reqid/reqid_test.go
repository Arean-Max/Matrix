package reqid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareKeepsValidID(t *testing.T) {
	var got string
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = From(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(Header, "client-request-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got != "client-request-123" {
		t.Fatalf("context id = %q", got)
	}
	if rec.Header().Get(Header) != got {
		t.Fatalf("response id = %q", rec.Header().Get(Header))
	}
}

func TestMiddlewareRejectsInvalidID(t *testing.T) {
	for _, raw := range []string{"short", "with space", "line\nbreak", ""} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(Header, raw)
		rec := httptest.NewRecorder()
		var got string
		Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = From(r.Context())
		})).ServeHTTP(rec, req)
		if got == raw || len(got) < 8 {
			t.Fatalf("id %q was not replaced: %q", raw, got)
		}
	}
}

func TestWithFromRoundTrip(t *testing.T) {
	ctx := With(context.Background(), "abc-12345")
	if From(ctx) != "abc-12345" {
		t.Fatal("context lost request id")
	}
	if From(context.Background()) != "" {
		t.Fatal("empty context returned an id")
	}
}

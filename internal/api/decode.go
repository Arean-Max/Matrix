package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"eventhorizon/internal/wire"
)

const maxBody = 1 << 20

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		return nil, &httpError{
			status:  http.StatusUnsupportedMediaType,
			code:    wire.CodeInvalidRequest,
			message: "Content-Type must be application/json",
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, &httpError{
				status:  http.StatusRequestEntityTooLarge,
				code:    wire.CodeInvalidRequest,
				message: "request body too large",
			}
		}
		return nil, &httpError{
			status:  http.StatusBadRequest,
			code:    wire.CodeInvalidRequest,
			message: "cannot read request body",
		}
	}
	return body, nil
}

func unmarshalStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &httpError{
			status:  http.StatusBadRequest,
			code:    wire.CodeInvalidRequest,
			message: "malformed JSON body",
		}
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return &httpError{
			status:  http.StatusBadRequest,
			code:    wire.CodeInvalidRequest,
			message: "trailing data after JSON body",
		}
	}
	return nil
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := readBody(w, r)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return &httpError{
			status:  http.StatusBadRequest,
			code:    wire.CodeInvalidRequest,
			message: "empty request body",
		}
	}
	return unmarshalStrict(body, v)
}

func decodeOptional(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := readBody(w, r)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return unmarshalStrict(body, v)
}

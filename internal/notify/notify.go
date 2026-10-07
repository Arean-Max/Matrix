package notify

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"eventhorizon/internal/cryptox"
)

var ErrManual = errors.New("manual retrieval")

type Event struct {
	Event     string `json:"event"`
	LicenseID string `json:"license_id"`
	Customer  string `json:"customer"`
	Code      string `json:"code"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

type Notifier struct {
	client *http.Client
	secret []byte
}

func New(timeout time.Duration, secret string) *Notifier {
	return &Notifier{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		secret: []byte(secret),
	}
}

func (n *Notifier) Send(ctx context.Context, target string, ev Event) error {
	switch {
	case target == "" || target == "manual":
		return ErrManual
	case strings.HasPrefix(target, "webhook:"):
		url := strings.TrimPrefix(target, "webhook:")
		if !strings.HasPrefix(url, "https://") {
			return fmt.Errorf("notify: webhook target must be https: %q", url)
		}
		return n.post(ctx, url, ev)
	default:
		return fmt.Errorf("notify: unsupported channel %q", target)
	}
}

func (n *Notifier) post(ctx context.Context, url string, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(n.secret) > 0 {
		req.Header.Set("X-EH-Signature", hex.EncodeToString(cryptox.HMAC(n.secret, body)))
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: webhook: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify: webhook returned %s", resp.Status)
	}
	return nil
}

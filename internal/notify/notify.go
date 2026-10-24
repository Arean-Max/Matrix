package notify

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	transport := &http.Transport{
		DialContext:           safeDialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	return &Notifier{
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		secret: []byte(secret),
	}
}

// safeDialContext refuses loopback, private, link-local, multicast and
// unspecified destinations. It dials the address that was checked, so a
// second DNS answer cannot redirect the request into an internal network.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("notify: %s has no addresses", host)
	}
	for _, ip := range ips {
		if !publicIP(ip.IP) {
			return nil, fmt.Errorf("notify: refusing non-public address %s", ip.IP)
		}
	}
	d := &net.Dialer{}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// 0.0.0.0/8 and 100.64.0.0/10 are not covered by net.IP.IsPrivate.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 {
			return false
		}
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
	}
	return true
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
		if len(n.secret) == 0 {
			return errors.New("notify: webhook_secret is required for webhook delivery")
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

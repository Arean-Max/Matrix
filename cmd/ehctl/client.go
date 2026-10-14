package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"eventhorizon/internal/wire"
)

type apiError struct {
	Status      int
	Code        string
	Message     string
	RetryAfterS int
}

func (e *apiError) Error() string {
	msg := fmt.Sprintf("%s (HTTP %d)", e.Code, e.Status)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.RetryAfterS > 0 {
		msg += fmt.Sprintf(" — retry in ~%ds", e.RetryAfterS)
	}
	return msg
}

type client struct {
	base  string
	token string
	hc    *http.Client

	hcLong *http.Client
}

func newClient(g *globals, needToken bool) (*client, error) {
	server := strings.TrimSpace(g.server)
	if server == "" {
		return nil, errors.New("--server is required (or set EHCTL_SERVER)")
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid --server %q", server)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("refusing plain HTTP to %q (use https or a loopback address)", u.Host)
		}
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if g.ca != "" {
		pem, err := os.ReadFile(g.ca)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}

	token := strings.TrimSpace(g.token)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("EHCTL_TOKEN"))
	}
	if token == "" && needToken {
		raw, err := readFileTrim(g.tokenFile)
		if err != nil {
			return nil, fmt.Errorf("no --token and cannot read token file %s: %w", g.tokenFile, err)
		}
		token = raw
	}
	if needToken && token == "" {
		return nil, errors.New("empty admin token")
	}

	transport := &http.Transport{TLSClientConfig: tlsCfg}
	return &client{
		base:  strings.TrimRight(server, "/"),
		token: token,
		hc: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		hcLong: &http.Client{
			Timeout:   10 * time.Minute,
			Transport: transport,
		},
	}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var eb wire.ErrorBody
		if json.Unmarshal(raw, &eb) == nil && eb.Error.Code != "" {
			return &apiError{
				Status: resp.StatusCode, Code: eb.Error.Code,
				Message: eb.Error.Message, RetryAfterS: eb.Error.RetryAfterS,
			}
		}
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (c *client) download(path string, w io.Writer) error {
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hcLong.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var eb wire.ErrorBody
		if json.Unmarshal(raw, &eb) == nil && eb.Error.Code != "" {
			return &apiError{
				Status: resp.StatusCode, Code: eb.Error.Code,
				Message: eb.Error.Message, RetryAfterS: eb.Error.RetryAfterS,
			}
		}
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return fmt.Errorf("download interrupted: %w", err)
	}
	if n == 0 {
		return errors.New("server returned an empty backup")
	}
	return nil
}

func printJSON(v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}

func printOrJSON(g *globals, v any, human func()) error {
	if g.asJSON {
		return printJSON(v)
	}
	human()
	return nil
}

func fetch(c *client, path string, out any) error {
	return c.do(http.MethodGet, path, nil, out)
}

func ts(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return time.Unix(unix, 0).Format("2006-01-02 15:04:05")
}

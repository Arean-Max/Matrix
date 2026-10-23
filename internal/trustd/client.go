package trustd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"

	"eventhorizon/internal/attestation"
)

const maxRequestBytes = 1 << 20
const maxResponseBytes = 64 << 10
const protocolVersion = 1

type Client struct {
	path    string
	timeout time.Duration
	log     *slog.Logger

	mu    sync.Mutex
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bufio.Reader
	wait  chan struct{}
}

type response struct {
	Protocol int            `json:"protocol"`
	OK       bool           `json:"ok"`
	AKName   string         `json:"ak_name"`
	Quote    *quoteResponse `json:"quote"`
	Error    string         `json:"error"`
}

type quoteResponse struct {
	PCRDigest       string `json:"pcr_digest"`
	PCRs            []int  `json:"pcrs"`
	ClockMS         uint64 `json:"clock_ms"`
	ResetCount      uint32 `json:"reset_count"`
	RestartCount    uint32 `json:"restart_count"`
	Safe            bool   `json:"safe"`
	FirmwareVersion uint64 `json:"firmware_version"`
}

func New(path string, timeout time.Duration, log *slog.Logger) (*Client, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("trustd: path is empty")
	}
	if timeout <= 0 {
		return nil, errors.New("trustd: timeout must be positive")
	}
	if log == nil {
		log = slog.Default()
	}
	c := &Client{path: path, timeout: timeout, log: log}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.startLocked(); err != nil {
		return nil, err
	}
	if _, err := c.callLocked(map[string]any{"op": "ping"}); err != nil {
		c.stopLocked()
		return nil, fmt.Errorf("trustd: handshake failed: %w", err)
	}
	return c, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

func (c *Client) CheckAK(akPub []byte) ([]byte, error) {
	resp, err := c.call(map[string]any{
		"op":     "check_ak",
		"ak_pub": base64.StdEncoding.EncodeToString(akPub),
	})
	if err != nil {
		return nil, err
	}
	name, err := hex.DecodeString(resp.AKName)
	if err != nil || len(name) != 34 || name[0] != 0 || name[1] != 0x0B {
		return nil, errors.New("trustd: malformed ak_name response")
	}
	return name, nil
}

func (c *Client) VerifyQuote(attest, signature, akPub []byte, akNameHex string, nonce []byte) (*attestation.Quote, error) {
	resp, err := c.call(map[string]any{
		"op":        "verify_quote",
		"ak_pub":    base64.StdEncoding.EncodeToString(akPub),
		"attest":    base64.StdEncoding.EncodeToString(attest),
		"signature": base64.StdEncoding.EncodeToString(signature),
		"ak_name":   akNameHex,
		"nonce":     hex.EncodeToString(nonce),
	})
	if err != nil {
		return nil, err
	}
	if resp.Quote == nil {
		return nil, errors.New("trustd: response has no quote")
	}
	if len(resp.Quote.PCRDigest) != 64 {
		return nil, errors.New("trustd: malformed pcr_digest")
	}
	if _, err := hex.DecodeString(resp.Quote.PCRDigest); err != nil {
		return nil, errors.New("trustd: malformed pcr_digest")
	}
	return &attestation.Quote{
		PCRDigestHex: resp.Quote.PCRDigest,
		PCRs:         resp.Quote.PCRs,
		ClockMs:      resp.Quote.ClockMS,
		ResetCount:   resp.Quote.ResetCount,
		RestartCount: resp.Quote.RestartCount,
		Safe:         resp.Quote.Safe,
		FirmwareVer:  resp.Quote.FirmwareVersion,
	}, nil
}

func (c *Client) call(request any) (*response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd == nil {
		if err := c.startLocked(); err != nil {
			return nil, err
		}
	}
	return c.callLocked(request)
}

func (c *Client) callLocked(request any) (*response, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("trustd: encode request: %w", err)
	}
	if len(payload) > maxRequestBytes {
		return nil, errors.New("trustd: request is too large")
	}
	payload = append(payload, '\n')

	deadline := time.NewTimer(c.timeout)
	defer deadline.Stop()

	writeErr := make(chan error, 1)
	go func() {
		_, err := c.stdin.Write(payload)
		writeErr <- err
	}()
	select {
	case err := <-writeErr:
		if err != nil {
			c.stopLocked()
			return nil, fmt.Errorf("trustd: write: %w", err)
		}
	case <-deadline.C:
		c.stopLocked()
		return nil, errors.New("trustd: write timeout")
	}

	type readResult struct {
		line []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	reader := c.out
	go func() {
		line, err := readLineLimited(reader, maxResponseBytes)
		readDone <- readResult{line: line, err: err}
	}()
	select {
	case result := <-readDone:
		if result.err != nil {
			c.stopLocked()
			return nil, fmt.Errorf("trustd: read: %w", result.err)
		}
		var resp response
		if err := json.Unmarshal(result.line, &resp); err != nil {
			c.stopLocked()
			return nil, fmt.Errorf("trustd: decode response: %w", err)
		}
		if resp.Protocol != protocolVersion {
			c.stopLocked()
			return nil, fmt.Errorf("trustd: protocol %d, want %d", resp.Protocol, protocolVersion)
		}
		if !resp.OK {
			if resp.Error == "" {
				resp.Error = "request rejected"
			}
			return nil, fmt.Errorf("trustd: %s", resp.Error)
		}
		return &resp, nil
	case <-deadline.C:
		c.stopLocked()
		return nil, errors.New("trustd: read timeout")
	}
}

func (c *Client) startLocked() error {
	cmd := exec.Command(c.path)
	cmd.Env = []string{}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("trustd: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("trustd: stdout pipe: %w", err)
	}
	cmd.Stderr = newLogWriter(c.log)
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return fmt.Errorf("trustd: start %s: %w", c.path, err)
	}
	wait := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(wait)
	}()
	c.cmd = cmd
	c.stdin = stdin
	c.out = bufio.NewReaderSize(stdout, 64<<10)
	c.wait = wait
	return nil
}

func (c *Client) stopLocked() {
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	if c.wait != nil {
		select {
		case <-c.wait:
		case <-time.After(time.Second):
		}
	}
	c.cmd = nil
	c.stdin = nil
	c.out = nil
	c.wait = nil
}

type logWriter struct {
	log *slog.Logger
	mu  sync.Mutex
	buf []byte
}

func readLineLimited(r *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		fragment, err := r.ReadSlice('\n')
		out = append(out, fragment...)
		if len(out) > max {
			return nil, errors.New("response is too large")
		}
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

func newLogWriter(log *slog.Logger) *logWriter {
	return &logWriter{log: log}
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
		if line != "" {
			w.log.Warn("trustd stderr", "line", line)
		}
	}
	if len(w.buf) > 64<<10 {
		w.buf = nil
	}
	return len(p), nil
}

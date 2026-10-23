package trustd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
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

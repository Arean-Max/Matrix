package trustd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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

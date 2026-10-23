package trustd

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
)

type logWriter struct {
	log *slog.Logger
	mu  sync.Mutex
	buf []byte
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

package ratelimit

import (
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*entry
	now     func() time.Time
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

func New() *Limiter {
	return &Limiter{buckets: make(map[string]*entry), now: time.Now}
}

func (l *Limiter) Allow(key string, perMinute float64, burst int) bool {
	l.mu.Lock()
	e, ok := l.buckets[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(rate.Limit(perMinute/60.0), burst)}
		l.buckets[key] = e
	}
	e.seen = l.now()
	lim := e.lim
	l.mu.Unlock()
	return lim.Allow()
}

func (l *Limiter) AllowRetry(key string, perMinute float64, burst int) (bool, int) {
	if l.Allow(key, perMinute, burst) {
		return true, 0
	}
	secs := int(math.Ceil(60.0 / perMinute))
	if secs < 1 {
		secs = 1
	}
	return false, secs
}

func (l *Limiter) GC(maxIdle time.Duration) int {
	cutoff := l.now().Add(-maxIdle)
	l.mu.Lock()
	defer l.mu.Unlock()
	removed := 0
	for k, e := range l.buckets {
		if e.seen.Before(cutoff) {
			delete(l.buckets, k)
			removed++
		}
	}
	return removed
}

func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func (l *Limiter) StartGC(every, maxIdle time.Duration) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				l.GC(maxIdle)
			case <-done:
				return
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

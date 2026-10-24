package ratelimit

import (
	"math"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const defaultMaxBuckets = 20000

type Limiter struct {
	mu         sync.Mutex
	buckets    map[string]*entry
	maxBuckets int
	now        func() time.Time
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

func New() *Limiter {
	return &Limiter{
		buckets:    make(map[string]*entry),
		maxBuckets: defaultMaxBuckets,
		now:        time.Now,
	}
}

func (l *Limiter) SetMaxBuckets(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > 0 {
		l.maxBuckets = n
	}
}

func (l *Limiter) Allow(key string, perMinute float64, burst int) bool {
	l.mu.Lock()
	e, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxBuckets {
			l.evictOldestLocked(l.maxBuckets / 10)
		}
		e = &entry{lim: rate.NewLimiter(rate.Limit(perMinute/60.0), burst)}
		l.buckets[key] = e
	}
	e.seen = l.now()
	lim := e.lim
	l.mu.Unlock()
	return lim.Allow()
}

func (l *Limiter) evictOldestLocked(count int) {
	if count <= 0 || len(l.buckets) == 0 {
		count = 1
	}
	type pair struct {
		key  string
		seen time.Time
	}
	sampleSize := count * 3
	if sampleSize < 10 {
		sampleSize = 10
	}
	var sample []pair
	for k, e := range l.buckets {
		sample = append(sample, pair{key: k, seen: e.seen})
		if len(sample) >= sampleSize {
			break
		}
	}
	sort.Slice(sample, func(i, j int) bool {
		return sample[i].seen.Before(sample[j].seen)
	})
	n := count
	if len(sample) < n {
		n = len(sample)
	}
	for i := 0; i < n; i++ {
		delete(l.buckets, sample[i].key)
	}
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
	t := time.NewTicker(every)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		for {
			select {
			case <-t.C:
				l.GC(maxIdle)
			case <-done:
				t.Stop()
				return
			}
		}
	}()
	return func() {
		once.Do(func() { close(done) })
	}
}

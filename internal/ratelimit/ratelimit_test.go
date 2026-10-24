package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenDeny(t *testing.T) {
	l := New()
	for i := 0; i < 3; i++ {
		if !l.Allow("ip:1.2.3.4", 60, 3) {
			t.Fatalf("burst %d denied", i)
		}
	}
	if l.Allow("ip:1.2.3.4", 60, 3) {
		t.Fatal("over-burst request allowed")
	}
	if !l.Allow("ip:5.6.7.8", 60, 3) {
		t.Fatal("independent key denied")
	}
}

func TestGC(t *testing.T) {
	l := New()
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }

	l.Allow("k1", 60, 1)
	now = now.Add(10 * time.Minute)
	l.Allow("k2", 60, 1)
	if n := l.Len(); n != 2 {
		t.Fatalf("Len = %d", n)
	}
	if removed := l.GC(5 * time.Minute); removed != 1 {
		t.Fatalf("GC removed %d, want 1", removed)
	}
	if l.Len() != 1 {
		t.Fatalf("after GC Len = %d", l.Len())
	}
}

func TestStartGCStops(t *testing.T) {
	l := New()
	stop := l.StartGC(time.Millisecond, time.Millisecond)
	l.Allow("k", 60, 1)
	time.Sleep(20 * time.Millisecond)
	stop()
	stop()
	if l.Len() != 0 {
		t.Fatalf("GC did not evict idle bucket: %d", l.Len())
	}
}

func TestBoundedCapacity(t *testing.T) {
	l := New()
	l.SetMaxBuckets(50)
	for i := 0; i < 200; i++ {
		l.Allow(time.Duration(i).String(), 60, 1)
	}
	if l.Len() > 50 {
		t.Fatalf("bucket count %d exceeded max limit 50", l.Len())
	}
}


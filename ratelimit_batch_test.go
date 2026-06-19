package jwt

import (
	"fmt"
	"testing"
	"time"
)

// TestRateLimiterBatchEvictionAtCapacity verifies that when the bucket map is at
// capacity, a batch of the oldest entries is evicted in a single pass (not one
// at a time), keeping the map bounded and letting new distinct keys proceed.
// This is the regression guard for the O(n)->amortized-O(log n) eviction fix.
func TestRateLimiterBatchEvictionAtCapacity(t *testing.T) {
	rl := NewRateLimiter(1000, time.Minute)
	rl.maxBuckets = 100
	// Monotonic, distinct clock so lastRefill values are strictly increasing:
	// the oldest buckets are unambiguously the earliest inserted.
	var tick int64
	rl.nowFunc = func() time.Time {
		tick++
		return time.Unix(0, tick).UTC()
	}
	defer rl.Close()

	for i := range rl.maxBuckets {
		if !rl.Allow(fmt.Sprintf("u%d", i)) {
			t.Fatalf("Allow(u%d) failed during fill", i)
		}
	}
	if got := len(rl.buckets); got != rl.maxBuckets {
		t.Fatalf("after fill: got %d buckets, want %d", got, rl.maxBuckets)
	}

	// One more distinct key triggers eviction. maxBuckets/10 == 10, so the 10
	// oldest buckets go in a single pass, then the new one is inserted: 100-10+1.
	if !rl.Allow("overflow") {
		t.Fatal("Allow(overflow) should succeed after batch eviction")
	}
	if got, want := len(rl.buckets), rl.maxBuckets-10+1; got != want {
		t.Errorf("after overflow: got %d buckets, want %d (batch should evict 10)", got, want)
	}

	// Sustained over-capacity traffic must keep the map bounded at maxBuckets.
	for i := range 5000 {
		if !rl.Allow(fmt.Sprintf("v%d", i)) {
			t.Fatalf("Allow(v%d) failed under sustained load", i)
		}
		if got := len(rl.buckets); got > rl.maxBuckets {
			t.Fatalf("map exceeded maxBuckets: got %d > %d", got, rl.maxBuckets)
		}
	}
}

// BenchmarkRateLimiterAtCapacity measures Allow() cost for distinct keys while
// the bucket map is at capacity — the eviction hot path. Before the batch fix
// this was O(n) per insert (full-map scan each time); it is now amortized
// O(log n) (one scan per ~maxBuckets/10 inserts). Allocs/op is the deterministic
// signal; ns/op varies with thermal throttling (see benchmark-thermal-variance).
func BenchmarkRateLimiterAtCapacity(b *testing.B) {
	rl := NewRateLimiter(1000, time.Minute)
	rl.maxBuckets = 10000
	defer rl.Close()
	for i := range rl.maxBuckets {
		rl.Allow(fmt.Sprintf("seed-%d", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(fmt.Sprintf("k-%d", i))
	}
}

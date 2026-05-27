package api

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestGate_AcquireRelease(t *testing.T) {
	g := newIngestGate(IngestPolicy{MaxConcurrentAppends: 2})
	if !g.acquire() {
		t.Fatal("first acquire failed")
	}
	if !g.acquire() {
		t.Fatal("second acquire failed")
	}
	if g.acquire() {
		t.Fatal("third acquire should have been refused")
	}
	g.release()
	if !g.acquire() {
		t.Fatal("acquire after release failed")
	}
}

func TestGate_DisabledConcurrency(t *testing.T) {
	g := newIngestGate(IngestPolicy{}) // both fields zero → disabled
	for i := 0; i < 100; i++ {
		if !g.acquire() {
			t.Fatalf("acquire #%d refused on disabled limiter", i)
		}
	}
}

func TestGate_AllowProducerEnforcesBurst(t *testing.T) {
	g := newIngestGate(IngestPolicy{PerProducerRPS: 5, PerProducerBurst: 3})
	// First 3 must succeed (burst). 4th typically fails because we
	// haven't waited for the bucket to refill.
	for i := 0; i < 3; i++ {
		if !g.allowProducer("alice") {
			t.Fatalf("burst slot %d unexpectedly refused", i)
		}
	}
	if g.allowProducer("alice") {
		t.Fatal("4th immediate call within burst should have been refused")
	}
	// A different producer has its own bucket.
	if !g.allowProducer("bob") {
		t.Fatal("bob's first call should be allowed (independent bucket)")
	}
}

func TestGate_AllowProducerNoLimit(t *testing.T) {
	g := newIngestGate(IngestPolicy{PerProducerRPS: 0})
	for i := 0; i < 1000; i++ {
		if !g.allowProducer("any") {
			t.Fatalf("call %d refused with rate=0", i)
		}
	}
}

func TestGate_ConcurrencyParallel(t *testing.T) {
	g := newIngestGate(IngestPolicy{MaxConcurrentAppends: 5})
	var wg sync.WaitGroup
	var ok, denied int
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.acquire() {
				time.Sleep(20 * time.Millisecond)
				g.release()
				mu.Lock()
				ok++
				mu.Unlock()
			} else {
				mu.Lock()
				denied++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok < 5 {
		t.Fatalf("expected at least 5 acquires, got %d", ok)
	}
	if denied == 0 {
		t.Fatalf("expected some acquires to be denied, got 0")
	}
}

func TestGate_EvictIdle(t *testing.T) {
	g := newIngestGate(IngestPolicy{PerProducerRPS: 1, PerProducerBurst: 1})
	g.allowProducer("alice")
	g.allowProducer("bob")
	if got := len(g.producerLimits); got != 2 {
		t.Fatalf("expected 2 producer limiters, got %d", got)
	}
	// Force lastUsed into the past for one limiter.
	g.mu.Lock()
	g.producerLimits["alice"].lastUsed = time.Now().Add(-1 * time.Hour)
	g.mu.Unlock()
	n := g.evictIdle(10 * time.Minute)
	if n != 1 {
		t.Fatalf("expected to evict 1, got %d", n)
	}
	if _, ok := g.producerLimits["bob"]; !ok {
		t.Fatal("bob should still be present (recent)")
	}
}

func TestGate_RetryAfterFloor(t *testing.T) {
	g := newIngestGate(IngestPolicy{RetryAfter: 0})
	if got := g.retryAfterSeconds(); got != 1 {
		t.Fatalf("RetryAfter floor should be 1, got %d", got)
	}
}

func TestWriteRetryAfterSetsHeader(t *testing.T) {
	rec := &headerRecorder{header: http.Header{}}
	writeRetryAfter(rec, http.StatusTooManyRequests, 5, "test")
	if got := rec.header.Get("Retry-After"); got != "5" {
		t.Fatalf("Retry-After = %q, want %q", got, "5")
	}
}

type headerRecorder struct {
	header http.Header
	status int
	body   []byte
}

func (h *headerRecorder) Header() http.Header        { return h.header }
func (h *headerRecorder) Write(b []byte) (int, error) { h.body = append(h.body, b...); return len(b), nil }
func (h *headerRecorder) WriteHeader(s int)           { h.status = s }

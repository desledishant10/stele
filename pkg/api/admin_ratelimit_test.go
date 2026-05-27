package api

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// callerIdentityOrIP tests: covers the precedence chain (mTLS CN >
// X-Stele-Admin header > source IP).

func TestCallerIdentity_mTLS_CN_Wins(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/rotate", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Stele-Admin", "from-header")
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "alice"}}},
	}
	if got := callerIdentityOrIP(r); got != "alice" {
		t.Fatalf("mTLS CN should win: got %q, want %q", got, "alice")
	}
}

func TestCallerIdentity_HeaderFallback(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/rotate", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Stele-Admin", "bob")
	if got := callerIdentityOrIP(r); got != "bob" {
		t.Fatalf("header fallback failed: got %q, want %q", got, "bob")
	}
}

func TestCallerIdentity_IPLastResort(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/rotate", nil)
	r.RemoteAddr = "192.168.10.5:54321"
	if got := callerIdentityOrIP(r); got != "192.168.10.5" {
		t.Fatalf("IP fallback failed: got %q, want %q", got, "192.168.10.5")
	}
}

func TestCallerIdentity_IPv6_RemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/rotate", nil)
	// IPv6 RemoteAddr looks like "[::1]:1234"; LastIndex on ':' lands
	// after the brackets — we lose the port but keep the address.
	r.RemoteAddr = "[::1]:1234"
	got := callerIdentityOrIP(r)
	if got == "" || got == r.RemoteAddr {
		t.Fatalf("IPv6 fallback should strip port; got %q", got)
	}
}

// gate.allowAdmin: independent from allowProducer (separate buckets).

func TestGate_AllowAdmin_SeparateFromProducers(t *testing.T) {
	g := newIngestGate(IngestPolicy{
		PerProducerRPS:   1,
		PerProducerBurst: 1,
		PerAdminRPS:      1,
		PerAdminBurst:    1,
	})
	// Consume the only producer slot for "alice".
	if !g.allowProducer("alice") {
		t.Fatal("first producer call should succeed")
	}
	if g.allowProducer("alice") {
		t.Fatal("second producer call should be refused (burst=1)")
	}
	// Admin bucket for the SAME name "alice" must be independent.
	if !g.allowAdmin("alice") {
		t.Fatal("admin call should be independent from producer bucket")
	}
}

func TestGate_AllowAdmin_PerActorIsolation(t *testing.T) {
	g := newIngestGate(IngestPolicy{PerAdminRPS: 1, PerAdminBurst: 1})
	if !g.allowAdmin("alice") {
		t.Fatal("alice first call should succeed")
	}
	if g.allowAdmin("alice") {
		t.Fatal("alice second call should be refused")
	}
	// bob has his own bucket.
	if !g.allowAdmin("bob") {
		t.Fatal("bob first call should succeed")
	}
}

func TestGate_AllowAdmin_DisabledAlwaysAllows(t *testing.T) {
	g := newIngestGate(IngestPolicy{PerAdminRPS: 0})
	for i := 0; i < 100; i++ {
		if !g.allowAdmin("anyone") {
			t.Fatalf("call %d refused with rate=0", i)
		}
	}
}

// rateLimitAdmin middleware end-to-end behaviour.

func TestRateLimitAdmin_AllowsGETs(t *testing.T) {
	s := &Server{}
	s.gate = newIngestGate(IngestPolicy{PerAdminRPS: 1, PerAdminBurst: 1})
	calls := 0
	handler := s.rateLimitAdmin("test", func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})

	// Fire 5 GETs in a row — none should be rate-limited.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "1.2.3.4:1"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %d returned %d, want 200", i, w.Code)
		}
	}
	if calls != 5 {
		t.Fatalf("expected 5 underlying calls, got %d", calls)
	}
}

func TestRateLimitAdmin_RejectsExcessPOSTs(t *testing.T) {
	s := &Server{}
	s.gate = newIngestGate(IngestPolicy{PerAdminRPS: 1, PerAdminBurst: 2, RetryAfter: 3})
	handler := s.rateLimitAdmin("test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	codes := []int{}
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.RemoteAddr = "1.2.3.4:1"
		w := httptest.NewRecorder()
		handler(w, req)
		codes = append(codes, w.Code)
	}
	// First 2 (burst) succeed, the rest 429.
	want := []int{200, 200, 429, 429, 429}
	for i, c := range codes {
		if c != want[i] {
			t.Fatalf("call %d: got %d, want %d", i, c, want[i])
		}
	}

	// Last 429 must include Retry-After header.
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.RemoteAddr = "1.2.3.4:1"
	w := httptest.NewRecorder()
	handler(w, req)
	if got := w.Header().Get("Retry-After"); got != "3" {
		t.Fatalf("Retry-After = %q, want %q", got, "3")
	}
}

func TestRateLimitAdmin_PerActorBuckets(t *testing.T) {
	s := &Server{}
	s.gate = newIngestGate(IngestPolicy{PerAdminRPS: 1, PerAdminBurst: 1})
	handler := s.rateLimitAdmin("test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// alice exhausts her bucket.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set("X-Stele-Admin", "alice")
		w := httptest.NewRecorder()
		handler(w, req)
		if i == 1 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("alice's 2nd call should be 429, got %d", w.Code)
		}
	}
	// bob has his own bucket and is unaffected.
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("X-Stele-Admin", "bob")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		body, _ := readAllString(w.Body)
		t.Fatalf("bob's 1st call should be 200, got %d body=%s", w.Code, body)
	}
}

func TestRateLimitAdmin_DisabledPassesEverything(t *testing.T) {
	s := &Server{}
	s.gate = newIngestGate(IngestPolicy{PerAdminRPS: 0})
	handler := s.rateLimitAdmin("test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.RemoteAddr = "10.0.0.1:1"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("call %d: rate=0 should never reject, got %d", i, w.Code)
		}
	}
}

func readAllString(r interface{ String() string }) (string, error) {
	return r.String(), nil
}

// silence unused-import warning for strings used only in callerIdentity tests.
var _ = strings.TrimSpace
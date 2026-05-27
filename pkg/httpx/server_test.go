package httpx

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewServerAppliesDefaults(t *testing.T) {
	s := NewServer(":0", http.NotFoundHandler(), Timeouts{})
	if s.ReadHeaderTimeout != DefaultTimeouts.ReadHeader {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", s.ReadHeaderTimeout, DefaultTimeouts.ReadHeader)
	}
	if s.ReadTimeout != DefaultTimeouts.Read {
		t.Fatalf("ReadTimeout = %v", s.ReadTimeout)
	}
	if s.WriteTimeout != DefaultTimeouts.Write {
		t.Fatalf("WriteTimeout = %v", s.WriteTimeout)
	}
	if s.IdleTimeout != DefaultTimeouts.Idle {
		t.Fatalf("IdleTimeout = %v", s.IdleTimeout)
	}
}

func TestNewServerHonoursOverrides(t *testing.T) {
	s := NewServer(":0", http.NotFoundHandler(), Timeouts{Read: 7 * time.Second})
	if s.ReadTimeout != 7*time.Second {
		t.Fatalf("ReadTimeout override not applied: %v", s.ReadTimeout)
	}
	if s.WriteTimeout != DefaultTimeouts.Write {
		t.Fatalf("Other timeouts should still use default")
	}
}

func TestMaxBodyBytesRejectsOversize(t *testing.T) {
	const limit = 32
	var captured error
	h := MaxBodyBytes(limit, func(w http.ResponseWriter, r *http.Request) {
		_, captured = io.ReadAll(r.Body)
	})

	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/octet-stream",
		bytes.NewReader(make([]byte, limit+1)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if captured == nil {
		t.Fatal("handler did not observe a body-read error")
	}
	if !IsMaxBytesError(captured) {
		t.Fatalf("expected MaxBytesError, got %T: %v", captured, captured)
	}
}

func TestMaxBodyBytesAcceptsUnderLimit(t *testing.T) {
	const limit = 32
	h := MaxBodyBytes(limit, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL, "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Fatalf("echo = %q, want %q", body, "hello")
	}
}

func TestIsMaxBytesErrorRejectsUnrelated(t *testing.T) {
	if IsMaxBytesError(errors.New("not a max bytes error")) {
		t.Fatal("IsMaxBytesError mis-identified a plain error")
	}
}

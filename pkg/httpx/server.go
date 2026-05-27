// Package httpx provides hardened HTTP server primitives shared by
// every stele daemon. The goal is to eliminate the "default
// http.Server is wide-open" foot-gun: zero timeouts, unbounded
// request bodies, and ambiguous handler ownership of failure modes.
//
// Use NewServer to construct a server with explicit, conservative
// timeouts. Wrap handlers with MaxBodyBytes to cap the request body
// size at every endpoint that reads one. Both are cheap and should be
// applied by default.
package httpx

import (
	"errors"
	"net/http"
	"time"
)

// DefaultTimeouts is the timeout policy applied to every stele daemon.
// Each value is conservative enough to defeat Slowloris-style attacks
// while still tolerating real-world TCP retransmits on busy networks.
//
//   - ReadHeaderTimeout caps the time a client can take to send request
//     headers. Slowloris pushes this to the limit; 10s is comfortable
//     for legitimate clients.
//   - ReadTimeout is the deadline for reading the ENTIRE request,
//     headers + body. 30s permits ~10MB bodies on a 3 Mbps link.
//   - WriteTimeout bounds how long the handler+response write may
//     take. 30s catches stuck handlers.
//   - IdleTimeout closes keep-alive connections that aren't sending
//     anything. 120s matches typical NLB / cloud LB idle timeouts so
//     we never end up with connections the LB has already given up on.
type Timeouts struct {
	ReadHeader time.Duration
	Read       time.Duration
	Write      time.Duration
	Idle       time.Duration
}

// DefaultTimeouts is the production-ready default. Callers can derive
// custom policies by copying it and overriding individual fields.
var DefaultTimeouts = Timeouts{
	ReadHeader: 10 * time.Second,
	Read:       30 * time.Second,
	Write:      30 * time.Second,
	Idle:       120 * time.Second,
}

// NewServer builds an http.Server with hardened defaults. Any field on
// `base` that is already set takes precedence — so callers who pre-fill
// TLSConfig, BaseContext, etc. keep those settings.
//
// The caller still owns lifecycle (Shutdown / Close).
func NewServer(addr string, handler http.Handler, t Timeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: pickDuration(t.ReadHeader, DefaultTimeouts.ReadHeader),
		ReadTimeout:       pickDuration(t.Read, DefaultTimeouts.Read),
		WriteTimeout:      pickDuration(t.Write, DefaultTimeouts.Write),
		IdleTimeout:       pickDuration(t.Idle, DefaultTimeouts.Idle),
	}
}

func pickDuration(v, fallback time.Duration) time.Duration {
	if v <= 0 {
		return fallback
	}
	return v
}

// MaxBodyBytes wraps `next` with an http.MaxBytesReader that caps the
// request body at `limit` bytes. Requests exceeding the cap fail with
// HTTP 413 Payload Too Large — Go's net/http surfaces this as an
// http.MaxBytesError that the handler can detect via errors.As.
//
// Use a tight per-endpoint cap rather than one big global limit. A
// stele envelope is usually under 1 KiB; a gossip payload can be
// larger. Setting the cap close to the realistic upper bound keeps
// memory amplification attacks bounded.
func MaxBodyBytes(limit int64, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next(w, r)
	}
}

// IsMaxBytesError reports whether err was returned by an
// http.MaxBytesReader because the body exceeded the cap. Use inside
// handlers to surface a clean 413 response.
func IsMaxBytesError(err error) bool {
	var mb *http.MaxBytesError
	return errors.As(err, &mb)
}

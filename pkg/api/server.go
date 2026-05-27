package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/desledishant10/stele/pkg/adminlog"
	"github.com/desledishant10/stele/pkg/core"
	"github.com/desledishant10/stele/pkg/honeylog"
	"github.com/desledishant10/stele/pkg/httpx"
	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/readlog"
	"github.com/desledishant10/stele/pkg/storage"
)

// Limits configures per-endpoint request-body size caps. Sensible
// defaults are in DefaultLimits; override on Server.Limits before
// NewMux.
type Limits struct {
	// AppendBodyBytes caps the /append request body. Envelopes are
	// usually under 1 KiB; 64 KiB tolerates an unusually large payload
	// without leaving room for memory-amplification attacks.
	AppendBodyBytes int64

	// AdminBodyBytes caps every admin endpoint body
	// (/producers, /witnesses, /threshold-group, /rotate). Threshold
	// groups can be the largest of these — N member entries with
	// 1952-byte Dilithium pubkeys add up.
	AdminBodyBytes int64
}

// DefaultLimits is the production-ready default. Each cap is set close
// to the realistic upper bound of legitimate payload size.
var DefaultLimits = Limits{
	AppendBodyBytes: 64 * 1024,
	AdminBodyBytes:  256 * 1024,
}

// withSizeCap returns `next` wrapped so the request body cannot exceed
// `limit` bytes. The handler still sees a normal io.Reader; the cap
// surfaces as a decoder error which writeBodyErr translates into a
// clean 413 plus a metric.
func withSizeCap(limit int64, next http.HandlerFunc) http.HandlerFunc {
	return httpx.MaxBodyBytes(limit, next)
}

// writeBodyErr translates a request-body read/decode error into the
// right HTTP response. MaxBytesError → 413, otherwise → 400. Records
// the rejection against IngestRejectsTotal so operators can alert on
// spikes per endpoint.
func writeBodyErr(w http.ResponseWriter, endpoint string, err error) {
	if httpx.IsMaxBytesError(err) {
		obs.IngestRejectsTotal.WithLabelValues(endpoint, "body_too_large").Inc()
		writeErr(w, http.StatusRequestEntityTooLarge,
			fmt.Errorf("request body exceeds size limit"))
		return
	}
	writeErr(w, http.StatusBadRequest, err)
}

// Server is the HTTP handler set. Mount with NewMux().
type Server struct {
	Log       *core.Log
	HoneySink honeylog.Sink // nil disables alerting

	// AppendObserver, if set, is called once per successful Append.
	// The watchdog uses this to update the append-rate baseline.
	AppendObserver func()

	// RequireClientCertCN, when true, demands that the TLS client
	// certificate's Common Name equals envelope.ProducerID on every
	// /append request. Set to true when mTLS is configured.
	RequireClientCertCN bool

	// ReadLog, if set, captures every read operation served by this
	// API into an append-only signed journal. Reads of read-log
	// entries themselves do NOT recursively log.
	ReadLog *readlog.Journal

	// AdminLog, if set, captures every admin-level mutation (rotate,
	// producer/witness add+remove, threshold-group swap) into an
	// append-only signed journal. Persisted independently of the main
	// log so a compromise of the entry DB does not also erase the
	// audit trail of administrative actions.
	AdminLog *adminlog.Journal

	// Limits caps request body sizes per endpoint. Zero fields use
	// DefaultLimits.
	Limits Limits

	// IngestPolicy configures bounded concurrency + per-producer rate
	// limiting on the /append path. Zero fields use
	// DefaultIngestPolicy.
	IngestPolicy IngestPolicy

	// gate is constructed lazily on first NewMux call.
	gate *ingestGate
}

// recordRead appends a tamper-evident event to the read log (if
// configured). Failures are logged but do not interrupt the response —
// failing closed on a read-log issue would let any read failure bring
// down the read API. A monitoring system should alert on
// s.ReadLog.Size() not advancing despite served reads.
func (s *Server) recordRead(r *http.Request, entryIdx uint64, leafHash []byte, op string) {
	if s.ReadLog == nil {
		return
	}
	_, _ = s.ReadLog.Append(entryIdx, leafHash, op, r.RemoteAddr, r.UserAgent())
}

// recordAdmin appends one entry to the admin audit log AND increments
// the obs metric. Outcome is "ok" if `err == nil`, else "error" with
// err.Error() captured.
//
// Failures of the admin journal itself are logged but do NOT abort
// the operation — the operation already mutated state, and the goal
// here is auditability, not consistency. Operators should alert on
// `stele_admin_actions_total{outcome="error"}` to detect a stuck
// journal.
func (s *Server) recordAdmin(r *http.Request, action, subject string, details any, err error) {
	outcome := "ok"
	errMsg := ""
	if err != nil {
		outcome = "error"
		errMsg = err.Error()
	}
	obs.AdminActionsTotal.WithLabelValues(action, outcome).Inc()
	if s.AdminLog == nil {
		return
	}
	actor := callerIdentity(r)
	if _, jerr := s.AdminLog.Action(action, subject, outcome, errMsg, details, actor, r.RemoteAddr, r.UserAgent()); jerr != nil {
		obs.Error("adminlog append failed",
			"action", action, "subject", subject, "err", jerr)
	}
}

// callerIdentity prefers the TLS client cert CN (strongest signal),
// then falls back to the X-Stele-Admin header (when configured behind
// a trusted reverse proxy). Empty when neither is available — the
// admin journal still records the IP and UA.
func callerIdentity(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cn := strings.TrimSpace(r.TLS.PeerCertificates[0].Subject.CommonName)
		if cn != "" {
			return cn
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Stele-Admin"))
}

// callerIdentityOrIP is callerIdentity with a final fallback to the
// source IP, used as the rate-limiter key so unauthenticated callers
// still get a stable bucket. RemoteAddr is the actual TCP peer —
// harder to spoof than X-Forwarded-For but still affected by NAT, so
// behind a shared NAT multiple distinct admins share a bucket. That's
// an acceptable trade-off for v1 (admin actions are rare anyway);
// production setups should ensure mTLS is on so the CN path wins.
func callerIdentityOrIP(r *http.Request) string {
	if id := callerIdentity(r); id != "" {
		return id
	}
	// RemoteAddr is "ip:port"; we want just the IP.
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// rateLimitAdmin wraps `next` so mutating requests (POST/PUT/DELETE)
// run through the admin token bucket keyed by callerIdentityOrIP.
// Non-mutation methods pass through. On rejection: HTTP 429 +
// Retry-After + ingest_rejects metric incremented under
// {endpoint, reason="rate_limit"}.
func (s *Server) rateLimitAdmin(endpoint string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			// rate-limited; fall through
		default:
			next(w, r)
			return
		}
		actor := callerIdentityOrIP(r)
		if !s.gate.allowAdmin(actor) {
			obs.IngestRejectsTotal.WithLabelValues(endpoint, "rate_limit").Inc()
			writeRetryAfter(w, http.StatusTooManyRequests, s.gate.retryAfterSeconds(),
				fmt.Sprintf("admin actor %q rate-limited on %s", actor, endpoint))
			return
		}
		next(w, r)
	}
}

// fireHoney is a helper called from every read path that exposes an
// individual entry. If the entry is flagged as honeypot, an alert is
// produced and sent to s.HoneySink asynchronously so the response time
// to the attacker is unchanged.
func (s *Server) fireHoney(r *http.Request, idx uint64, leafHash []byte, note string) {
	if s.HoneySink == nil {
		return
	}
	a := &honeylog.Alert{
		Origin:    s.Log.Origin(),
		EntryIdx:  idx,
		LeafHash:  leafHash,
		CallerIP:  r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Path:      r.URL.Path,
		Time:      time.Now().UnixNano(),
		Note:      note,
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.HoneySink.Fire(ctx, a)
	}()
}

// NewMux builds an http.ServeMux with every API route registered. Each
// POST endpoint that reads a body is wrapped with a per-endpoint size
// cap (s.Limits, with DefaultLimits used when zero). GET endpoints do
// not read bodies so they get the cap anyway as a defence in depth.
func NewMux(s *Server) *http.ServeMux {
	lim := s.Limits
	if lim.AppendBodyBytes == 0 {
		lim.AppendBodyBytes = DefaultLimits.AppendBodyBytes
	}
	if lim.AdminBodyBytes == 0 {
		lim.AdminBodyBytes = DefaultLimits.AdminBodyBytes
	}

	// Ingest gate (concurrency + per-producer rate limit) is shared
	// across all Append calls served by this Server.
	pol := s.IngestPolicy
	if pol == (IngestPolicy{}) {
		pol = DefaultIngestPolicy
	}
	s.gate = newIngestGate(pol)

	mux := http.NewServeMux()
	// Hot path: producer ingest. Tightest cap; per-producer + global
	// concurrency limits applied inside the handler.
	mux.HandleFunc("/api/"+APIVersion+"/append", withSizeCap(lim.AppendBodyBytes, s.handleAppend))
	// Read-only paths still get a defensive cap so malformed clients
	// can't fire a chunked GET body and burn memory.
	mux.HandleFunc("/api/"+APIVersion+"/entries/", withSizeCap(lim.AdminBodyBytes, s.handleGetEntry))
	mux.HandleFunc("/api/"+APIVersion+"/entries", withSizeCap(lim.AdminBodyBytes, s.handleEntriesRange))
	mux.HandleFunc("/api/"+APIVersion+"/size", withSizeCap(lim.AdminBodyBytes, s.handleSize))
	mux.HandleFunc("/api/"+APIVersion+"/proof/inclusion", withSizeCap(lim.AdminBodyBytes, s.handleInclusionProof))
	mux.HandleFunc("/api/"+APIVersion+"/proof/consistency", withSizeCap(lim.AdminBodyBytes, s.handleConsistencyProof))
	mux.HandleFunc("/api/"+APIVersion+"/pubkey", withSizeCap(lim.AdminBodyBytes, s.handlePubKey))
	mux.HandleFunc("/api/"+APIVersion+"/keychain", withSizeCap(lim.AdminBodyBytes, s.handleKeyChain))
	mux.HandleFunc("/api/"+APIVersion+"/threshold-group", withSizeCap(lim.AdminBodyBytes, s.handleThresholdGroup))
	mux.HandleFunc("/api/"+APIVersion+"/read-log/size", withSizeCap(lim.AdminBodyBytes, s.handleReadLogSize))
	mux.HandleFunc("/api/"+APIVersion+"/read-log/events", withSizeCap(lim.AdminBodyBytes, s.handleReadLogRange))
	mux.HandleFunc("/api/"+APIVersion+"/admin-log/size", withSizeCap(lim.AdminBodyBytes, s.handleAdminLogSize))
	mux.HandleFunc("/api/"+APIVersion+"/admin-log/events", withSizeCap(lim.AdminBodyBytes, s.handleAdminLogRange))
	// Admin mutation endpoints: size cap + per-actor rate limit. The
	// rate limiter passes GET requests through untouched so reads of
	// /producers, /witnesses, /enrollments stay cheap.
	mux.HandleFunc("/api/"+APIVersion+"/checkpoint",
		withSizeCap(lim.AdminBodyBytes, s.rateLimitAdmin("checkpoint", s.handleCheckpoint)))
	mux.HandleFunc("/api/"+APIVersion+"/anchor",
		withSizeCap(lim.AdminBodyBytes, s.rateLimitAdmin("anchor", s.handleAnchor)))
	mux.HandleFunc("/api/"+APIVersion+"/rotate",
		withSizeCap(lim.AdminBodyBytes, s.rateLimitAdmin("rotate", s.handleRotate)))
	mux.HandleFunc("/api/"+APIVersion+"/producers",
		withSizeCap(lim.AdminBodyBytes, s.rateLimitAdmin("producers", s.handleProducers)))
	mux.HandleFunc("/api/"+APIVersion+"/witnesses",
		withSizeCap(lim.AdminBodyBytes, s.rateLimitAdmin("witnesses", s.handleWitnesses)))
	mux.HandleFunc("/api/"+APIVersion+"/enrollments",
		withSizeCap(lim.AdminBodyBytes, s.rateLimitAdmin("enrollments", s.handleEnrollments)))
	mux.HandleFunc("/api/"+APIVersion+"/enrollments/begin",
		withSizeCap(lim.AdminBodyBytes, s.rateLimitAdmin("enrollments_begin", s.handleEnrollmentsBegin)))
	mux.HandleFunc("/api/"+APIVersion+"/enrollments/confirm",
		withSizeCap(lim.AdminBodyBytes, s.rateLimitAdmin("enrollments_confirm", s.handleEnrollmentsConfirm)))
	mux.HandleFunc("/api/"+APIVersion+"/producers/revoke",
		withSizeCap(lim.AdminBodyBytes, s.rateLimitAdmin("producers_revoke", s.handleRevokeProducer)))
	// /healthz, /readyz, /metrics are mounted by callers via obs.Mount.
	return mux
}

// ---- handlers ----

func (s *Server) handleAppend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req AppendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyErr(w, "append", fmt.Errorf("invalid JSON: %w", err))
		return
	}
	if req.Envelope == nil {
		writeErr(w, http.StatusBadRequest, errors.New("envelope is required"))
		return
	}
	// If mTLS is enforced, the TLS client cert's Common Name must match
	// the envelope's ProducerID. This binds network identity to the
	// cryptographic producer identity. An attacker who stole only the
	// producer's signing key but cannot also obtain the producer's TLS
	// client cert is stopped here.
	if s.RequireClientCertCN {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeErr(w, http.StatusUnauthorized, errors.New("client certificate required"))
			return
		}
		cn := strings.TrimSpace(r.TLS.PeerCertificates[0].Subject.CommonName)
		if cn != req.Envelope.ProducerID {
			writeErr(w, http.StatusForbidden,
				fmt.Errorf("client cert CN %q does not match envelope ProducerID %q", cn, req.Envelope.ProducerID))
			return
		}
	}
	// Per-producer rate limiting: this is the cheapest of the gates,
	// runs first. Producer IDs come from the parsed envelope so we
	// only rate-limit clients who at least submitted a well-formed
	// envelope. Pure-junk POSTs are bounded by the size cap above.
	if !s.gate.allowProducer(req.Envelope.ProducerID) {
		obs.IngestRejectsTotal.WithLabelValues("append", "rate_limit").Inc()
		writeRetryAfter(w, http.StatusTooManyRequests, s.gate.retryAfterSeconds(),
			fmt.Sprintf("producer %q rate-limited", req.Envelope.ProducerID))
		return
	}
	// Server-wide concurrency: a single producer at quota plus N
	// quiet producers can still saturate the server if each Append
	// is slow. The semaphore bounds total in-flight work and returns
	// a polite 503 + Retry-After when full.
	if !s.gate.acquire() {
		obs.IngestRejectsTotal.WithLabelValues("append", "concurrency").Inc()
		writeRetryAfter(w, http.StatusServiceUnavailable, s.gate.retryAfterSeconds(),
			"server at concurrent-append capacity")
		return
	}
	defer s.gate.release()

	entry, err := s.Log.AppendCtx(r.Context(), req.Envelope, req.Honeypot)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if s.AppendObserver != nil {
		s.AppendObserver()
	}
	writeJSON(w, http.StatusOK, AppendResponse{Entry: entry})
}

func (s *Server) handleReadLogSize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	if s.ReadLog == nil {
		writeErr(w, http.StatusNotFound, errors.New("read log not enabled"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"size":      s.ReadLog.Size(),
		"pub_key":   s.ReadLog.PublicKey(),
	})
}

func (s *Server) handleReadLogRange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	if s.ReadLog == nil {
		writeErr(w, http.StatusNotFound, errors.New("read log not enabled"))
		return
	}
	q := r.URL.Query()
	from, err := strconv.ParseUint(q.Get("from"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid from: %w", err))
		return
	}
	to, err := strconv.ParseUint(q.Get("to"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid to: %w", err))
		return
	}
	events, err := s.ReadLog.Range(from, to)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleAdminLogSize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	if s.AdminLog == nil {
		writeErr(w, http.StatusNotFound, errors.New("admin log not enabled"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"size":              s.AdminLog.Size(),
		"pub_key":           s.AdminLog.PublicKey(),
		"quantum_pub_key":   s.AdminLog.QuantumPublicKey(),
	})
}

func (s *Server) handleAdminLogRange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	if s.AdminLog == nil {
		writeErr(w, http.StatusNotFound, errors.New("admin log not enabled"))
		return
	}
	q := r.URL.Query()
	from, err := strconv.ParseUint(q.Get("from"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid from: %w", err))
		return
	}
	to, err := strconv.ParseUint(q.Get("to"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid to: %w", err))
		return
	}
	events, err := s.AdminLog.Range(from, to)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleThresholdGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	g := s.Log.Signer().ThresholdGroup()
	writeJSON(w, http.StatusOK, ThresholdGroupResponse{Group: g})
}

func (s *Server) handleWitnesses(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ws, err := s.Log.ListWitnesses()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, ListWitnessesResponse{Witnesses: ws})
	case http.MethodPost:
		var req RegisterWitnessRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBodyErr(w, "witnesses", err)
			return
		}
		if req.Witness == nil || req.Witness.ID == "" {
			writeErr(w, http.StatusBadRequest, errors.New("witness.id is required"))
			return
		}
		req.Witness.AddedAt = time.Now().UnixNano()
		err := s.Log.RegisterWitness(req.Witness)
		s.recordAdmin(r, "witness_add", req.Witness.ID, map[string]any{
			"url":        req.Witness.URL,
			"public_key": req.Witness.PublicKey,
		}, err)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, req.Witness)
	default:
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *Server) handleProducers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var list []*storage.Producer
		err := s.Log.ListProducers(func(p *storage.Producer) error {
			list = append(list, p)
			return nil
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, ListProducersResponse{Producers: list})
	case http.MethodPost:
		var req RegisterProducerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBodyErr(w, "producers", err)
			return
		}
		if req.Producer == nil || req.Producer.ID == "" {
			writeErr(w, http.StatusBadRequest, errors.New("producer.id is required"))
			return
		}
		err := s.Log.RegisterProducer(req.Producer)
		s.recordAdmin(r, "producer_register", req.Producer.ID, map[string]any{
			"public_key":         req.Producer.PublicKey,
			"attestation_type":   req.Producer.AttestationType,
			"quantum_public_key": req.Producer.QuantumPublicKey != nil,
		}, err)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, req.Producer)
	default:
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *Server) handleGetEntry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	idxStr := strings.TrimPrefix(r.URL.Path, "/api/"+APIVersion+"/entries/")
	if idxStr == "" || strings.Contains(idxStr, "/") {
		writeErr(w, http.StatusBadRequest, errors.New("path must be /entries/<index>"))
		return
	}
	idx, err := strconv.ParseUint(idxStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid index: %w", err))
		return
	}
	entry, err := s.Log.Get(idx)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if entry.Honeypot {
		s.fireHoney(r, entry.Index, entry.LeafHash, "GET /entries/{idx}")
	}
	s.recordRead(r, entry.Index, entry.LeafHash, "get_entry")
	writeJSON(w, http.StatusOK, EntryResponse{Entry: entry})
}

func (s *Server) handleEntriesRange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	q := r.URL.Query()
	from, err := strconv.ParseUint(q.Get("from"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid 'from': %w", err))
		return
	}
	to, err := strconv.ParseUint(q.Get("to"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid 'to': %w", err))
		return
	}
	if to <= from {
		writeErr(w, http.StatusBadRequest, errors.New("'to' must be > 'from'"))
		return
	}
	if to-from > 10_000 {
		writeErr(w, http.StatusBadRequest, errors.New("range too large (max 10000)"))
		return
	}
	resp := EntriesResponse{From: from, To: to}
	for i := from; i < to; i++ {
		e, err := s.Log.Get(i)
		if err != nil {
			break // partial range = log shorter than requested
		}
		if e.Honeypot {
			s.fireHoney(r, e.Index, e.LeafHash, "GET /entries?from=..&to=..")
		}
		s.recordRead(r, e.Index, e.LeafHash, "range_entry")
		resp.Entries = append(resp.Entries, e)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	size := s.Log.Size()
	root := s.Log.Root()
	// head hash: best-effort
	var head []byte
	if cp, err := s.Log.LatestCheckpoint(); err == nil && cp != nil {
		head = cp.HeadHash
	}
	writeJSON(w, http.StatusOK, SizeResponse{Size: size, RootHash: root, HeadHash: head})
}

func (s *Server) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c, err := s.Log.LatestCheckpoint()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if c == nil {
			writeErr(w, http.StatusNotFound, errors.New("no checkpoint yet"))
			return
		}
		writeJSON(w, http.StatusOK, CheckpointResponse{Checkpoint: c})
	case http.MethodPost:
		c, err := s.Log.Checkpoint()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, CheckpointResponse{Checkpoint: c})
	default:
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *Server) handleAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	recs, err := s.Log.Anchor()
	if err != nil {
		// partial success may still produce records; report 207-style
		if len(recs) == 0 {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, AnchorResponse{Records: recs})
}

func (s *Server) handleInclusionProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	q := r.URL.Query()
	idx, err := strconv.ParseUint(q.Get("index"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid index: %w", err))
		return
	}
	treeSize := s.Log.Size()
	if sz := q.Get("tree_size"); sz != "" {
		treeSize, err = strconv.ParseUint(sz, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid tree_size: %w", err))
			return
		}
	}
	entry, err := s.Log.Get(idx)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	proofHashes, err := s.Log.InclusionProof(idx, treeSize)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// Root at treeSize: for the current size we have it; otherwise we
	// compute it by reading entries up to treeSize. For MVP we only serve
	// proofs at the current size (treeSize == log.Size()).
	root := s.Log.Root()
	if treeSize != s.Log.Size() {
		writeErr(w, http.StatusNotImplemented, errors.New("MVP only serves proofs at current tree size"))
		return
	}
	writeJSON(w, http.StatusOK, InclusionProofResponse{
		Index:    idx,
		TreeSize: treeSize,
		LeafHash: entry.LeafHash,
		Proof:    proofHashes,
		RootHash: root,
	})
}

func (s *Server) handleConsistencyProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	q := r.URL.Query()
	oldSize, err := strconv.ParseUint(q.Get("old"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid old: %w", err))
		return
	}
	newSize := s.Log.Size()
	if ns := q.Get("new"); ns != "" {
		newSize, err = strconv.ParseUint(ns, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid new: %w", err))
			return
		}
	}
	if newSize != s.Log.Size() {
		writeErr(w, http.StatusNotImplemented, errors.New("MVP only serves proofs at current tree size"))
		return
	}
	proofHashes, err := s.Log.ConsistencyProof(oldSize, newSize)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// New root.
	newRoot := s.Log.Root()
	// Old root: load from the checkpoint nearest to oldSize, or compute.
	var oldRoot []byte
	if cp, err := s.Log.LatestCheckpoint(); err == nil && cp != nil && cp.Size == oldSize {
		oldRoot = cp.RootHash
	}
	writeJSON(w, http.StatusOK, ConsistencyProofResponse{
		OldSize: oldSize,
		NewSize: newSize,
		OldRoot: oldRoot,
		NewRoot: newRoot,
		Proof:   proofHashes,
	})
}

func (s *Server) handlePubKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	chain := s.Log.Signer().Chain()
	rootPub := chain.RootPublicKey()
	activePub := chain.ActivePublicKey()
	activeSum := sha256.Sum256(activePub)
	writeJSON(w, http.StatusOK, PubKeyResponse{
		Origin:        s.Log.Origin(),
		RootPublicKey: rootPub,
		ActiveEpoch:   chain.ActiveEpoch(),
		ActiveKeyID:   hex.EncodeToString(activeSum[:8]),
	})
}

func (s *Server) handleKeyChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	writeJSON(w, http.StatusOK, KeyChainResponse{Chain: s.Log.Signer().Chain()})
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	preEpoch := s.Log.Signer().Chain().ActiveEpoch()
	err := s.Log.Rotate()
	postEpoch := s.Log.Signer().Chain().ActiveEpoch()
	details := map[string]any{
		"from_epoch": preEpoch,
		"to_epoch":   postEpoch,
	}
	s.recordAdmin(r, "rotate", "", details, err)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, KeyChainResponse{Chain: s.Log.Signer().Chain()})
}

// handleEnrollments mints a signed enrollment (POST) or lists all
// active enrollments (GET). Minting is an admin action: the operator
// must run steled itself to do it, since the active chain key signs
// the record.
func (s *Server) handleEnrollments(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// List producers that carry a signed enrollment.
		var list []*storage.Producer
		err := s.Log.ListProducers(func(p *storage.Producer) error {
			if p.HasEnrollment() {
				list = append(list, p)
			}
			return nil
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, ListProducersResponse{Producers: list})
	case http.MethodPost:
		var req EnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBodyErr(w, "enrollments", err)
			return
		}
		if req.ID == "" || len(req.PublicKey) == 0 {
			writeErr(w, http.StatusBadRequest, errors.New("id and public_key are required"))
			return
		}
		prod, err := s.Log.IssueEnrollment(core.EnrollmentRequest{
			ID:               req.ID,
			PublicKey:        req.PublicKey,
			QuantumPublicKey: req.QuantumPublicKey,
			AttestationType:  req.AttestationType,
			Description:      req.Description,
			Scope:            req.Scope,
			Validity:         time.Duration(req.ValiditySeconds) * time.Second,
		})
		// Record into admin log regardless of outcome so failed
		// enrollment attempts are auditable too.
		s.recordAdmin(r, "enrollment_issue", req.ID, map[string]any{
			"scope":             req.Scope,
			"validity_seconds":  req.ValiditySeconds,
			"hybrid":            len(req.QuantumPublicKey) > 0,
			"attestation_type":  req.AttestationType,
		}, err)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, EnrollmentResponse{Producer: prod})
	default:
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

// handleEnrollmentsBegin starts a challenge-response enrollment. It
// builds the pending state, returns the bytes the producer must sign.
// Until /enrollments/confirm completes (within ~5min), nothing is
// persisted — so failed/abandoned enrollments cost no storage.
func (s *Server) handleEnrollmentsBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req BeginEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyErr(w, "enrollments_begin", err)
		return
	}
	if req.ID == "" || len(req.PublicKey) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("id and public_key are required"))
		return
	}
	res, err := s.Log.BeginEnrollment(core.EnrollmentRequest{
		ID:               req.ID,
		PublicKey:        req.PublicKey,
		QuantumPublicKey: req.QuantumPublicKey,
		AttestationType:  req.AttestationType,
		Description:      req.Description,
		Scope:            req.Scope,
		Validity:         time.Duration(req.ValiditySeconds) * time.Second,
	})
	// Begin is not yet a state-mutating event — don't admin-log it.
	// We log only Confirm (after the producer actually proves
	// possession).
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, BeginEnrollmentResponse{
		ChallengeID:    res.ChallengeID,
		ChallengeBytes: res.ChallengeBytes,
		ExpiresAtNS:    res.ExpiresAt.UnixNano(),
	})
}

// handleEnrollmentsConfirm completes a challenge-response enrollment.
// On success, the producer record persisted carries BOTH the
// operator's enrollment signature AND the producer's challenge
// response — proof both parties agreed to these terms.
func (s *Server) handleEnrollmentsConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req ConfirmEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyErr(w, "enrollments_confirm", err)
		return
	}
	if req.ChallengeID == "" || len(req.Signature) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("challenge_id and signature are required"))
		return
	}
	prod, err := s.Log.ConfirmEnrollment(req.ChallengeID, req.Signature, req.QuantumSignature)
	// Record into admin log: this is a state-mutating event with
	// auditable consent evidence.
	subject := ""
	hybrid := false
	if prod != nil {
		subject = prod.ID
		hybrid = len(prod.QuantumPublicKey) > 0
	}
	s.recordAdmin(r, "enrollment_confirm", subject, map[string]any{
		"challenge_id": req.ChallengeID,
		"hybrid":       hybrid,
	}, err)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, EnrollmentResponse{Producer: prod})
}

// handleRevokeProducer revokes a producer and records the reason.
// Auditors fetch the revocation evidence from the admin log.
func (s *Server) handleRevokeProducer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req RevokeProducerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyErr(w, "producers_revoke", err)
		return
	}
	if req.ID == "" {
		writeErr(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	err := s.Log.RevokeProducer(req.ID, req.Reason)
	s.recordAdmin(r, "producer_revoke", req.ID, map[string]any{
		"reason": req.Reason,
	}, err)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": req.ID})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, ErrorResponse{Error: err.Error()})
}

// silence unused import in MVP
var _ = context.TODO

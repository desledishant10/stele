package witness

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/threshold"
)

// CosignRequest is what an operator sends to a witness's /cosign endpoint.
// Group is required when the checkpoint was threshold-signed (the witness
// needs it to verify the operator's t-of-N member signatures).
type CosignRequest struct {
	Checkpoint *checkpoint.Checkpoint `json:"checkpoint"`
	Chain      *fwdsec.Chain          `json:"chain"`
	Group      *threshold.Group       `json:"group,omitempty"`
}

// CosignResponse carries the witness signature back.
type CosignResponse struct {
	Sig *checkpoint.WitnessSig `json:"sig"`
}

// AddOperatorRequest is the body of POST /operators on the witness.
type AddOperatorRequest struct {
	Operator *WatchedOperator `json:"operator"`
}

// AddPeerRequest is the body of POST /peers.
type AddPeerRequest struct {
	Peer *Peer `json:"peer"`
}

// SeenResponse is the body of GET /seen?origin=X.
type SeenResponse struct {
	Origin string            `json:"origin"`
	Seen   map[uint64]string `json:"seen"` // size -> hex(root)
}

// SignedSeenResponse is the body of GET /seen-signed?origin=X. The
// witness's own signature on the seen map means peers can keep it as
// evidence and detect contradictions later.
type SignedSeenResponse struct {
	Statement *SignedSeen `json:"statement"`
}

// PeerAttestationsResponse is the body of GET /peer-attestations.
type PeerAttestationsResponse struct {
	Attestations []*PeerAttestation `json:"attestations"`
}

// CrossAttestationsResponse is the body of GET /cross-attestations.
type CrossAttestationsResponse struct {
	Attestations []*CrossAttestation `json:"attestations"`
}

// CheckpointResponse is the body of GET /checkpoint?origin=X&size=N.
type CheckpointResponse struct {
	Checkpoint *checkpoint.Checkpoint `json:"checkpoint"`
}

// IdentityResponse is what GET /pubkey returns from a witness.
type IdentityResponse struct {
	ID               string `json:"id"`
	PublicKey        []byte `json:"public_key"`
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	KeyID            string `json:"key_id"`
}

// NewMux returns an http.ServeMux with witness endpoints registered.
func NewMux(s *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/witness/v0/cosign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
			return
		}
		var req CosignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if req.Checkpoint == nil || req.Chain == nil {
			writeErr(w, http.StatusBadRequest, errors.New("checkpoint and chain required"))
			return
		}
		sig, err := s.Cosign(req.Checkpoint, req.Chain, req.Group)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, CosignResponse{Sig: sig})
	})
	mux.HandleFunc("/witness/v0/operators", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, s.ListOperators())
		case http.MethodPost:
			var req AddOperatorRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			if err := s.AddOperator(req.Operator); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, req.Operator)
		default:
			writeErr(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
		}
	})
	mux.HandleFunc("/witness/v0/peers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, s.ListPeers())
		case http.MethodPost:
			var req AddPeerRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			if err := s.AddPeer(req.Peer); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, req.Peer)
		default:
			writeErr(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
		}
	})
	mux.HandleFunc("/witness/v0/seen", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
			return
		}
		origin := r.URL.Query().Get("origin")
		if origin == "" {
			writeErr(w, http.StatusBadRequest, errors.New("origin required"))
			return
		}
		writeJSON(w, http.StatusOK, SeenResponse{Origin: origin, Seen: s.SeenFor(origin)})
	})
	mux.HandleFunc("/witness/v0/seen-signed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
			return
		}
		origin := r.URL.Query().Get("origin")
		if origin == "" {
			writeErr(w, http.StatusBadRequest, errors.New("origin required"))
			return
		}
		writeJSON(w, http.StatusOK, SignedSeenResponse{Statement: s.IssueSignedSeen(origin)})
	})
	mux.HandleFunc("/witness/v0/cross-attestations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
			return
		}
		peerID := r.URL.Query().Get("peer_id")
		writeJSON(w, http.StatusOK, CrossAttestationsResponse{
			Attestations: s.CrossAttestationsAbout(peerID),
		})
	})
	mux.HandleFunc("/witness/v0/peer-attestations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
			return
		}
		peerID := r.URL.Query().Get("peer_id") // empty = all peers
		writeJSON(w, http.StatusOK, PeerAttestationsResponse{Attestations: s.PeerAttestations(peerID)})
	})
	mux.HandleFunc("/witness/v0/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
			return
		}
		origin := r.URL.Query().Get("origin")
		sizeStr := r.URL.Query().Get("size")
		if origin == "" || sizeStr == "" {
			writeErr(w, http.StatusBadRequest, errors.New("origin and size required"))
			return
		}
		size, err := strconv.ParseUint(sizeStr, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		cp := s.CheckpointAt(origin, size)
		if cp == nil {
			writeErr(w, http.StatusNotFound, errors.New("not seen"))
			return
		}
		writeJSON(w, http.StatusOK, CheckpointResponse{Checkpoint: cp})
	})
	mux.HandleFunc("/witness/v0/forks", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, s.ListForks())
		case http.MethodDelete:
			origin := r.URL.Query().Get("origin")
			if origin == "" {
				writeErr(w, http.StatusBadRequest, errors.New("origin required"))
				return
			}
			s.ClearFork(origin)
			writeJSON(w, http.StatusOK, map[string]string{"cleared": origin})
		default:
			writeErr(w, http.StatusMethodNotAllowed, errors.New("GET or DELETE"))
		}
	})
	mux.HandleFunc("/witness/v0/pubkey", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, IdentityResponse{
			ID:               s.ID(),
			PublicKey:        s.PublicKey(),
			QuantumPublicKey: s.QuantumPublicKey(),
			KeyID:            s.KeyID(),
		})
	})
	// /healthz, /readyz, /metrics are mounted by callers via obs.Mount.
	return mux
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

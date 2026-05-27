package mirror

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/desledishant10/stele/pkg/api"
	"github.com/desledishant10/stele/pkg/core"
)

// fakeServer is a tiny test HTTP server that mimics steled's read API
// but tampers with the entry at tamperIndex (corrupts envelope data
// without re-signing). The mirror should detect this and refuse.
type fakeServer struct {
	op          *core.Log
	tamperIndex uint64
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/v0/size":
		json.NewEncoder(w).Encode(api.SizeResponse{Size: f.op.Size()})
	case strings.HasPrefix(r.URL.Path, "/api/v0/entries/"):
		idxStr := strings.TrimPrefix(r.URL.Path, "/api/v0/entries/")
		idx, _ := strconv.ParseUint(idxStr, 10, 64)
		f.writeEntry(w, idx)
	case r.URL.Path == "/api/v0/entries":
		q := r.URL.Query()
		from, _ := strconv.ParseUint(q.Get("from"), 10, 64)
		to, _ := strconv.ParseUint(q.Get("to"), 10, 64)
		f.writeRange(w, from, to)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeServer) writeEntry(w http.ResponseWriter, idx uint64) {
	e, err := f.op.Get(idx)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	if idx == f.tamperIndex {
		e.Envelope.Data[0] ^= 0xFF
	}
	json.NewEncoder(w).Encode(api.EntryResponse{Entry: e})
}

func (f *fakeServer) writeRange(w http.ResponseWriter, from, to uint64) {
	resp := api.EntriesResponse{From: from, To: to}
	for i := from; i < to && i < f.op.Size(); i++ {
		e, _ := f.op.Get(i)
		if i == f.tamperIndex {
			e.Envelope.Data[0] ^= 0xFF
		}
		resp.Entries = append(resp.Entries, e)
	}
	json.NewEncoder(w).Encode(resp)
}

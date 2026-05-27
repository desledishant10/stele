package trustdns

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockResolver starts a tiny in-process DNS server that answers
// queries for a fixed name with a fixed TXT body. The `ad` flag
// controls whether the answer claims DNSSEC validation succeeded.
type mockResolver struct {
	srv  *dns.Server
	addr string
	wg   sync.WaitGroup
}

func startMockResolver(t *testing.T, name, txt string, ad bool) *mockResolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.AuthenticatedData = ad
		if len(r.Question) > 0 && strings.EqualFold(r.Question[0].Name, dns.Fqdn(name)) && r.Question[0].Qtype == dns.TypeTXT {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{txt},
			}
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})
	s := &dns.Server{PacketConn: pc, Handler: mux}
	mr := &mockResolver{srv: s, addr: addr}
	mr.wg.Add(1)
	go func() {
		defer mr.wg.Done()
		_ = s.ActivateAndServe()
	}()
	// Give the server a tick to start serving.
	time.Sleep(20 * time.Millisecond)
	t.Cleanup(func() {
		_ = s.Shutdown()
		mr.wg.Wait()
	})
	return mr
}

func TestFetch_HappyPath_RecordParsed(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	body := "v=stele/v1; root_pubkey=" + base64.StdEncoding.EncodeToString(pub)
	mr := startMockResolver(t, "_stele.example.com", body, true)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rec, err := Fetch(ctx, Config{Resolver: mr.addr, Timeout: time.Second}, "example.com")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if rec.Origin != "example.com" {
		t.Fatalf("origin = %q", rec.Origin)
	}
	if got := base64.StdEncoding.EncodeToString(rec.RootPublicKey); got != base64.StdEncoding.EncodeToString(pub) {
		t.Fatalf("root_pubkey mismatch: %s", got)
	}
	if rec.Version != "stele/v1" {
		t.Fatalf("version = %q", rec.Version)
	}
}

func TestFetch_RefusesWithoutADBit(t *testing.T) {
	pub := make([]byte, 32)
	body := "v=stele/v1; root_pubkey=" + base64.StdEncoding.EncodeToString(pub)
	// ad=false → resolver did NOT validate → trustdns must reject.
	mr := startMockResolver(t, "_stele.example.com", body, false)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Fetch(ctx, Config{Resolver: mr.addr, Timeout: time.Second}, "example.com")
	if err == nil {
		t.Fatal("Fetch should refuse responses without AD bit")
	}
	if !strings.Contains(err.Error(), "AD bit") {
		t.Fatalf("error should mention AD bit, got: %v", err)
	}
}

func TestFetch_NoRecords(t *testing.T) {
	// Mock responds to the right name but with NO answers — emulates
	// "domain exists but has no _stele subdomain configured."
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.AuthenticatedData = true
		// No answers.
		_ = w.WriteMsg(m)
	})
	s := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = s.ActivateAndServe() }()
	defer s.Shutdown()
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = Fetch(ctx, Config{Resolver: pc.LocalAddr().String(), Timeout: time.Second}, "example.com")
	if err == nil {
		t.Fatal("Fetch should fail with no answers")
	}
}

func TestParseTXT_AllFields(t *testing.T) {
	pub := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	qpub := []byte("BB")
	w1 := []byte("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
	w2 := []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	body := "v=stele/v1" +
		"; root_pubkey=" + base64.StdEncoding.EncodeToString(pub) +
		"; root_qpubkey=" + base64.StdEncoding.EncodeToString(qpub) +
		"; chain_digest=deadbeef" +
		"; witnesses=" + base64.StdEncoding.EncodeToString(w1) + "," + base64.StdEncoding.EncodeToString(w2)
	rec, err := ParseTXT(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(rec.RootPublicKey) != string(pub) {
		t.Fatalf("root_pubkey mismatch")
	}
	if string(rec.RootQuantumPublicKey) != string(qpub) {
		t.Fatalf("root_qpubkey mismatch")
	}
	if rec.ChainDigest == nil || rec.ChainDigest[0] != 0xde {
		t.Fatalf("chain_digest mismatch: %x", rec.ChainDigest)
	}
	if len(rec.Witnesses) != 2 {
		t.Fatalf("expected 2 witnesses, got %d", len(rec.Witnesses))
	}
}

func TestParseTXT_MissingRootPubkey(t *testing.T) {
	if _, err := ParseTXT("v=stele/v1; chain_digest=ab"); err == nil {
		t.Fatal("ParseTXT should reject records missing root_pubkey")
	}
}

func TestParseTXT_UnknownVersion(t *testing.T) {
	body := "v=other/v9; root_pubkey=" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := ParseTXT(body); err == nil {
		t.Fatal("ParseTXT should reject unknown version prefix")
	}
}

func TestFormatTXT_Roundtrip(t *testing.T) {
	orig := &Record{
		RootPublicKey:        []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		RootQuantumPublicKey: []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
		ChainDigest:          []byte{0xde, 0xad, 0xbe, 0xef},
		Witnesses: [][]byte{
			[]byte("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"),
		},
	}
	body := FormatTXT(orig)
	back, err := ParseTXT(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(back.RootPublicKey) != string(orig.RootPublicKey) ||
		string(back.RootQuantumPublicKey) != string(orig.RootQuantumPublicKey) ||
		string(back.ChainDigest) != string(orig.ChainDigest) ||
		len(back.Witnesses) != 1 ||
		string(back.Witnesses[0]) != string(orig.Witnesses[0]) {
		t.Fatalf("roundtrip mismatch: got %+v", back)
	}
}

// Package trustdns resolves a stele operator's root public key by
// looking up DNSSEC-signed TXT records at
//
//	_stele.<origin>
//
// The auditor's trust path becomes: I trust DNSSEC (the root KSK +
// the global registry hierarchy) → DNSSEC vouches that this TXT
// record really belongs to <origin> → the TXT record names the
// operator's root pubkey. This replaces the social-engineering-
// vulnerable "I was told the pubkey over Slack" first-mile of trust.
//
// Approach: we use a recursive DNSSEC-validating resolver and DEMAND
// the Authenticated Data (AD) bit on the response. The AD bit means
// "the resolver itself successfully validated the DNSSEC chain to
// the root KSK." This is the same trust path browsers + the rest of
// the internet rely on for DNSSEC-protected services.
//
// What the auditor must trust:
//
//  1. The recursive resolver they configure (default: 1.1.1.1 over
//     TCP+TLS in real deployments; tests inject a local mock).
//  2. The kernel's DNS stack between them and the resolver, OR they
//     bring their own validating stub via --resolver.
//
// What the auditor does NOT have to trust:
//
//   - The operator. The DNSSEC signature is checked end-to-end.
//   - Whoever told them the operator's pubkey out of band.
//
// TXT record format (single record, space-separated key=value pairs):
//
//	"root_pubkey=<base64-ed25519>; chain_digest=<hex-sha256>; v=stele/v1"
//
// Optional fields:
//
//	root_qpubkey=<base64-dilithium3>   (hybrid mode)
//	witnesses=<comma-separated-base64-ed25519>
//
// stele-export-chain emits exactly this format with `--format dns`.
package trustdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Record is the parsed contents of a `_stele.<origin>` TXT record.
type Record struct {
	Origin       string
	RootPublicKey []byte
	RootQuantumPublicKey []byte // optional
	ChainDigest  []byte         // SHA-256 of the operator chain, optional
	Witnesses    [][]byte       // optional list of trusted witness pubkeys
	Version      string         // e.g. "stele/v1"
}

// Config configures a Resolver. Resolver defaults to 1.1.1.1:53 if
// empty. Timeout defaults to 5 seconds.
type Config struct {
	Resolver string
	Timeout  time.Duration
}

// Fetch performs a DNSSEC-validated lookup of `_stele.<origin>` and
// returns the parsed Record. Fails if:
//
//   - the lookup errors,
//   - the response lacks the Authenticated Data bit (DNSSEC was not
//     validated by the resolver — anyone in the middle could have
//     forged the answer),
//   - no TXT records are present,
//   - none of the TXT records parse as a stele v1 record.
//
// On success the caller knows that the recursive resolver successfully
// chained the response back to the global DNSSEC root. The auditor's
// trust assumption is "I trust this resolver", which is a much
// smaller surface than "I trust whoever told me the pubkey."
func Fetch(ctx context.Context, cfg Config, origin string) (*Record, error) {
	if origin == "" {
		return nil, errors.New("trustdns: origin required")
	}
	resolver := cfg.Resolver
	if resolver == "" {
		resolver = "1.1.1.1:53"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	name := dns.Fqdn("_stele." + origin)
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	// DO (DNSSEC OK) bit: tell the resolver we want DNSSEC. AD
	// (Authenticated Data) bit: ask the resolver to validate and set
	// AD on the reply.
	m.SetEdns0(4096, true)
	m.AuthenticatedData = true

	c := &dns.Client{
		Net:     "udp", // tcp/tls upgrade is automatic on truncation
		Timeout: timeout,
	}
	// dns.Client.ExchangeContext respects ctx for cancellation.
	in, _, err := c.ExchangeContext(ctx, m, ensurePort(resolver))
	if err != nil {
		return nil, fmt.Errorf("trustdns: query %s: %w", name, err)
	}
	if in.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("trustdns: query %s: rcode=%s", name, dns.RcodeToString[in.Rcode])
	}
	if !in.AuthenticatedData {
		return nil, fmt.Errorf("trustdns: response for %s lacks AD bit — DNSSEC validation FAILED (use a DNSSEC-validating resolver)", name)
	}

	for _, rr := range in.Answer {
		t, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		// A single TXT RR may have multiple <character-strings>; join
		// them as the protocol spec does.
		joined := strings.Join(t.Txt, "")
		rec, err := ParseTXT(joined)
		if err != nil {
			continue
		}
		rec.Origin = origin
		return rec, nil
	}
	return nil, fmt.Errorf("trustdns: no parseable stele TXT records at %s (got %d answers)", name, len(in.Answer))
}

// ParseTXT parses a stele TXT record from its on-the-wire string.
// Exposed for testability and for `stele-export-chain` to round-trip.
func ParseTXT(raw string) (*Record, error) {
	if raw == "" {
		return nil, errors.New("trustdns: empty TXT body")
	}
	rec := &Record{}
	for _, part := range strings.Split(raw, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		switch k {
		case "v", "version":
			rec.Version = v
		case "root_pubkey":
			b, err := decodeBase64(v)
			if err != nil {
				return nil, fmt.Errorf("trustdns: root_pubkey: %w", err)
			}
			rec.RootPublicKey = b
		case "root_qpubkey":
			b, err := decodeBase64(v)
			if err != nil {
				return nil, fmt.Errorf("trustdns: root_qpubkey: %w", err)
			}
			rec.RootQuantumPublicKey = b
		case "chain_digest":
			b, err := decodeHex(v)
			if err != nil {
				return nil, fmt.Errorf("trustdns: chain_digest: %w", err)
			}
			rec.ChainDigest = b
		case "witnesses":
			for _, w := range strings.Split(v, ",") {
				if w = strings.TrimSpace(w); w == "" {
					continue
				}
				b, err := decodeBase64(w)
				if err != nil {
					return nil, fmt.Errorf("trustdns: witness: %w", err)
				}
				rec.Witnesses = append(rec.Witnesses, b)
			}
		}
	}
	if len(rec.RootPublicKey) == 0 {
		return nil, errors.New("trustdns: TXT record missing root_pubkey")
	}
	if rec.Version != "" && !strings.HasPrefix(rec.Version, "stele/v") {
		return nil, fmt.Errorf("trustdns: unrecognised version %q", rec.Version)
	}
	return rec, nil
}

// FormatTXT renders a Record back to the wire format used in the TXT
// record. Output is suitable for `_stele.<origin>. TXT "..."` zone
// files.
func FormatTXT(r *Record) string {
	parts := []string{"v=stele/v1"}
	parts = append(parts, "root_pubkey="+encodeBase64(r.RootPublicKey))
	if len(r.RootQuantumPublicKey) > 0 {
		parts = append(parts, "root_qpubkey="+encodeBase64(r.RootQuantumPublicKey))
	}
	if len(r.ChainDigest) > 0 {
		parts = append(parts, "chain_digest="+encodeHex(r.ChainDigest))
	}
	if len(r.Witnesses) > 0 {
		ws := make([]string, 0, len(r.Witnesses))
		for _, w := range r.Witnesses {
			ws = append(ws, encodeBase64(w))
		}
		parts = append(parts, "witnesses="+strings.Join(ws, ","))
	}
	return strings.Join(parts, "; ")
}

// ensurePort returns host:port. If host has no :, default :53 is
// appended.
func ensurePort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return host + ":53"
}

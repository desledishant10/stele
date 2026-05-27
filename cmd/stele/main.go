// stele is the command-line client and auditor for steled.
//
// Common usage:
//
//	stele --server http://localhost:8080 size
//	stele log "user alice deleted file /etc/passwd"
//	stele audit
//
// Run `stele help` for the full list of subcommands.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/desledishant10/stele/pkg/api"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/audit"
	"github.com/desledishant10/stele/pkg/auditpdf"
	"github.com/desledishant10/stele/pkg/logentry"
	"github.com/desledishant10/stele/pkg/storage"
	"github.com/desledishant10/stele/pkg/threshold"
	"github.com/desledishant10/stele/pkg/tlsutil"
	"github.com/desledishant10/stele/pkg/trustdns"
	"github.com/desledishant10/stele/pkg/verify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "log":
		err = cmdLog(args)
	case "get":
		err = cmdGet(args)
	case "size":
		err = cmdSize(args)
	case "checkpoint":
		err = cmdCheckpoint(args)
	case "mint-checkpoint":
		err = cmdMintCheckpoint(args)
	case "anchor":
		err = cmdAnchor(args)
	case "pubkey":
		err = cmdPubkey(args)
	case "keychain":
		err = cmdKeyChain(args)
	case "rotate":
		err = cmdRotate(args)
	case "producer-init":
		err = cmdProducerInit(args)
	case "producer-register":
		err = cmdProducerRegister(args)
	case "producer-list":
		err = cmdProducerList(args)
	case "enroll-producer":
		err = cmdEnrollProducer(args)
	case "revoke-producer":
		err = cmdRevokeProducer(args)
	case "witness-add":
		err = cmdWitnessAdd(args)
	case "witness-list":
		err = cmdWitnessList(args)
	case "witness-peer-add":
		err = cmdWitnessPeerAdd(args)
	case "witness-forks":
		err = cmdWitnessForks(args)
	case "cosigner-init":
		err = cmdCosignerInit(args)
	case "group-init":
		err = cmdGroupInit(args)
	case "group-show":
		err = cmdGroupShow(args)
	case "dns-record":
		err = cmdDNSRecord(args)
	case "dnssec-fetch":
		err = cmdDNSSECFetch(args)
	case "ca-init":
		err = cmdCAInit(args)
	case "ca-issue-server":
		err = cmdCAIssueServer(args)
	case "ca-issue-producer":
		err = cmdCAIssueProducer(args)
	case "verify-inclusion":
		err = cmdVerifyInclusion(args)
	case "verify-consistency":
		err = cmdVerifyConsistency(args)
	case "audit":
		err = cmdAudit(args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "stele: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `stele — provenance-log client and auditor

Usage: stele <subcommand> [flags]

Subcommands:
  log                <text>         Append an attested entry (requires --producer + --key)
  get                <index>        Fetch entry by index
  size                              Print current size, root, head
  checkpoint                        Show latest signed checkpoint
  mint-checkpoint                   Tell the server to sign a new checkpoint
  anchor                            Tell the server to anchor latest checkpoint
  pubkey                            Show the operator public key
  producer-init                     Generate a producer keypair (--id, --out)
  producer-register                 Register a producer with the operator (--id, --key|--pub)
  producer-list                     List producers known to the operator
  enroll-producer                   Mint a SIGNED enrollment via two-step proof-of-possession (--id, --key, --scope, --validity; add --unverified for legacy one-step)
  revoke-producer                   Revoke a producer (--id, --reason); future Appends refused
  ca-init                           Generate an operator CA (--out-cert, --out-key, --org)
  ca-issue-server                   Issue a server cert (--ca-cert, --ca-key, --host, --out-*)
  ca-issue-producer                 Issue a producer client cert (--ca-cert, --ca-key, --id, --out-*)
  dns-record                        Emit the TXT record to publish under _stele.<domain> (--domain)
  dnssec-fetch                      DNSSEC-validate _stele.<origin> + print the root pubkey (--origin, --resolver)
  verify-inclusion   <index>        Fetch entry + proof and verify
  verify-consistency <old> <new>    Fetch consistency proof and verify
  audit                             Full audit (chain, checkpoint, anchors)

Common flags:
  --server   URL   steled base URL (default http://localhost:8080)
  --source   NAME  for 'log': origin tag on the entry (default $USER@host)
  --producer ID    for 'log': registered producer ID
  --key      PATH  for 'log': producer Ed25519 private key
  --honey          for 'log': mark entry as a honeypot canary`)
}

// ---- generic helpers ----

// clientTLSFlags carries optional TLS settings shared across subcommands.
type clientTLSFlags struct {
	Cert       string
	Key        string
	CA         string
	SkipVerify bool
}

// clientTLS is populated by every newFlagSet call so all subcommands
// expose the same --tls-* flags.
var clientTLS clientTLSFlags

func newFlagSet(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "steled base URL (use https:// for TLS)")
	fs.StringVar(&clientTLS.Cert, "tls-cert", clientTLS.Cert, "client cert PEM (mTLS)")
	fs.StringVar(&clientTLS.Key, "tls-key", clientTLS.Key, "client key PEM (mTLS)")
	fs.StringVar(&clientTLS.CA, "tls-ca", clientTLS.CA, "PEM file of CAs to trust for the operator's cert")
	fs.BoolVar(&clientTLS.SkipVerify, "tls-skip-verify", clientTLS.SkipVerify, "skip server cert verification (DEV ONLY)")
	return fs, server
}

// httpClient returns an http.Client configured with current clientTLS.
func httpClient() *http.Client {
	if clientTLS.Cert == "" && clientTLS.CA == "" && !clientTLS.SkipVerify {
		return http.DefaultClient
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: clientTLS.SkipVerify, //nolint:gosec
	}
	if clientTLS.Cert != "" && clientTLS.Key != "" {
		cert, err := tls.LoadX509KeyPair(clientTLS.Cert, clientTLS.Key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stele: load client cert: %v\n", err)
			os.Exit(1)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if clientTLS.CA != "" {
		ca, err := os.ReadFile(clientTLS.CA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stele: read CA: %v\n", err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			fmt.Fprintf(os.Stderr, "stele: CA file contains no certs\n")
			os.Exit(1)
		}
		cfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}
}

func httpGet(server, path string, out any) error {
	resp, err := httpClient().Get(server + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var er api.ErrorResponse
		_ = json.Unmarshal(body, &er)
		if er.Error != "" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, er.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

func httpPost(server, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}
	resp, err := httpClient().Post(server+path, "application/json", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var er api.ErrorResponse
		_ = json.Unmarshal(respBody, &er)
		if er.Error != "" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, er.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(respBody, out)
}

func defaultSource() string {
	u := os.Getenv("USER")
	if u == "" {
		u = "user"
	}
	h, err := os.Hostname()
	if err != nil {
		h = "host"
	}
	return u + "@" + h
}

// ---- subcommands ----

func cmdLog(args []string) error {
	fs, server := newFlagSet("log")
	source := fs.String("source", defaultSource(), "source label embedded in the envelope")
	producerID := fs.String("producer", "", "producer ID (must be registered with the operator)")
	keyPath := fs.String("key", "", "path to producer Ed25519 private key (base64)")
	honeypot := fs.Bool("honey", false, "mark entry as a honeypot canary")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("log: provide text to log (or pipe data via stdin)")
	}
	if *producerID == "" || *keyPath == "" {
		return errors.New("log: --producer and --key are required")
	}

	var data []byte
	if rest[0] == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		data = b
	} else {
		joined := rest[0]
		for _, r := range rest[1:] {
			joined += " " + r
		}
		data = []byte(joined)
	}

	att, err := attest.LoadSoftwareAttestor(*producerID, *keyPath)
	if err != nil {
		return fmt.Errorf("load producer key: %w", err)
	}
	env, err := att.Sign(*source, data)
	if err != nil {
		return fmt.Errorf("sign envelope: %w", err)
	}

	var resp api.AppendResponse
	if err := httpPost(*server, "/api/v0/append", api.AppendRequest{Envelope: env, Honeypot: *honeypot}, &resp); err != nil {
		return err
	}
	e := resp.Entry
	fmt.Printf("entry %d sealed at %s\n  producer   : %s\n  source     : %s\n  data       : %q\n  honeypot   : %v\n  entry_hash : %s\n  leaf_hash  : %s\n  prev_hash  : %s\n",
		e.Index, time.Unix(0, e.TimeNanos).UTC().Format(time.RFC3339Nano),
		e.Envelope.ProducerID, e.Envelope.Source, string(e.Envelope.Data), e.Honeypot,
		hex.EncodeToString(e.EntryHash), hex.EncodeToString(e.LeafHash), hex.EncodeToString(e.PrevHash))
	return nil
}

func cmdProducerInit(args []string) error {
	fs := flag.NewFlagSet("producer-init", flag.ExitOnError)
	id := fs.String("id", "", "producer ID")
	keyOut := fs.String("out", "", "path to write the producer private key (base64)")
	hybrid := fs.Bool("pq", false, "generate a HYBRID key (Ed25519 + Dilithium3) for post-quantum-protected envelopes")
	_ = fs.Parse(args)
	if *id == "" || *keyOut == "" {
		return errors.New("producer-init: --id and --out are required")
	}
	var att *attest.SoftwareAttestor
	var err error
	if *hybrid {
		att, err = attest.NewHybridSoftwareAttestor(*id)
	} else {
		att, err = attest.NewSoftwareAttestor(*id)
	}
	if err != nil {
		return err
	}
	if err := att.WriteKey(*keyOut); err != nil {
		return err
	}
	mode := "classical"
	if *hybrid {
		mode = "hybrid (Ed25519+Dilithium3)"
	}
	fmt.Printf("producer key written: %s\n  id         : %s\n  mode       : %s\n  public_key : %s\n",
		*keyOut, *id, mode, base64.StdEncoding.EncodeToString(att.PublicKey()))
	if att.IsHybrid() {
		fmt.Printf("  quantum_pk : %s...\n", base64.StdEncoding.EncodeToString(att.QuantumPublicKey())[:32])
	}
	return nil
}

func cmdProducerRegister(args []string) error {
	fs, server := newFlagSet("producer-register")
	id := fs.String("id", "", "producer ID to register")
	keyPath := fs.String("key", "", "path to producer private key (we extract the public key)")
	pubPath := fs.String("pub", "", "OR: path to a file containing only the base64 public key")
	desc := fs.String("desc", "", "human description")
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("producer-register: --id is required")
	}
	var pub ed25519.PublicKey
	switch {
	case *keyPath != "":
		att, err := attest.LoadSoftwareAttestor(*id, *keyPath)
		if err != nil {
			return err
		}
		pub = att.PublicKey()
	case *pubPath != "":
		raw, err := os.ReadFile(*pubPath)
		if err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return err
		}
		if len(decoded) != ed25519.PublicKeySize {
			return fmt.Errorf("public key wrong length %d", len(decoded))
		}
		pub = ed25519.PublicKey(decoded)
	default:
		return errors.New("producer-register: provide --key or --pub")
	}

	// If we loaded a hybrid key file (--key path), pick up the quantum
	// pubkey too so the registry knows to enforce hybrid binding.
	var qpub []byte
	if *keyPath != "" {
		att, err := attest.LoadSoftwareAttestor(*id, *keyPath)
		if err == nil && att.IsHybrid() {
			qpub = att.QuantumPublicKey()
		}
	}
	body := api.RegisterProducerRequest{Producer: &storage.Producer{
		ID:               *id,
		PublicKey:        pub,
		QuantumPublicKey: qpub,
		AttestationType:  string(attest.TypeSoftware),
		Description:      *desc,
	}}
	var out storage.Producer
	if err := httpPost(*server, "/api/v0/producers", body, &out); err != nil {
		return err
	}
	mode := "classical"
	if len(out.QuantumPublicKey) > 0 {
		mode = "hybrid"
	}
	fmt.Printf("producer registered: %s mode=%s pubkey=%s\n", out.ID, mode,
		base64.StdEncoding.EncodeToString(out.PublicKey))
	return nil
}

// cmdEnrollProducer enrolls a producer via the two-step
// challenge-response ceremony (proof of possession):
//
//   1. Call /enrollments/begin with the producer's pubkey + terms.
//      The server returns a one-time challenge to sign.
//   2. Sign the challenge locally with the producer's private key
//      (both classical and Dilithium3 if --key is hybrid).
//   3. Call /enrollments/confirm with the signature(s). On success
//      the server returns a Producer record carrying BOTH the
//      operator's enrollment signature AND the producer's challenge
//      response (provable consent + key possession).
//
// Use --unverified to fall back to the legacy one-step path that
// skips proof-of-possession (operator vouches unilaterally). That
// path is dangerous in --require-enrollment mode without
// out-of-band guarantees the pubkey is genuinely the producer's.
func cmdEnrollProducer(args []string) error {
	fs, server := newFlagSet("enroll-producer")
	id := fs.String("id", "", "producer ID to enroll")
	keyPath := fs.String("key", "", "path to producer private key (REQUIRED for two-step; --pub only valid with --unverified)")
	pubPath := fs.String("pub", "", "OR: path to file containing only the base64 public key (legacy --unverified path only)")
	desc := fs.String("desc", "", "human description")
	scope := fs.String("scope", "", "free-form authorisation scope, e.g. \"logs:audit\"")
	validity := fs.Duration("validity", 0, "how long the enrollment is valid (0 = never expires until revoked)")
	unverified := fs.Bool("unverified", false, "skip proof-of-possession; operator vouches unilaterally (legacy path)")
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("enroll-producer: --id is required")
	}

	if *unverified {
		return cmdEnrollProducerUnverified(*server, *id, *keyPath, *pubPath, *desc, *scope, *validity)
	}

	// Two-step (default): proof of possession.
	if *keyPath == "" {
		return errors.New("enroll-producer: --key is required for the proof-of-possession flow (use --unverified --pub for the legacy path)")
	}
	att, err := attest.LoadSoftwareAttestor(*id, *keyPath)
	if err != nil {
		return err
	}
	pub := att.PublicKey()
	var qpub []byte
	if att.IsHybrid() {
		qpub = att.QuantumPublicKey()
	}

	// Step 1: begin — server builds the challenge.
	beginReq := api.BeginEnrollmentRequest{
		ID:               *id,
		PublicKey:        pub,
		QuantumPublicKey: qpub,
		AttestationType:  string(attest.TypeSoftware),
		Description:      *desc,
		Scope:            *scope,
		ValiditySeconds:  int64(validity.Seconds()),
	}
	var begin api.BeginEnrollmentResponse
	if err := httpPost(*server, "/api/v0/enrollments/begin", beginReq, &begin); err != nil {
		return fmt.Errorf("enroll-producer: begin: %w", err)
	}
	if begin.ChallengeID == "" || len(begin.ChallengeBytes) == 0 {
		return errors.New("enroll-producer: server returned an empty challenge")
	}

	// Step 2: sign the challenge with the producer key.
	// Hybrid producers sign with BOTH keys (downgrade-resistance).
	classicalSig, qSig, err := att.SignChallenge(begin.ChallengeBytes)
	if err != nil {
		return fmt.Errorf("enroll-producer: sign challenge: %w", err)
	}

	// Step 3: confirm.
	confirmReq := api.ConfirmEnrollmentRequest{
		ChallengeID:      begin.ChallengeID,
		Signature:        classicalSig,
		QuantumSignature: qSig,
	}
	var out api.EnrollmentResponse
	if err := httpPost(*server, "/api/v0/enrollments/confirm", confirmReq, &out); err != nil {
		return fmt.Errorf("enroll-producer: confirm: %w", err)
	}
	if out.Producer == nil {
		return errors.New("enroll-producer: server returned no producer record")
	}
	printEnrolled(out.Producer)
	return nil
}

// cmdEnrollProducerUnverified is the legacy single-call path. Kept for
// migration and for emergency scenarios where the operator already
// trusts the channel.
func cmdEnrollProducerUnverified(server, id, keyPath, pubPath, desc, scope string, validity time.Duration) error {
	var pub ed25519.PublicKey
	var qpub []byte
	switch {
	case keyPath != "":
		att, err := attest.LoadSoftwareAttestor(id, keyPath)
		if err != nil {
			return err
		}
		pub = att.PublicKey()
		if att.IsHybrid() {
			qpub = att.QuantumPublicKey()
		}
	case pubPath != "":
		raw, err := os.ReadFile(pubPath)
		if err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return err
		}
		if len(decoded) != ed25519.PublicKeySize {
			return fmt.Errorf("public key wrong length %d", len(decoded))
		}
		pub = ed25519.PublicKey(decoded)
	default:
		return errors.New("enroll-producer: provide --key or --pub")
	}
	body := api.EnrollmentRequest{
		ID:               id,
		PublicKey:        pub,
		QuantumPublicKey: qpub,
		AttestationType:  string(attest.TypeSoftware),
		Description:      desc,
		Scope:            scope,
		ValiditySeconds:  int64(validity.Seconds()),
	}
	var out api.EnrollmentResponse
	if err := httpPost(server, "/api/v0/enrollments", body, &out); err != nil {
		return err
	}
	if out.Producer == nil {
		return errors.New("enroll-producer: server returned no producer record")
	}
	fmt.Println("WARNING: --unverified path used; producer did NOT prove key possession")
	printEnrolled(out.Producer)
	return nil
}

func printEnrolled(p *storage.Producer) {
	mode := "classical"
	if len(p.QuantumSignature) > 0 {
		mode = "hybrid"
	}
	expiry := "never"
	if p.ExpiresAt > 0 {
		expiry = time.Unix(0, p.ExpiresAt).UTC().Format(time.RFC3339)
	}
	consent := "operator-only"
	if p.HasChallengeResponse() {
		consent = "operator + producer (proof of possession)"
	}
	fmt.Printf("enrolled: %s\n", p.ID)
	fmt.Printf("  mode          : %s\n", mode)
	fmt.Printf("  scope         : %s\n", p.Scope)
	fmt.Printf("  operator_epoch: %d\n", p.OperatorEpoch)
	fmt.Printf("  expires       : %s\n", expiry)
	fmt.Printf("  consent       : %s\n", consent)
	fmt.Printf("  signature     : %s\n", base64.StdEncoding.EncodeToString(p.Signature)[:24]+"...")
}

// cmdRevokeProducer revokes a producer and records the reason.
func cmdRevokeProducer(args []string) error {
	fs, server := newFlagSet("revoke-producer")
	id := fs.String("id", "", "producer ID to revoke")
	reason := fs.String("reason", "", "human-readable reason (recorded in the admin audit log)")
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("revoke-producer: --id is required")
	}
	body := api.RevokeProducerRequest{ID: *id, Reason: *reason}
	var out map[string]any
	if err := httpPost(*server, "/api/v0/producers/revoke", body, &out); err != nil {
		return err
	}
	fmt.Printf("revoked: %s (reason: %s)\n", *id, *reason)
	return nil
}

func cmdWitnessAdd(args []string) error {
	fs, server := newFlagSet("witness-add")
	id := fs.String("id", "", "witness ID (must match the value in witness-server config)")
	url := fs.String("url", "", "witness base URL, e.g. http://localhost:9090")
	desc := fs.String("desc", "", "human description")
	_ = fs.Parse(args)
	if *id == "" || *url == "" {
		return errors.New("witness-add: --id and --url are required")
	}
	// Fetch the witness's public key from its identity endpoint.
	var ident struct {
		ID               string `json:"id"`
		PublicKey        []byte `json:"public_key"`
		QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	}
	if err := httpGet(*url, "/witness/v0/pubkey", &ident); err != nil {
		return fmt.Errorf("fetch witness identity: %w", err)
	}
	if ident.ID != *id {
		return fmt.Errorf("witness at %s identifies as %q, not %q", *url, ident.ID, *id)
	}
	body := api.RegisterWitnessRequest{Witness: &storage.Witness{
		ID:               *id,
		URL:              *url,
		PublicKey:        ident.PublicKey,
		QuantumPublicKey: ident.QuantumPublicKey,
		Description:      *desc,
	}}
	var out storage.Witness
	if err := httpPost(*server, "/api/v0/witnesses", body, &out); err != nil {
		return err
	}
	fmt.Printf("witness added: %s (pubkey=%s, url=%s)\n",
		out.ID, base64.StdEncoding.EncodeToString(out.PublicKey)[:16], out.URL)

	// Also tell the witness to watch this operator.
	var pk api.PubKeyResponse
	if err := httpGet(*server, "/api/v0/pubkey", &pk); err != nil {
		return fmt.Errorf("get operator pubkey: %w", err)
	}
	addReq := map[string]map[string]interface{}{
		"operator": {
			"origin":          pk.Origin,
			"root_public_key": pk.RootPublicKey,
			"description":     fmt.Sprintf("registered by stele CLI"),
		},
	}
	if err := httpPost(*url, "/witness/v0/operators", addReq, nil); err != nil {
		return fmt.Errorf("teach witness about this operator: %w", err)
	}
	fmt.Printf("witness %s is now watching operator %s\n", out.ID, pk.Origin)
	return nil
}

// cmdWitnessPeerAdd registers a peer with a witness server. The peer's
// public key is fetched from the peer's own /pubkey endpoint so the
// caller doesn't have to look it up manually.
func cmdWitnessPeerAdd(args []string) error {
	fs := flag.NewFlagSet("witness-peer-add", flag.ExitOnError)
	on := fs.String("on", "", "witness to add the peer to, e.g. http://localhost:9090")
	peerURL := fs.String("peer", "", "URL of the peer witness, e.g. http://localhost:9091")
	desc := fs.String("desc", "", "description")
	_ = fs.Parse(args)
	if *on == "" || *peerURL == "" {
		return errors.New("witness-peer-add: --on and --peer are required")
	}
	// Fetch the peer's identity.
	var ident struct {
		ID        string `json:"id"`
		PublicKey []byte `json:"public_key"`
		KeyID     string `json:"key_id"`
	}
	if err := httpGet(*peerURL, "/witness/v0/pubkey", &ident); err != nil {
		return fmt.Errorf("fetch peer identity from %s: %w", *peerURL, err)
	}
	body := map[string]any{
		"peer": map[string]any{
			"id":          ident.ID,
			"url":         *peerURL,
			"public_key":  ident.PublicKey,
			"description": *desc,
		},
	}
	var resp map[string]any
	if err := httpPost(*on, "/witness/v0/peers", body, &resp); err != nil {
		return err
	}
	fmt.Printf("peer %s (%s) registered with witness %s\n", ident.ID, *peerURL, *on)
	return nil
}

// cmdWitnessForks lists current fork evidence held by a witness.
func cmdWitnessForks(args []string) error {
	fs := flag.NewFlagSet("witness-forks", flag.ExitOnError)
	on := fs.String("on", "", "witness URL, e.g. http://localhost:9090")
	_ = fs.Parse(args)
	if *on == "" {
		return errors.New("witness-forks: --on is required")
	}
	var forks []*struct {
		Origin     string                 `json:"origin"`
		Size       uint64                 `json:"size"`
		DetectedAt int64                  `json:"detected_at"`
		TheirPeerID string                `json:"their_peer_id"`
		OurCheckpoint   map[string]any    `json:"our_checkpoint"`
		TheirCheckpoint map[string]any    `json:"their_checkpoint"`
	}
	if err := httpGet(*on, "/witness/v0/forks", &forks); err != nil {
		return err
	}
	if len(forks) == 0 {
		fmt.Println("(no forks detected)")
		return nil
	}
	for _, f := range forks {
		fmt.Printf("FORK: %s size=%d detected_at=%s peer=%s\n",
			f.Origin, f.Size, time.Unix(0, f.DetectedAt).UTC().Format(time.RFC3339), f.TheirPeerID)
		fmt.Printf("  our root  : %v\n", f.OurCheckpoint["root_hash"])
		fmt.Printf("  their root: %v\n", f.TheirCheckpoint["root_hash"])
	}
	return nil
}

// cmdCosignerInit generates a fresh member keypair into a directory.
// Run this on each cosigner's host before starting stele-cosigner.
func cmdCosignerInit(args []string) error {
	fs := flag.NewFlagSet("cosigner-init", flag.ExitOnError)
	dir := fs.String("dir", "", "data directory for the cosigner")
	id := fs.String("id", "", "member ID (must match the group entry)")
	_ = fs.Parse(args)
	if *dir == "" || *id == "" {
		return errors.New("cosigner-init: --dir and --id are required")
	}
	c, err := threshold.NewCosigner(*id, *dir, nil)
	if err != nil {
		return err
	}
	fmt.Printf("cosigner key generated\n  dir       : %s\n  id        : %s\n  pubkey    : %s\n  key_id    : %s\n",
		*dir, c.ID(), base64.StdEncoding.EncodeToString(c.PublicKey()), c.KeyID())
	return nil
}

// cmdGroupInit assembles a group.json from a list of cosigner identity
// URLs + a threshold. Run AFTER each cosigner is running.
func cmdGroupInit(args []string) error {
	fs := flag.NewFlagSet("group-init", flag.ExitOnError)
	origin := fs.String("origin", "", "operator origin (must match steled --origin)")
	thresholdN := fs.Uint("threshold", 0, "minimum signatures required")
	cosigners := fs.String("cosigners", "", "comma-separated cosigner URLs, e.g. http://localhost:9101,http://localhost:9102")
	out := fs.String("out", "group.json", "path to write the group descriptor")
	_ = fs.Parse(args)
	if *origin == "" || *thresholdN == 0 || *cosigners == "" {
		return errors.New("group-init: --origin, --threshold, --cosigners required")
	}
	urls := strings.Split(*cosigners, ",")
	g := &threshold.Group{
		Version:   1,
		Origin:    *origin,
		Threshold: uint32(*thresholdN),
		CreatedAt: time.Now().UnixNano(),
	}
	for _, u := range urls {
		u = strings.TrimSpace(u)
		var ident threshold.IdentityResponse
		if err := httpGet(u, "/cosigner/v0/identity", &ident); err != nil {
			return fmt.Errorf("fetch identity from %s: %w", u, err)
		}
		g.Members = append(g.Members, &threshold.Member{
			ID:               ident.ID,
			PublicKey:        ident.PublicKey,
			QuantumPublicKey: ident.QuantumPublicKey,
			Endpoint:         u,
		})
	}
	if err := g.Validate(); err != nil {
		return err
	}
	body, err := g.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		return err
	}
	fmt.Printf("group written: %s\n  origin    : %s\n  threshold : %d / %d\n  digest    : %s\n",
		*out, g.Origin, g.Threshold, len(g.Members), g.DigestHex())
	return nil
}

// cmdGroupShow fetches and pretty-prints the operator's active group.
func cmdGroupShow(args []string) error {
	fs, server := newFlagSet("group-show")
	_ = fs.Parse(args)
	var resp api.ThresholdGroupResponse
	if err := httpGet(*server, "/api/v0/threshold-group", &resp); err != nil {
		return err
	}
	if resp.Group == nil {
		fmt.Println("(operator is in single-sig mode; no threshold group active)")
		return nil
	}
	body, _ := json.MarshalIndent(resp.Group, "", "  ")
	fmt.Println(string(body))
	fmt.Printf("\ndigest: %s\n", resp.Group.DigestHex())
	return nil
}

// cmdDNSRecord prints the TXT record content an operator should
// publish under `_stele.<their-domain>` so new auditors can fetch the
// trust anchor via DNSSEC instead of a manual out-of-band exchange.
//
// Why this matters. Today, new auditors are told the operator's root
// public key over Slack / docs / email. Any of those channels can be
// social-engineered. With DNSSEC, the operator's domain owner's
// signing key vouches for the TXT record, and the DNSSEC PKI vouches
// for the domain owner. New auditors who know your domain name can
// fetch and validate the anchor with `dig +dnssec`.
func cmdDNSRecord(args []string) error {
	fs, server := newFlagSet("dns-record")
	domain := fs.String("domain", "", "your operator domain, e.g. example.com (the record goes under _stele.<domain>)")
	_ = fs.Parse(args)
	if *domain == "" {
		return errors.New("dns-record: --domain is required")
	}
	var pk api.PubKeyResponse
	if err := httpGet(*server, "/api/v0/pubkey", &pk); err != nil {
		return err
	}
	// Use the trustdns FormatTXT helper so emit + fetch stay in sync.
	rec := &trustdns.Record{
		RootPublicKey: pk.RootPublicKey,
	}
	fmt.Printf("# Publish this TXT record under _stele.%s\n", *domain)
	fmt.Printf("# After it's signed with DNSSEC, new auditors can fetch + verify with:\n")
	fmt.Printf("#   stele dnssec-fetch --origin %s\n", *domain)
	fmt.Println("#")
	fmt.Printf("# stele dnssec-fetch demands the AD bit on the DNS response; a\n")
	fmt.Printf("# non-DNSSEC-validating resolver fails the check.\n")
	fmt.Println()
	fmt.Printf("_stele.%s. IN TXT \"%s\"\n", *domain, trustdns.FormatTXT(rec))
	return nil
}

// cmdDNSSECFetch resolves _stele.<origin> with DNSSEC validation and
// prints the operator's root public key on stdout. Fails non-zero if
// DNSSEC validation fails (the AD bit is missing) or the TXT record
// is malformed.
//
// Trust path: the auditor trusts the recursive resolver (default
// 1.1.1.1:53) → the resolver validates the DNSSEC chain from the
// global root KSK → the auditor accepts the resolved root pubkey.
// This replaces the brittle "I was told the pubkey over Slack"
// first-mile.
func cmdDNSSECFetch(args []string) error {
	fs := flag.NewFlagSet("dnssec-fetch", flag.ExitOnError)
	origin := fs.String("origin", "", "operator origin / DNS domain (e.g. example.com)")
	resolver := fs.String("resolver", "1.1.1.1:53", "DNS resolver address (must do DNSSEC validation)")
	timeout := fs.Duration("timeout", 5*time.Second, "DNS query timeout")
	_ = fs.Parse(args)
	if *origin == "" {
		return errors.New("dnssec-fetch: --origin is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rec, err := trustdns.Fetch(ctx, trustdns.Config{
		Resolver: *resolver,
		Timeout:  *timeout,
	}, *origin)
	if err != nil {
		return err
	}
	fmt.Println("==== STELE TRUST ANCHOR — DNSSEC-VALIDATED ====")
	fmt.Printf("origin       : %s\n", rec.Origin)
	if rec.Version != "" {
		fmt.Printf("version      : %s\n", rec.Version)
	}
	fmt.Printf("root_pubkey  : %s\n", base64.StdEncoding.EncodeToString(rec.RootPublicKey))
	if len(rec.RootQuantumPublicKey) > 0 {
		fmt.Printf("root_qpubkey : %s\n", base64.StdEncoding.EncodeToString(rec.RootQuantumPublicKey))
	}
	if len(rec.ChainDigest) > 0 {
		fmt.Printf("chain_digest : %x\n", rec.ChainDigest)
	}
	if len(rec.Witnesses) > 0 {
		fmt.Printf("witnesses    : %d trusted witness keys\n", len(rec.Witnesses))
	}
	fmt.Println()
	fmt.Println("Pass --root <base64> to `stele audit` using the value above.")
	return nil
}

func cmdCAInit(args []string) error {
	fs := flag.NewFlagSet("ca-init", flag.ExitOnError)
	outCert := fs.String("out-cert", "", "path to write CA cert (PEM)")
	outKey := fs.String("out-key", "", "path to write CA private key (PEM, 0o600)")
	org := fs.String("org", "", "organization name (e.g. \"example.com\")")
	_ = fs.Parse(args)
	if *outCert == "" || *outKey == "" || *org == "" {
		return errors.New("ca-init: --out-cert, --out-key, --org are required")
	}
	ca, err := tlsutil.GenerateCA(*org)
	if err != nil {
		return err
	}
	if err := ca.WriteCA(*outCert, *outKey); err != nil {
		return err
	}
	fmt.Printf("CA generated\n  cert : %s\n  key  : %s\n  CN   : %s\n", *outCert, *outKey, ca.Cert.Subject.CommonName)
	return nil
}

func cmdCAIssueServer(args []string) error {
	fs := flag.NewFlagSet("ca-issue-server", flag.ExitOnError)
	caCert := fs.String("ca-cert", "", "path to CA cert")
	caKey := fs.String("ca-key", "", "path to CA key")
	cn := fs.String("cn", "stele-operator", "Common Name for the server cert")
	host := fs.String("host", "", "comma-separated DNS names and IPs the cert is valid for")
	outCert := fs.String("out-cert", "", "path to write server cert (PEM)")
	outKey := fs.String("out-key", "", "path to write server key (PEM, 0o600)")
	lifetime := fs.Duration("lifetime", tlsutil.DefaultLeafLifetime, "cert validity")
	_ = fs.Parse(args)
	if *caCert == "" || *caKey == "" || *outCert == "" || *outKey == "" || *host == "" {
		return errors.New("ca-issue-server: --ca-cert, --ca-key, --host, --out-cert, --out-key are required")
	}
	ca, err := tlsutil.LoadCA(*caCert, *caKey)
	if err != nil {
		return err
	}
	hosts := strings.Split(*host, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}
	certPEM, keyPEM, err := ca.IssueServerCert(*cn, hosts, *lifetime)
	if err != nil {
		return err
	}
	if err := tlsutil.WriteCertAndKey(*outCert, certPEM, *outKey, keyPEM); err != nil {
		return err
	}
	fmt.Printf("server cert issued\n  cert  : %s\n  key   : %s\n  hosts : %s\n", *outCert, *outKey, strings.Join(hosts, ","))
	return nil
}

func cmdCAIssueProducer(args []string) error {
	fs := flag.NewFlagSet("ca-issue-producer", flag.ExitOnError)
	caCert := fs.String("ca-cert", "", "path to CA cert")
	caKey := fs.String("ca-key", "", "path to CA key")
	id := fs.String("id", "", "producer ID (becomes the cert Common Name)")
	outCert := fs.String("out-cert", "", "path to write client cert (PEM)")
	outKey := fs.String("out-key", "", "path to write client key (PEM, 0o600)")
	lifetime := fs.Duration("lifetime", tlsutil.DefaultLeafLifetime, "cert validity")
	_ = fs.Parse(args)
	if *caCert == "" || *caKey == "" || *id == "" || *outCert == "" || *outKey == "" {
		return errors.New("ca-issue-producer: --ca-cert, --ca-key, --id, --out-cert, --out-key are required")
	}
	ca, err := tlsutil.LoadCA(*caCert, *caKey)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := ca.IssueClientCert(*id, *lifetime)
	if err != nil {
		return err
	}
	if err := tlsutil.WriteCertAndKey(*outCert, certPEM, *outKey, keyPEM); err != nil {
		return err
	}
	fmt.Printf("producer client cert issued\n  cert : %s\n  key  : %s\n  id   : %s\n", *outCert, *outKey, *id)
	return nil
}

func cmdWitnessList(args []string) error {
	fs, server := newFlagSet("witness-list")
	_ = fs.Parse(args)
	var resp api.ListWitnessesResponse
	if err := httpGet(*server, "/api/v0/witnesses", &resp); err != nil {
		return err
	}
	if len(resp.Witnesses) == 0 {
		fmt.Println("(no witnesses registered)")
		return nil
	}
	for _, w := range resp.Witnesses {
		fmt.Printf("- %s\n  url    : %s\n  pubkey : %s\n  desc   : %s\n",
			w.ID, w.URL, base64.StdEncoding.EncodeToString(w.PublicKey), w.Description)
	}
	return nil
}

func cmdProducerList(args []string) error {
	fs, server := newFlagSet("producer-list")
	_ = fs.Parse(args)
	var resp api.ListProducersResponse
	if err := httpGet(*server, "/api/v0/producers", &resp); err != nil {
		return err
	}
	if len(resp.Producers) == 0 {
		fmt.Println("(no producers registered)")
		return nil
	}
	for _, p := range resp.Producers {
		marker := ""
		if p.Revoked {
			marker = " [REVOKED]"
		}
		fmt.Printf("- %s%s\n  pubkey : %s\n  type   : %s\n  desc   : %s\n",
			p.ID, marker, base64.StdEncoding.EncodeToString(p.PublicKey),
			p.AttestationType, p.Description)
	}
	return nil
}

func cmdGet(args []string) error {
	fs, server := newFlagSet("get")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("get: requires <index>")
	}
	idx, err := strconv.ParseUint(fs.Arg(0), 10, 64)
	if err != nil {
		return err
	}
	var resp api.EntryResponse
	if err := httpGet(*server, fmt.Sprintf("/api/v0/entries/%d", idx), &resp); err != nil {
		return err
	}
	pretty, _ := json.MarshalIndent(resp.Entry, "", "  ")
	fmt.Println(string(pretty))
	return nil
}

func cmdSize(args []string) error {
	fs, server := newFlagSet("size")
	_ = fs.Parse(args)
	var resp api.SizeResponse
	if err := httpGet(*server, "/api/v0/size", &resp); err != nil {
		return err
	}
	fmt.Printf("size: %d\nroot: %s\nhead: %s\n",
		resp.Size, hex.EncodeToString(resp.RootHash), hex.EncodeToString(resp.HeadHash))
	return nil
}

func cmdCheckpoint(args []string) error {
	fs, server := newFlagSet("checkpoint")
	_ = fs.Parse(args)
	var resp api.CheckpointResponse
	if err := httpGet(*server, "/api/v0/checkpoint", &resp); err != nil {
		return err
	}
	pretty, _ := json.MarshalIndent(resp.Checkpoint, "", "  ")
	fmt.Println(string(pretty))
	return nil
}

func cmdMintCheckpoint(args []string) error {
	fs, server := newFlagSet("mint-checkpoint")
	_ = fs.Parse(args)
	var resp api.CheckpointResponse
	if err := httpPost(*server, "/api/v0/checkpoint", nil, &resp); err != nil {
		return err
	}
	fmt.Printf("checkpoint signed: size=%d root=%s\n",
		resp.Checkpoint.Size, hex.EncodeToString(resp.Checkpoint.RootHash))
	return nil
}

func cmdAnchor(args []string) error {
	fs, server := newFlagSet("anchor")
	_ = fs.Parse(args)
	var resp api.AnchorResponse
	if err := httpPost(*server, "/api/v0/anchor", nil, &resp); err != nil {
		return err
	}
	for name, rec := range resp.Records {
		fmt.Printf("anchored to %s: %s (record_hash=%s)\n", name, rec.SinkRef, rec.RecordHash)
	}
	if len(resp.Records) == 0 {
		fmt.Println("no sinks configured")
	}
	return nil
}

func cmdPubkey(args []string) error {
	fs, server := newFlagSet("pubkey")
	_ = fs.Parse(args)
	var resp api.PubKeyResponse
	if err := httpGet(*server, "/api/v0/pubkey", &resp); err != nil {
		return err
	}
	fmt.Printf("origin       : %s\nroot_pubkey  : %s\nactive_epoch : %d\nactive_keyid : %s\n",
		resp.Origin, hex.EncodeToString(resp.RootPublicKey),
		resp.ActiveEpoch, resp.ActiveKeyID)
	return nil
}

func cmdKeyChain(args []string) error {
	fs, server := newFlagSet("keychain")
	_ = fs.Parse(args)
	var resp api.KeyChainResponse
	if err := httpGet(*server, "/api/v0/keychain", &resp); err != nil {
		return err
	}
	pretty, _ := json.MarshalIndent(resp.Chain, "", "  ")
	fmt.Println(string(pretty))
	return nil
}

func cmdRotate(args []string) error {
	fs, server := newFlagSet("rotate")
	_ = fs.Parse(args)
	var resp api.KeyChainResponse
	if err := httpPost(*server, "/api/v0/rotate", nil, &resp); err != nil {
		return err
	}
	fmt.Printf("rotated to epoch %d (active_key=%s)\n",
		resp.Chain.ActiveEpoch(), base64.StdEncoding.EncodeToString(resp.Chain.ActivePublicKey()))
	return nil
}

// buildVerifier pulls everything needed to verify operator-signed
// artefacts: origin, root public key, the rotation chain, and (if the
// operator is in threshold mode) the active group descriptor.
func buildVerifier(server string) (*verify.Verifier, error) {
	var pk api.PubKeyResponse
	if err := httpGet(server, "/api/v0/pubkey", &pk); err != nil {
		return nil, err
	}
	var kc api.KeyChainResponse
	if err := httpGet(server, "/api/v0/keychain", &kc); err != nil {
		return nil, err
	}
	v := &verify.Verifier{
		Origin:        pk.Origin,
		RootPublicKey: ed25519.PublicKey(pk.RootPublicKey),
		Chain:         kc.Chain,
	}
	if err := v.Chain.VerifyChain(v.RootPublicKey); err != nil {
		return nil, fmt.Errorf("rotation chain from server is invalid: %w", err)
	}
	// Best-effort: fetch the threshold group. Older operators (or
	// single-sig deployments) return Group=nil; that's fine.
	var tg api.ThresholdGroupResponse
	if err := httpGet(server, "/api/v0/threshold-group", &tg); err == nil && tg.Group != nil {
		if err := tg.Group.Validate(); err != nil {
			return nil, fmt.Errorf("operator returned invalid threshold group: %w", err)
		}
		v.ThresholdGroup = tg.Group
	}
	return v, nil
}

func cmdVerifyInclusion(args []string) error {
	fs, server := newFlagSet("verify-inclusion")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("verify-inclusion: requires <index>")
	}
	idx, err := strconv.ParseUint(fs.Arg(0), 10, 64)
	if err != nil {
		return err
	}
	verifier, err := buildVerifier(*server)
	if err != nil {
		return err
	}
	var cpResp api.CheckpointResponse
	if err := httpGet(*server, "/api/v0/checkpoint", &cpResp); err != nil {
		return err
	}
	if err := verifier.Checkpoint(cpResp.Checkpoint); err != nil {
		return fmt.Errorf("checkpoint signature: %w", err)
	}
	var prfResp api.InclusionProofResponse
	if err := httpGet(*server, fmt.Sprintf("/api/v0/proof/inclusion?index=%d", idx), &prfResp); err != nil {
		return err
	}
	// Fetch the entry itself.
	var entryResp api.EntryResponse
	if err := httpGet(*server, fmt.Sprintf("/api/v0/entries/%d", idx), &entryResp); err != nil {
		return err
	}
	if err := verifier.Inclusion(entryResp.Entry, prfResp.TreeSize, prfResp.Proof, prfResp.RootHash); err != nil {
		return fmt.Errorf("inclusion: %w", err)
	}
	// Cross-check that the proof's root matches the checkpoint's root.
	if !bytes.Equal(prfResp.RootHash, cpResp.Checkpoint.RootHash) {
		return errors.New("proof root does not match checkpoint root (server inconsistency)")
	}
	fmt.Printf("OK: entry %d included in tree of size %d under signed root\n", idx, prfResp.TreeSize)
	fmt.Printf("  leaf_hash : %s\n", hex.EncodeToString(entryResp.Entry.LeafHash))
	fmt.Printf("  root      : %s\n", hex.EncodeToString(prfResp.RootHash))
	fmt.Printf("  proof len : %d hashes\n", len(prfResp.Proof))
	return nil
}

func cmdVerifyConsistency(args []string) error {
	fs, server := newFlagSet("verify-consistency")
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		return errors.New("verify-consistency: requires <old-size> <new-size>")
	}
	oldSize, err := strconv.ParseUint(fs.Arg(0), 10, 64)
	if err != nil {
		return err
	}
	newSize, err := strconv.ParseUint(fs.Arg(1), 10, 64)
	if err != nil {
		return err
	}
	verifier, err := buildVerifier(*server)
	if err != nil {
		return err
	}
	var resp api.ConsistencyProofResponse
	if err := httpGet(*server, fmt.Sprintf("/api/v0/proof/consistency?old=%d&new=%d", oldSize, newSize), &resp); err != nil {
		return err
	}
	if resp.OldRoot == nil {
		return errors.New("server did not have a stored old root at that size; cannot verify")
	}
	if err := verifier.Consistency(oldSize, resp.OldRoot, newSize, resp.NewRoot, resp.Proof); err != nil {
		return err
	}
	fmt.Printf("OK: tree of size %d is a prefix of tree of size %d\n", oldSize, newSize)
	return nil
}

// cmdAudit fetches every entry, verifies the hash chain, verifies the
// latest checkpoint signature, verifies the inclusion proof for the last
// entry, and walks any stored anchor history.
//
// This is the heavy artillery: in a real deployment, a CI job runs this
// against a target steled nightly and screams if it ever fails.
func cmdAudit(args []string) error {
	fs, server := newFlagSet("audit")
	pdfOut := fs.String("pdf", "", "if set, write a structured PDF audit report to this path")
	jsonOut := fs.String("json", "", "if set, write the machine-readable audit report to this path")
	sampleN := fs.Int("sample-n", 10, "number of entries to fetch + inclusion-verify as evidence (0 disables)")
	rootB64 := fs.String("root", "", "base64 trust-anchor pubkey from out-of-band (DNSSEC / paper / mirror). Improves PDF's compliance grade.")
	rootSource := fs.String("root-source", "", "where --root came from: paper | dnssec | ca-bundle | self-fetched")
	_ = fs.Parse(args)

	// 1. Origin + trust anchor + rotation chain.
	verifier, err := buildVerifier(*server)
	if err != nil {
		return err
	}
	fmt.Printf("[1/5] origin = %s, root_key = %s, active_epoch = %d (%d certs in chain)\n",
		verifier.Origin, hex.EncodeToString(verifier.RootPublicKey)[:16],
		verifier.Chain.ActiveEpoch(), len(verifier.Chain.Certs))

	// 2. Latest checkpoint signature.
	var cp api.CheckpointResponse
	if err := httpGet(*server, "/api/v0/checkpoint", &cp); err != nil {
		return fmt.Errorf("get checkpoint: %w", err)
	}
	if err := verifier.Checkpoint(cp.Checkpoint); err != nil {
		return fmt.Errorf("checkpoint signature INVALID: %w", err)
	}
	fmt.Printf("[2/5] checkpoint signature OK (size=%d, time=%s)\n",
		cp.Checkpoint.Size, time.Unix(0, cp.Checkpoint.TimeNanos).UTC().Format(time.RFC3339))

	// 3. Walk every entry in chunks and verify the hash chain.
	size := cp.Checkpoint.Size
	const chunk uint64 = 256
	entries := make([]*logentry.Entry, 0, size)
	for from := uint64(0); from < size; from += chunk {
		to := from + chunk
		if to > size {
			to = size
		}
		var r api.EntriesResponse
		if err := httpGet(*server, fmt.Sprintf("/api/v0/entries?from=%d&to=%d", from, to), &r); err != nil {
			return fmt.Errorf("get entries [%d,%d): %w", from, to, err)
		}
		entries = append(entries, r.Entries...)
	}
	if uint64(len(entries)) != size {
		return fmt.Errorf("got %d entries but checkpoint covers %d", len(entries), size)
	}
	if size == 0 {
		fmt.Println("[3/5] hash chain: empty log, nothing to check")
	} else {
		if err := verifier.EntryChain(entries); err != nil {
			return fmt.Errorf("hash chain INVALID: %w", err)
		}
		fmt.Printf("[3/5] hash chain OK (%d entries, last entry_hash=%s)\n",
			len(entries), hex.EncodeToString(entries[len(entries)-1].EntryHash))
		if !bytes.Equal(entries[len(entries)-1].EntryHash, cp.Checkpoint.HeadHash) {
			return errors.New("last entry hash does not match checkpoint head_hash")
		}
	}

	// 4. Verify the inclusion proof of the most recent entry against the
	//    signed root, as a spot check that the Merkle structure matches.
	if size > 0 {
		var prf api.InclusionProofResponse
		if err := httpGet(*server, fmt.Sprintf("/api/v0/proof/inclusion?index=%d", size-1), &prf); err != nil {
			return err
		}
		if err := verifier.Inclusion(entries[len(entries)-1], prf.TreeSize, prf.Proof, prf.RootHash); err != nil {
			return fmt.Errorf("inclusion proof INVALID: %w", err)
		}
		if !bytes.Equal(prf.RootHash, cp.Checkpoint.RootHash) {
			return errors.New("proof root mismatch with checkpoint root")
		}
		fmt.Printf("[4/5] Merkle inclusion of entry %d OK (root=%s)\n",
			size-1, hex.EncodeToString(prf.RootHash))
	} else {
		fmt.Println("[4/5] Merkle inclusion: skipped (empty log)")
	}

	// 5. Print summary.
	fmt.Printf("[5/5] audit complete: log of %d entries, signed by epoch %d under root_key %s\n",
		size, verifier.Chain.ActiveEpoch(), hex.EncodeToString(verifier.RootPublicKey)[:16])

	// 6. Optionally emit a structured Report (JSON and/or PDF).
	// The interactive output above is the human walkthrough; this
	// is the file deliverable a compliance team can archive.
	if *pdfOut != "" || *jsonOut != "" {
		cfg := audit.Config{
			OperatorURL:       *server,
			TrustAnchorSource: *rootSource,
			SampleN:           *sampleN,
		}
		if *rootB64 != "" {
			pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(*rootB64))
			if err != nil || len(pk) != ed25519.PublicKeySize {
				return fmt.Errorf("audit: --root must be base64 of a 32-byte Ed25519 pubkey: %w", err)
			}
			cfg.RootPublicKey = ed25519.PublicKey(pk)
			if cfg.TrustAnchorSource == "" {
				cfg.TrustAnchorSource = "supplied"
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		report, err := audit.Run(ctx, cfg)
		if err != nil {
			return fmt.Errorf("audit report: %w", err)
		}
		if *jsonOut != "" {
			body, _ := json.MarshalIndent(report, "", "  ")
			if err := os.WriteFile(*jsonOut, append(body, '\n'), 0o600); err != nil {
				return fmt.Errorf("write json: %w", err)
			}
			fmt.Printf("      json report written to %s\n", *jsonOut)
		}
		if *pdfOut != "" {
			body, err := auditpdf.Render(report)
			if err != nil {
				return fmt.Errorf("render pdf: %w", err)
			}
			if err := os.WriteFile(*pdfOut, body, 0o600); err != nil {
				return fmt.Errorf("write pdf: %w", err)
			}
			fmt.Printf("      PDF report written to %s (%d bytes, status=%s)\n",
				*pdfOut, len(body), report.Status)
		}
	}
	return nil
}

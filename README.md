# Go TLS Engineering Guide

A practical reference for building, operating, and debugging TLS-enabled Go
services and clients.

This guide covers the Go standard library first. It separates local development
from production deployment, explains the trust model behind certificate
validation, and provides runnable starting points for HTTPS and raw TLS over
TCP. It also documents operational concerns that are easy to miss in small
examples: timeouts, graceful shutdown, certificate rotation, SNI, mutual TLS,
HTTP/2, and compatibility across Go releases.

The examples target currently supported Go toolchains. Version-specific
behavior is called out rather than hidden behind a single claim of
"compatibility". Unless a section says otherwise, examples use only the Go
standard library.

The code is deliberately annotated where the reason is not obvious from the
syntax: trust boundaries, timeout placement, concurrency, failure recovery,
and protocol edge cases. Comments explain *why* a choice exists and what it
protects against; they do not merely translate each statement into English.
The reference section separates maintained tools, specialist tools, and
historical or experimental projects so that a link is not mistaken for an
endorsement.

> **Verification status**
>
> This document is a technical guide, not a claim that every command and code
> sample has been executed on every operating system and Go release. Validate
> examples in your target environment before production use. A recommended
> verification matrix is provided near the end of this document.

## Contents

1. [TLS fundamentals and design choices](#tls-fundamentals-and-design-choices)
2. [Go TLS defaults and version compatibility](#go-tls-defaults-and-version-compatibility)
3. [Certificates for development](#certificates-for-development)
4. [Certificate chains and trust stores](#certificate-chains-and-trust-stores)
5. [HTTPS server](#https-server)
6. [Raw TLS over TCP](#raw-tls-over-tcp)
7. [TLS client](#tls-client)
8. [Mutual TLS](#mutual-tls)
9. [SNI and multiple certificates](#sni-and-multiple-certificates)
10. [Reverse proxies and load balancers](#reverse-proxies-and-load-balancers)
11. [Certificate rotation and lifecycle](#certificate-rotation-and-lifecycle)
12. [Troubleshooting](#troubleshooting)
13. [Operational security checklist](#operational-security-checklist)
14. [Testing and verification](#testing-and-verification)
15. [Production certificate management](#production-certificate-management)
16. [Tools and further reading](#tools-and-further-reading)
17. [Legacy and specialist references](#legacy-and-specialist-references)

---

## TLS fundamentals and design choices

TLS provides three properties when configured and used correctly:

- **Confidentiality**: application data is encrypted in transit.
- **Integrity**: modifications to protected records are detected.
- **Peer authentication**: certificates and the configured trust model establish
  which endpoint the connection is talking to.

Encryption alone is not authentication. A client that sets
`InsecureSkipVerify: true` without supplying an alternative verification
mechanism can establish an encrypted connection to an attacker.

The right implementation depends on the protocol and deployment topology:

| Use case | Go API | Main concerns |
|---|---|---|
| HTTPS server | `net/http` + `crypto/tls` | Timeouts, shutdown, certificate lifecycle, HTTP/2 |
| HTTPS client | `http.Client` + `http.Transport` | Root CAs, hostname verification, request deadlines |
| Custom protocol over TCP | `tls.Listener`, `tls.Conn` | Framing, deadlines, concurrency, cancellation |
| Service-to-service identity | Mutual TLS | Client CA, client identity, authorization |
| Several hostnames on one listener | SNI and `GetCertificate` | Certificate selection and hostname coverage |
| Public certificates | ACME client or edge proxy | Renewal, challenge validation, deployment topology |

Prefer `net/http` for HTTP. Use `crypto/tls` directly only when the application
protocol is not HTTP or when a lower-level TLS feature is genuinely required.

### TLS is not an application protocol

A successful TLS handshake does not prove that the application protocol is
correct. The client and server must still agree on what happens after the
handshake: HTTP, a framed TCP protocol, a database protocol, or something else.

Likewise, sending plaintext HTTP to a TLS listener, or TLS records to a plaintext
listener, produces confusing symptoms. Confirm the scheme, port, and protocol
before debugging certificates.

---

## Go TLS defaults and version compatibility

The Go standard library has changed substantially since many early TLS
examples were written. In most applications, the safest configuration is
deliberately small: set a minimum protocol version when policy requires it and
leave cipher-suite and key-exchange selection to the Go implementation.

### Practical defaults

| Older configuration or assumption | Current guidance |
|---|---|
| Set a hand-picked cipher-suite list for every server | Leave `CipherSuites` unset unless a specific interoperability or compliance requirement justifies a reviewed override. TLS 1.3 cipher suites are not configurable through this field. |
| Set `PreferServerCipherSuites` | This field is legacy and has no effect. |
| Hard-code `CurvePreferences` | Leave it unset unless a specific peer or middlebox requires a narrowly scoped compatibility adjustment. |
| Use the certificate Common Name for hostname matching | Issue certificates with DNS or IP Subject Alternative Names (SANs). Go hostname verification does not use the legacy Common Name fallback. |
| Enable TLS 1.0 or TLS 1.1 for compatibility | Modern Go defaults favor TLS 1.2 or newer. Do not lower the minimum globally to accommodate an obsolete peer. |
| Disable certificate verification to get a connection working | Configure the correct trust roots and expected server name. |
| Use `net.Dial` and then assemble TLS manually | Use `tls.Dialer.DialContext` or `http.Client` with request contexts. |
| Assume key exchange is always classical | Recent Go releases enable hybrid post-quantum key exchanges by default. Test older middleboxes and TLS inspection appliances. |

An explicit minimum version makes the policy visible:

```go
config := &tls.Config{
	// ✓ Keep the minimum at TLS 1.2 unless a documented peer requires older
	// protocol support. Go negotiates the strongest mutually supported version.
	MinVersion: tls.VersionTLS12,
}
```

Use TLS 1.3 only when the supported client population and any required
intermediaries have been tested:

```go
config := &tls.Config{
	// ⚠ This rejects TLS 1.2 clients outright; test every client and TLS
	// terminator on the path before making TLS 1.3 a hard requirement.
	MinVersion: tls.VersionTLS13,
}
```

Do not set `MaxVersion` without a concrete reason. Restricting the maximum
version can prevent clients from using a newer protocol version supported by
both endpoints.

### Relevant Go release changes

The following is a selective compatibility summary, not a substitute for
reading the release notes for the exact toolchain deployed.

| Go release | Relevant TLS / X.509 change |
|---|---|
| Go 1.17 and later | Hostname verification relies on SANs; the legacy Common Name fallback is not a viable certificate issuance strategy. |
| Go 1.22 | TLS 1.0/1.1 server defaults and legacy RSA key-exchange defaults changed; compatibility behavior was controlled by `GODEBUG` settings. |
| Go 1.23 | 3DES was removed from the default cipher-suite set; related compatibility behavior was controlled by `GODEBUG`. |
| Go 1.24 | X25519MLKEM768 hybrid post-quantum key exchange became enabled by default. |
| Go 1.25 | SHA-1 signature algorithms were disabled in TLS 1.2 by default, following RFC 9155. Encrypted Client Hello server configuration and key-exchange observability also evolved. |
| Go 1.26 | Additional hybrid post-quantum key exchanges became enabled by default. |
| Go 1.27 | Compatibility `GODEBUG` switches for several legacy TLS behaviors were removed; ML-DSA TLS 1.3 signatures and additional post-quantum key-exchange support were added. |

As of 15 November 2026, the latest Go 1.27 patch release is Go 1.27.4
(released 10 November 2026). It includes security fixes, including updates to
`net/http` and other standard-library components. Use the latest patch release
available for the deployed release line, not merely the initial release tag.

Primary references:

- [Go release history](https://go.dev/doc/devel/release)
- [Go 1.22 release notes](https://go.dev/doc/go1.22)
- [Go 1.23 release notes](https://go.dev/doc/go1.23)
- [Go 1.24 release notes](https://go.dev/doc/go1.24)
- [Go 1.25 release notes](https://go.dev/doc/go1.25)
- [Go 1.26 release notes](https://go.dev/doc/go1.26)
- [Go 1.27 release notes](https://go.dev/doc/go1.27)
- [Go and GODEBUG compatibility policy](https://go.dev/doc/godebug)
- [`crypto/tls` package documentation](https://pkg.go.dev/crypto/tls)
- [`crypto/x509` package documentation](https://pkg.go.dev/crypto/x509)

### Cipher suites and HTTP/2

Avoid copying cipher-suite lists from old SSL Labs recipes into a modern Go
server. Such lists can remove suites required by HTTP/2 or exclude suites that
the Go implementation would otherwise select safely.

TLS 1.3 cipher suites are not controlled by `tls.Config.CipherSuites`. For TLS
1.2, the field controls the enabled suite set, but the order supplied by the
application is not a general-purpose server-preference mechanism.

If a compliance profile requires a custom list, document the exact requirement,
test HTTP/2 negotiation, and verify behavior against the Go version in use.
Do not disable HTTP/2 by setting `TLSNextProto` to an empty map merely to work
around a cipher-suite configuration problem.

---

## Certificates for development

Development certificates should be easy to create and should exercise the
same hostname-verification behavior as production certificates.

A certificate is valid for the names in its SAN extension. The Common Name is
not a substitute for SANs.

### Option A: mkcert

[`mkcert`](https://github.com/FiloSottile/mkcert) creates a local certificate
authority, installs its root certificate in supported local trust stores, and
issues certificates for development names.

```sh
mkcert -install
mkcert localhost 127.0.0.1 ::1
```

The command creates a certificate and private key in the current directory.
Use the filenames printed by the command.

Keep the local CA private key private. Do not copy it into a repository, image,
or shared development environment. Installing a local CA grants its holder
significant trust on that machine.

### Option B: OpenSSL self-signed leaf for a local test

A self-signed leaf is useful for a small isolated test. The client must
explicitly trust that certificate. It is not a general public certificate
issuance workflow.

The following requires OpenSSL 1.1.1 or newer for `-addext`:

```sh
#!/usr/bin/env bash
set -euo pipefail

# ── Inputs ──────────────────────────────────────────────────────────────
# Use a short lifetime: this is a disposable local leaf, not a production CA.
out="${1:-.}"
days="${DAYS:-30}"

mkdir -p "$out"

# ── Generate a self-signed leaf ─────────────────────────────────────────
# `-x509` emits a certificate directly (no separate CA signing step).
# SANs are mandatory for Go hostname verification; CN=localhost is cosmetic.
# CA:FALSE and serverAuth make the intended end-entity role explicit.
openssl req -x509 -new -nodes \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -sha256 -days "$days" \
  -keyout "$out/server.key" \
  -out "$out/server.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"

# ✓ The private key is readable only by the current user on Unix-like systems.
chmod 600 "$out/server.key"

# Inspect what was actually issued; do not infer extensions from the command.
openssl x509 -in "$out/server.crt" \
  -noout -subject -issuer -dates -ext subjectAltName
```

This certificate is self-signed. Trust it only in the test client that needs it.
For several local services, a local CA with separate leaf certificates is
usually a better model.

### Option C: local CA and a signed server certificate

Use a CA when multiple development services need certificates issued under one
trust anchor. The CA private key must be protected separately from service
private keys.

The commands below use Bash process substitution:

```sh
# ── 1. Create a local root CA ───────────────────────────────────────────
# CA:TRUE and keyCertSign identify this as a signing CA, not a server leaf.
# pathlen:0 prevents this root from delegating to another intermediate CA.
# ⚠ Keep ca.key offline or in a protected secret store; anyone holding it can
# issue certificates trusted by every client that trusts ca.crt.
openssl req -x509 -new -nodes \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -sha256 -days 825 \
  -keyout ca.key \
  -out ca.crt \
  -subj "/CN=Development Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# ── 2. Generate a distinct server key and a PKCS#10 request ──────────────
# The CA key is never copied to the service host; only the leaf key is deployed.
openssl req -new -nodes \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key \
  -out server.csr \
  -subj "/CN=localhost"

# ── 3. Sign a leaf with the CA ──────────────────────────────────────────
# The SAN identifies the endpoint; serverAuth limits the intended EKU.
# A real CA should also enforce issuance policy, serial uniqueness and audit logs.
openssl x509 -req \
  -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days 90 \
  -out server.crt \
  -extfile <(printf '%s\n' \
    "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth")

# ── 4. Inspect the issued certificate before distributing it ─────────────
openssl x509 -in server.crt -noout -text
```

The server presents `server.crt` and its private key. Clients trust `ca.crt`.
Do not configure the CA certificate itself as the server's leaf certificate.

For production PKI, use a maintained CA workflow and a documented renewal
process rather than treating these development commands as a full PKI system.

### Key algorithm considerations

- ECDSA P-256 is widely interoperable and efficient for general TLS use.
- RSA remains useful where compatibility requirements demand it. Use a
  currently acceptable key size and signature policy.
- Ed25519 support depends on the peer ecosystem and policy requirements. Test
  the actual clients and intermediaries before selecting it.
- Do not choose a key algorithm solely to maximize a scanner score. Select it
  based on interoperability, security policy, and operational support.

### File formats

Extensions are conventions, not reliable content-type declarations.

| Extension | Typical content |
|---|---|
| `.pem` | PEM-encoded key, certificate, CSR, or certificate chain |
| `.crt` / `.cer` | Certificate in PEM or DER encoding |
| `.key` | Private key, usually PEM-encoded |
| `.csr` | Certificate signing request |
| `.der` | Binary DER-encoded ASN.1 object |

Go's `tls.LoadX509KeyPair` expects PEM-encoded certificate and private-key
files. A certificate-chain file should contain the leaf certificate first,
followed by intermediate certificates in chain order.

---

## Certificate chains and trust stores

A client validates more than whether a certificate file exists. It verifies
that the presented chain leads to a trusted root, that the certificate is
valid for the name being dialed, that validity periods and constraints are
satisfied, and that the certificate is appropriate for the connection.

### Trusting a private CA

Do not use `InsecureSkipVerify` to solve an unknown-authority error. Add the
intended trust anchor to the client's root pool:

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// loadRoots builds a private trust pool from a PEM bundle.
// ⚠ This intentionally replaces the system roots; use SystemCertPool and
// AppendCertsFromPEM instead when both public and private roots are required.
func loadRoots(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}

	roots := x509.NewCertPool()
	// AppendCertsFromPEM reports false when it cannot parse any certificates.
	// A malformed/empty bundle must fail closed rather than silently trust none.
	if ok := roots.AppendCertsFromPEM(pem); !ok {
		return nil, fmt.Errorf("%q contains no PEM certificates", caFile)
	}

	return roots, nil
}

// clientTLSConfig keeps normal hostname and chain verification enabled.
// ServerName is normally inferred from the dial target; override it only when
// the network address and the certificate's DNS identity intentionally differ.
func clientTLSConfig(caFile string) (*tls.Config, error) {
	roots, err := loadRoots(caFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots, // Non-nil means verify against this pool, not system roots.
	}, nil
}
```

When `RootCAs` is non-nil, it defines the roots used for server verification.
If the client should trust both the system roots and an additional private CA,
start with `x509.SystemCertPool()` and append the private CA:

```go
// ── Extend, rather than replace, the platform trust store ───────────────
// This preserves public Web PKI roots while adding one private trust anchor.
roots, err := x509.SystemCertPool()
if err != nil {
	return nil, fmt.Errorf("load system roots: %w", err)
}
if roots == nil {
	// Some platforms can return (nil, nil); create an empty pool in that case.
	roots = x509.NewCertPool()
}
if ok := roots.AppendCertsFromPEM(privateCAPEM); !ok {
	return nil, errors.New("private CA bundle contains no certificates")
}
```

The name used by the client must match a SAN on the server certificate:

- `localhost` requires a DNS SAN such as `DNS:localhost`.
- `127.0.0.1` requires an IP SAN such as `IP:127.0.0.1`.
- An IP address is not interchangeable with a DNS name.

If the network address differs from the certificate identity, set
`tls.Config.ServerName` to the expected DNS identity. This preserves
certificate verification; it does not disable it.

### System trust stores differ

Go uses the platform trust store according to the behavior of the Go release and
operating system. Browsers may use a separate trust store or additional
enterprise policy. A certificate trusted by `curl` is not proof that Firefox,
Chrome, a container, or a Go process trusts the same root.

When diagnosing a trust problem, identify the exact client and trust store.
Avoid hard-coding operating-system CA bundle paths into portable Go programs.

---

## HTTPS server

For HTTP services, use `net/http` and configure the `http.Server` explicitly.
A minimal `ListenAndServeTLS` call is fine for a short demonstration, but it
does not show the operational controls a public service needs.

The example below demonstrates:

- An explicit TLS minimum version.
- Bounded HTTP timeouts.
- Graceful shutdown.
- A certificate callback backed by an atomic pointer.
- Certificate reload without replacing the server object.

It is an example service, not a complete application framework. Add request
limits, authentication, authorization, observability, and application-specific
resource controls as appropriate. This version uses the Go 1.22+ method-aware
`ServeMux` patterns and Go 1.21+ `log/slog` / context APIs. The `SIGHUP` reload
trigger is Unix-specific; use a platform-appropriate control path on Windows.

```go
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

// ── Certificate publication ────────────────────────────────────────────
// A TLS handshake reads one immutable *Certificate. Atomic publication means
// it sees either the complete old key pair or the complete new key pair—never
// a partially reloaded certificate/key combination.
type certificateStore struct {
	certFile string
	keyFile  string
	current  atomic.Pointer[tls.Certificate]
}

func newCertificateStore(certFile, keyFile string) (*certificateStore, error) {
	store := &certificateStore{
		certFile: certFile,
		keyFile:  keyFile,
	}
	if err := store.Reload(); err != nil {
		return nil, err
	}
	return store, nil
}

// Reload parses and checks the key pair before publishing it.
// ✓ On failure, current remains untouched: the last known-good cert keeps
// serving new handshakes while the operator fixes the files and retries.
func (s *certificateStore) Reload() error {
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS key pair: %w", err)
	}

	s.current.Store(&cert) // One atomic swap; readers need no separate lock.
	return nil
}

// GetCertificate runs during certificate selection in the TLS handshake.
// Do not do slow filesystem/network I/O here; Reload performs I/O ahead of time.
func (s *certificateStore) GetCertificate(
	_ *tls.ClientHelloInfo,
) (*tls.Certificate, error) {
	cert := s.current.Load()
	if cert == nil {
		return nil, errors.New("no TLS certificate is loaded")
	}
	return cert, nil
}

func newHTTPServer(addr string, store *certificateStore) *http.Server {
	mux := http.NewServeMux()

	// The health endpoint emits no body; use a cheap status-only response.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// r.TLS is nil when TLS terminates at an upstream proxy and the
		// application receives plain HTTP. Never infer external scheme from
		// untrusted X-Forwarded-* headers here.
		protocol := "unknown"
		if r.TLS != nil {
			protocol = tls.VersionName(r.TLS.Version)
		}
		_, _ = io.WriteString(w, "secure channel: "+protocol+"\n")
	})

	return &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: store.GetCertificate, // Certificate is selected per handshake.
		},
		// ── Bound resource occupancy ───────────────────────────────────
		// Header timeout is separate from full-body read and response-write bounds.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

func run(
	ctx context.Context,
	server *http.Server,
	store *certificateStore,
	logger *slog.Logger,
) error {
	// The reload worker has its own child context so it can be stopped and
	// joined even when ListenAndServeTLS returns before the parent is cancelled.
	runCtx, stopReload := context.WithCancel(ctx)
	defer stopReload()

	// SIGHUP is Unix-specific; replace this trigger with an admin API or
	// orchestrator signal on platforms where SIGHUP is unavailable.
	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGHUP)
	defer signal.Stop(reloadSignals)

	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		for {
			select {
			case <-runCtx.Done():
				return
			case <-reloadSignals:
				// Failed reloads are logged but do not replace the active cert.
				if err := store.Reload(); err != nil {
					logger.Error(
						"certificate reload failed; previous certificate remains active",
						"error", err,
					)
					continue
				}
				logger.Info("TLS certificate reloaded")
			}
		}
	}()

	serveErr := make(chan error, 1)
	go func() {
		// Empty paths are intentional: TLSConfig.GetCertificate supplies the
		// already-loaded certificate. Non-empty paths would trigger file loading.
		serveErr <- server.ListenAndServeTLS("", "")
	}()

	logger.Info("HTTPS listener started", "address", server.Addr)

	select {
	case err := <-serveErr:
		stopReload()
		<-reloadDone
		return err
	case <-ctx.Done():
	}

	// Graceful shutdown gets a bounded window independent of the cancelled
	// request context. If it expires, Close below forcefully interrupts sockets.
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		// Shutdown does not guarantee termination of hijacked connections
		// (for example, WebSockets); those need their own lifecycle handling.
		_ = server.Close()
		stopReload()
		<-reloadDone
		return fmt.Errorf("graceful HTTP shutdown: %w", err)
	}

	err := <-serveErr
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	<-reloadDone
	return nil
}

func main() {
	addr := flag.String("addr", ":8443", "HTTPS listen address")
	certFile := flag.String("cert", "server.crt", "PEM certificate chain")
	keyFile := flag.String("key", "server.key", "PEM private key")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	store, err := newCertificateStore(*certFile, *keyFile)
	if err != nil {
		logger.Error("certificate initialization failed", "error", err)
		os.Exit(1)
	}

	// First SIGINT/SIGTERM cancels ctx and starts graceful shutdown.
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	server := newHTTPServer(*addr, store)
	if err := run(ctx, server, store, logger); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTPS server stopped", "error", err)
		os.Exit(1)
	}
}
```

Run the service:

```sh
go run .
```

In a separate terminal, using a certificate trusted by the client:

```sh
curl --cacert ca.crt https://localhost:8443/
```

If the server is using a self-signed leaf rather than a CA-issued leaf, pass
that self-signed certificate as the trust anchor for this test.

### HTTP server timeout semantics

Timeouts are not interchangeable:

- `ReadHeaderTimeout` limits the time allowed to read request headers.
- `ReadTimeout` bounds reading the entire request, including the body.
- `WriteTimeout` bounds response writes. It can be unsuitable for long-lived
  streaming responses unless the design accounts for it.
- `IdleTimeout` bounds keep-alive idle time between requests.
- `MaxHeaderBytes` limits the request-header size.

Tune these values for the workload. A timeout that is too large permits slow
clients to occupy resources; one that is too small breaks legitimate uploads,
streaming, or high-latency clients.

`http.Server.Shutdown` stops accepting new connections and waits for active
requests until its context expires. It does not forcibly terminate every
long-lived hijacked connection. Handle WebSockets and other hijacked
connections separately.

### HSTS

HTTP Strict Transport Security (HSTS) is a browser policy, not a TLS
configuration option. Enable it only when the hostname is reliably served over
HTTPS. Be especially careful with `includeSubDomains`: every covered subdomain
must support HTTPS.

Do not enable a long-lived HSTS policy on `localhost` or a development domain
that may later need plaintext access.

---

## Raw TLS over TCP

Use raw TLS for a custom protocol, not as a replacement for HTTP. A TCP
protocol still needs framing, message-size limits, deadlines, backpressure,
and a shutdown model.

### Server

This minimal line-oriented example accepts TLS connections and echoes a
response. It bounds line size and read/write duration. A production server
should also impose a connection limit and application-level authorization.
This example uses `context.AfterFunc` (Go 1.21+) to interrupt blocked I/O on
shutdown.

```go
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	// A fresh read/write deadline is applied for each line. A slow or stuck
	// frame is bounded, but this is not a total connection lifetime limit.
	connectionIOTimeout = 30 * time.Second
	// Scanner rejects longer lines with ErrTooLong instead of growing without
	// bound on attacker-controlled input.
	maximumLineSize = 4096
)

// ── One accepted connection: bounded, line-framed request/response I/O ──
// TLS protects the byte stream; framing and message-size limits belong to the
// application protocol layered on top.
func handleConnection(
	ctx context.Context,
	conn net.Conn,
	logger *log.Logger,
) {
	defer conn.Close()

	// A blocked Scan/Write otherwise has no way to observe ctx cancellation.
	// Moving the deadline into the past interrupts pending network I/O.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stop()

	// ScanLines provides the simple protocol framing used in this example.
	// It is not suitable for arbitrary binary payloads; use an explicit length
	// prefix or another framed protocol for those.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 512), maximumLineSize)

	for {
		// Set both read and write deadlines before the next frame. This also
		// bounds the first TLS handshake because the first Scan triggers it.
		if err := conn.SetDeadline(time.Now().Add(connectionIOTimeout)); err != nil {
			return
		}

		if !scanner.Scan() {
			// EOF is a normal peer close. ErrTooLong and I/O errors are not;
			// log them unless shutdown is already in progress.
			if err := scanner.Err(); err != nil &&
				!errors.Is(err, io.EOF) &&
				ctx.Err() == nil {
				logger.Printf("read from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}

		if _, err := io.WriteString(conn, "ack: "+scanner.Text()+"\n"); err != nil {
			logger.Printf("write to %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

// ── Listener lifecycle and connection ownership ───────────────────────
// The accept loop owns registration; each handler owns and closes its conn.
func serve(
	ctx context.Context,
	listener net.Listener,
	logger *log.Logger,
) error {
	// The listener watcher unblocks Accept when ctx is cancelled. The wait
	// group ensures handlers have exited before serve reports shutdown complete.
	var handlers sync.WaitGroup
	watcherDone := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-watcherDone:
		}
	}()
	defer close(watcherDone)

	for {
		conn, err := listener.Accept()
		if err != nil {
			// net.Listener.Close is the normal way to interrupt Accept during
			// shutdown; other accept errors are returned to the caller.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				handlers.Wait()
				return nil
			}
			handlers.Wait()
			return err
		}

		// Register before starting the goroutine so Wait cannot miss a handler.
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			handleConnection(ctx, conn, logger)
		}()
	}
}

func main() {
	addr := flag.String("addr", ":9443", "TLS listen address")
	certFile := flag.String("cert", "server.crt", "PEM certificate chain")
	keyFile := flag.String("key", "server.key", "PEM private key")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)

	// Load and validate the pair before opening the listener; fail closed if
	// either PEM file is missing, malformed, or does not match the other.
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		logger.Fatalf("load TLS key pair: %v", err)
	}

	listener, err := tls.Listen("tcp", *addr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The server certificate chain must include intermediates after the leaf.
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	logger.Printf("listening on %s", listener.Addr())
	if err := serve(ctx, listener, logger); err != nil {
		logger.Fatalf("server stopped: %v", err)
	}
}
```

### Client

Use `tls.Dialer.DialContext` when a raw TLS connection needs context-aware
connection establishment. Keep certificate verification enabled.

```go
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// ── Context-aware dial, peer verification, and bounded protocol I/O ───
// nil RootCAs tells crypto/tls to use the platform system roots.
// Supplying caFile instead creates an isolated private pool; merge with
// SystemCertPool first if the client must trust public and private PKI.
func loadRootPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil // nil uses the system root pool
	}

	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}

	roots := x509.NewCertPool()
	// Fail on an empty or unparseable bundle rather than silently proceeding.
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %q", caFile)
	}
	return roots, nil
}

func main() {
	addr := flag.String("addr", "localhost:9443", "TLS endpoint host:port")
	caFile := flag.String("ca", "", "optional PEM CA bundle")
	message := flag.String("message", "ping", "line to send")
	timeout := flag.Duration("timeout", 5*time.Second, "connection and I/O timeout")
	flag.Parse()

	roots, err := loadRootPool(*caFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots, // nil means system roots; non-nil is this explicit pool.
			// ServerName is inferred from addr. Set it explicitly only when the
			// certificate identity intentionally differs from the dial address.
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "TLS dial:", err)
		os.Exit(1)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		// DialContext covers connect + handshake. This deadline also bounds
		// subsequent protocol I/O, which is not automatically tied to ctx.
		_ = conn.SetDeadline(deadline)
	}

	if _, err := io.WriteString(conn, *message+"\n"); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}

	// The sample protocol is newline-delimited; production protocols must
	// define framing, maximum message size and how partial frames are handled.
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}

	fmt.Print(reply)
}
```

The dial address determines the default server name used for verification.
When dialing an IP address, the server certificate needs a matching IP SAN.
When the certificate is issued for a DNS name, connect using that DNS name or
set `ServerName` to the expected DNS identity while retaining verification.

---

## TLS client

For HTTP, use `http.Client`; do not create a raw TLS connection for ordinary
HTTP requests.

```go
// ── HTTP client trust configuration ────────────────────────────────────
// Clone/extend the system roots: private-only RootCAs would break public HTTPS.
roots, err := x509.SystemCertPool()
if err != nil {
	return fmt.Errorf("load system trust roots: %w", err)
}
if roots == nil {
	roots = x509.NewCertPool()
}

privateCA, err := os.ReadFile("internal-ca.pem")
if err != nil {
	return fmt.Errorf("read private CA: %w", err)
}
if ok := roots.AppendCertsFromPEM(privateCA); !ok {
	return errors.New("private CA bundle contains no certificates")
}

transport := &http.Transport{
	TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	},
	// For a production client, clone http.DefaultTransport when appropriate
	// so proxy, dial, HTTP/2 and connection-pool defaults remain intentional.
}

client := &http.Client{
	Transport: transport,
	// This is an end-to-end request bound, including reading the response body.
	// Choose a different policy for streaming, SSE or long-polling endpoints.
	Timeout: 10 * time.Second,
}
defer transport.CloseIdleConnections()

req, err := http.NewRequestWithContext(
	ctx,
	http.MethodGet,
	"https://service.internal.example/health",
	nil,
)
if err != nil {
	return err
}

resp, err := client.Do(req)
if err != nil {
	return err
}
// Always close the body. Read or drain it when connection reuse matters and
// the response is small enough to consume safely.
defer resp.Body.Close()
```

Production clients should generally reuse `http.Client` and its transport.
Creating a new transport for every request discards connection pooling and
increases handshake overhead.

Use request contexts for cancellation and deadlines. `http.Client.Timeout`
bounds the entire request, including response-body reading; choose it
deliberately for streaming or long-polling workloads.

Never share a mutable `tls.Config` and change its fields after handing it to
the TLS stack. Treat configuration as immutable after use.

---

## Mutual TLS

Mutual TLS (mTLS) authenticates the client to the server using a client
certificate. It does not replace application authorization. A successfully
authenticated certificate still needs to map to an identity and permissions
in the application.

A server that requires a client certificate should configure a client CA pool
and an explicit client-authentication policy:

```go
// ── Server side: authenticate clients against a dedicated issuing CA ────
// ⚠ A verified client certificate authenticates a peer; it does not grant
// application permissions. Map its identity to an explicit authorization policy.
// This CA pool is for client certificates; it is not the server's RootCAs pool.
clientCAPEM, err := os.ReadFile("client-ca.pem")
if err != nil {
	return err
}

clientCAs := x509.NewCertPool()
if ok := clientCAs.AppendCertsFromPEM(clientCAPEM); !ok {
	return errors.New("client CA bundle contains no certificates")
}

serverTLS := &tls.Config{
	MinVersion: tls.VersionTLS12,
	// Require a cert and verify its chain against ClientCAs during the handshake.
	// Application code must still map the verified identity to authorization.
	ClientAuth: tls.RequireAndVerifyClientCert,
	ClientCAs:  clientCAs,
}
```

Common `ClientAuth` policies include:

- `NoClientCert`: do not request a client certificate.
- `RequestClientCert`: request one, but do not require it.
- `RequireAnyClientCert`: require a certificate, without verifying it against
  `ClientCAs`.
- `VerifyClientCertIfGiven`: verify a supplied certificate, but do not require
  one.
- `RequireAndVerifyClientCert`: require and verify a client certificate.

For most private service-to-service deployments that require mTLS,
`RequireAndVerifyClientCert` is the intended policy. Confirm the certificate
identity and authorization model before accepting requests.

A client presents its certificate using `Certificates`:

```go
// ── Client side: present a separate client identity ─────────────────────
// The client private key must be protected like any other credential.
clientCert, err := tls.LoadX509KeyPair("client.crt", "client.key")
if err != nil {
	return err
}

clientTLS := &tls.Config{
	MinVersion: tls.VersionTLS12,
	RootCAs:    serverRoots, // Trust used to authenticate the server.
	// Identity sent to the server if it requests/requires client authentication.
	Certificates: []tls.Certificate{clientCert},
}
```

Do not confuse server trust (`RootCAs`) with client identity (`Certificates`).
They solve different sides of the handshake.

---

## SNI and multiple certificates

Server Name Indication (SNI) allows a TLS client to indicate the hostname it
intends to reach during the handshake. A server can use that name to select the
appropriate certificate before the HTTP request is available.

For a small fixed set of names:

```go
// ── SNI-based certificate selection ────────────────────────────────────
// The map is immutable after the server starts. If certificates are rotated,
// publish a new immutable map atomically (or protect mutations with a mutex).
certificates := map[string]*tls.Certificate{
	"api.example.com": apiCertificate,
	"www.example.com": webCertificate,
}

config := &tls.Config{
	MinVersion: tls.VersionTLS12,
	// SNI arrives in ClientHello, before HTTP Host headers exist.
	GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// ⚠ This example intentionally requires an exact SNI match. An empty SNI,
		// an unknown host, or a wildcard name is not silently mapped to a cert.
		cert := certificates[strings.ToLower(hello.ServerName)]
		if cert == nil {
			return nil, fmt.Errorf("no certificate for SNI name %q", hello.ServerName)
		}
		return cert, nil
	},
}
```

A production implementation should define how it handles:

- Unknown or absent SNI.
- Wildcard names and exact-name precedence.
- Certificate reload and concurrent access.
- Multiple certificates for the same name.
- Expired or not-yet-valid certificates.
- Whether a default certificate is appropriate.

Do not select a certificate based on untrusted HTTP headers. Certificate
selection occurs during the TLS handshake, before HTTP headers exist.

---

## Reverse proxies and load balancers

A common source of confusion is assuming that every backend server must
present the public certificate.

There are several valid topologies:

1. **TLS termination at the edge**: the load balancer presents the public
   certificate. Traffic from the balancer to the Go service may use plaintext
   on a protected network or a separate TLS connection.
2. **TLS re-encryption**: the balancer terminates the client connection and
   establishes a new TLS connection to the backend. The backend certificate
   must be valid for the identity the balancer verifies.
3. **TLS passthrough**: the balancer forwards the TLS stream without
   terminating it. The backend presents the certificate to the client.

These topologies have different trust boundaries. Document which component
authenticates which peer and where encryption is required.

For TLS re-encryption, configure backend certificate verification on the
load balancer. Do not treat private network placement as a replacement for
peer authentication.

If TLS terminates at a proxy, the Go application may receive plaintext HTTP.
Only trust forwarded headers such as `Forwarded` or `X-Forwarded-Proto` from
known proxy addresses. An arbitrary client can forge these headers.

When several public hostnames share one listener, SNI is the normal mechanism
for selecting a certificate. The client does not need to know which backend
instance the load balancer selected.

---

## Certificate rotation and lifecycle

Certificates expire. Rotation should be routine, observable, and tested before
the first production expiry event.

A robust lifecycle includes:

1. Obtain or renew a certificate before expiry.
2. Validate the certificate chain, SANs, key match, and validity period.
3. Deploy the new certificate and key as an atomic or otherwise consistent
   pair.
4. Reload the certificate without exposing a partially written key pair.
5. Verify that new connections receive the new certificate.
6. Keep a rollback path and alert on failed renewal or reload.

The HTTPS example uses `atomic.Pointer[tls.Certificate]` so a successful
reload publishes a complete certificate object. If loading fails, the
previous certificate remains active.

Do not overwrite certificate and key files independently while a process may
read them. Use a temporary directory or versioned files, validate the pair,
then switch a symlink or deployment reference atomically where supported.

On Unix-like systems, `SIGHUP` is a common reload trigger. It is not portable
to Windows. A control endpoint, file watcher, or orchestrator-driven restart
may be more appropriate for cross-platform services.

Monitor at least:

- Certificate expiry horizon.
- Last successful renewal time.
- Last successful reload time.
- Certificate issuer and SAN coverage.
- Handshake failures and unknown-authority errors.
- The identity and version of the certificate currently served.

---

## Troubleshooting

Start by identifying which stage failed:

1. TCP connection establishment.
2. TLS handshake and protocol negotiation.
3. Certificate-chain and hostname verification.
4. Application-protocol exchange.
5. HTTP or application authorization.

The text of a TLS error is evidence, not a complete diagnosis. Capture the
client command, destination hostname, destination port, Go version, certificate
chain, and proxy topology before changing security settings.

| Symptom | Likely cause | Diagnostic direction |
|---|---|---|
| `x509: certificate is valid for X, not Y` | The dialed name does not match a DNS or IP SAN. | Inspect SANs and the actual dial target. |
| `x509: certificate relies on legacy Common Name field` | The certificate has no suitable SAN. | Reissue it with DNS and/or IP SANs. |
| `x509: certificate signed by unknown authority` | The client does not trust the issuing CA or the server omitted an intermediate. | Inspect the presented chain and configure the correct trust anchor. |
| `tls: failed to verify certificate` | Chain, hostname, time validity, usage, or policy validation failed. | Inspect the nested verification error and certificate fields. |
| `tls: first record does not look like a TLS handshake` | A TLS client reached a plaintext service, or a plaintext client reached a TLS listener. | Confirm URL scheme, port, and proxy configuration. |
| Browser reports a certificate warning while `curl` works | The clients may use different trust stores or policies. | Check the browser trust store and enterprise policy. |
| `MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY` | A CA certificate was served as the leaf certificate. | Serve a CA-signed leaf with appropriate server usage. |
| `remote error: tls: unknown certificate` | The remote peer rejected a certificate, commonly in mTLS or a private-CA setup. | Determine which side requested a certificate and inspect that side's trust roots. |
| HTTP/2 server complains about a required cipher suite | A custom TLS 1.2 suite list may have excluded an HTTP/2-compatible suite. | Remove the unnecessary override and retest HTTP/2 negotiation. |
| `bad record MAC` | Records could not be authenticated; possible causes include protocol mismatch, broken TLS termination, a faulty intermediary, or corrupted/misrouted traffic. | Reproduce directly against each hop and inspect proxy/LB configuration. Do not assume the certificate is at fault. |
| Works with a DNS name but fails by IP | The certificate may have a DNS SAN but no matching IP SAN. | Use the DNS identity or issue a certificate with the required IP SAN. |

### Inspect the certificate

```sh
openssl x509 -in server.crt -noout \
  -subject -issuer -dates -ext subjectAltName \
  -ext basicConstraints -ext keyUsage -ext extendedKeyUsage
```

### Inspect the chain presented by a server

```sh
openssl s_client \
  -connect example.com:443 \
  -servername example.com \
  -showcerts \
  -verify_return_error
```

For a private CA:

```sh
openssl s_client \
  -connect service.internal.example:443 \
  -servername service.internal.example \
  -CAfile internal-ca.pem \
  -verify_return_error
```

### Inspect negotiated protocol and certificate details

```sh
curl -v https://example.com/
```

```sh
testssl.sh --fast example.com:443
```

Do not use `curl -k` or `openssl s_client` without verification flags as proof
that certificate validation works. Those commands can be useful for isolating
a handshake, but they do not establish that the trust model is correct.

### Community issues that informed this guide

The original project and Gist discussions repeatedly surfaced a small set of
problems:

- A certificate Common Name was mistaken for the hostname clients should
  verify. The durable fix is SAN issuance.
- A client needed a private CA in its trust pool; disabling verification was
  suggested as a tempting but unsafe shortcut.
- A load balancer's TLS termination point was confused with backend
  certificate selection.
- Alternative RSA and ECDSA key-generation commands wrote to the same output
  filenames, causing one key to overwrite the other.
- A custom cipher list conflicted with HTTP/2 requirements.
- A remote `unknown certificate` error was reported without enough details to
  determine which peer rejected which certificate.
- A `bad record MAC` report illustrated why protocol and intermediary
  configuration must be investigated separately from certificate validation.
- A 2024 comment proposed `io.Copy` as a workaround for short writes. The
  `io.Writer` contract requires a non-nil error when fewer bytes than requested
  are written. Follow the contract and check errors; do not add a copy loop
  without evidence that a particular writer violates its contract.

Sources:
- [Original Go TLS Gist and comments](https://gist.github.com/denji/12b3a568f092ab951456)
- [Project issue: HTTP/2 cipher-suite compatibility](https://github.com/denji/golang-tls/issues/4)
- [Project issue: certificate trust error](https://github.com/denji/golang-tls/issues/5)
- [Project issue: TLS handshake error](https://github.com/denji/golang-tls/issues/7)
- [Go issue: HTTP/2 and TLS cipher suites](https://github.com/golang/go/issues/34776)
- [`io.Writer` contract](https://pkg.go.dev/io#Writer)

---

## Operational security checklist

Use this as a review aid, not as a substitute for a threat model or a
compliance assessment.

- [ ] Use TLS 1.2 or newer unless a documented compatibility requirement says
      otherwise.
- [ ] Prefer TLS 1.3 where the client population and network path support it.
- [ ] Keep Go patched on a supported release line.
- [ ] Leave cipher-suite and key-exchange defaults intact unless an explicit
      requirement justifies an override.
- [ ] Issue certificates with correct DNS and IP SANs.
- [ ] Verify certificate chains and hostnames on clients.
- [ ] Never use `InsecureSkipVerify` as a production workaround.
- [ ] Protect private keys with restrictive filesystem permissions and secret
      management controls.
- [ ] Do not commit private keys, CA private keys, or TLS key logs.
- [ ] Use bounded request, connection, and handshake deadlines.
- [ ] Provide graceful shutdown and account for hijacked connections.
- [ ] Test certificate renewal and reload, including failure and rollback paths.
- [ ] Validate backend TLS when using proxy re-encryption.
- [ ] Trust forwarded headers only from known proxies.
- [ ] Use mTLS only with a clear identity and authorization model.
- [ ] Avoid enabling HSTS until HTTPS is stable across the covered hostname
      hierarchy.
- [ ] Do not set `tls.Config.KeyLogWriter` in production. It exports session
      secrets for debugging tools and compromises connection confidentiality.
- [ ] Test TLS inspection devices and older middleboxes before changing
      post-quantum key-exchange defaults.
- [ ] Run vulnerability scanning and update the Go toolchain in a controlled
      release process.
- [ ] Review FIPS requirements separately; FIPS mode changes the set of
      available algorithms and behavior.

### FIPS 140-3

Go provides a documented FIPS 140-3 mode and validated cryptographic module
options. Enabling a mode is not equivalent to making an application compliant.
Review the exact module, toolchain, deployment configuration, and operational
requirements:

- [Go FIPS 140-3 documentation](https://go.dev/doc/security/fips140)

---

## Testing and verification

TLS examples should be tested at more than one layer.

### Static and unit checks

For a repository containing Go packages and examples:

```sh
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
```

Run `gofmt -l .` in CI to detect formatting drift without modifying files.

Use the race detector on certificate reload, connection lifecycle, and
concurrent server tests. It does not prove protocol correctness, but it can
detect unsafe shared state.

### Compatibility matrix

A useful CI matrix includes:

- The minimum Go version the project claims to support.
- The latest patch release of the current stable Go release.
- The previous supported stable release, where practical.
- Linux, Windows, and macOS if the project claims cross-platform behavior.

Do not claim compatibility with a Go release merely because the code compiles
on a newer version. Run the test suite on the claimed toolchain.

### Integration scenarios

At minimum, test:

- A trusted certificate and matching DNS SAN.
- A trusted certificate and matching IP SAN.
- A hostname mismatch.
- An unknown CA.
- An expired certificate.
- TLS 1.1 rejected when TLS 1.2 is the minimum.
- HTTP/2 negotiation for HTTPS servers.
- mTLS with a trusted client certificate.
- mTLS rejection for an untrusted client certificate.
- Certificate rotation to a valid replacement.
- Failed rotation preserving the last known-good certificate.
- Shutdown while idle and while connections are active.
- A client timeout during connection establishment and during I/O.
- A deployment behind the actual reverse proxy or load balancer.

### Vulnerability scanning

[`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
checks Go code and dependencies against known vulnerabilities:

```sh
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Pin and manage tool versions in CI according to the repository's dependency
policy rather than relying on an unreviewed floating tool version for every
production build.

---

## Production certificate management

Manual OpenSSL commands are useful for development and controlled tests.
Public production services should normally automate issuance, renewal, and
deployment. Choose a tool by its operational role: a GUI certificate manager,
a CA/signing service, an ACME client, and a Kubernetes certificate controller
solve different problems; they are not interchangeable.

| Requirement | Tools and approaches |
|---|---|
| ACME issuance inside a Go application | [`autocert`](https://pkg.go.dev/golang.org/x/crypto/acme/autocert) |
| Certificate automation and storage | [`CertMagic`](https://github.com/caddyserver/certmagic) |
| Private ACME-compatible CA | [`step-ca`](https://github.com/smallstep/certificates) |
| Minimal local CA for tests | [`minica`](https://github.com/jsha/minica) |
| TLS terminated outside the Go process | Reverse proxy, ingress controller, or load balancer with an explicit backend trust policy |

For public ACME issuance, understand the challenge type:

- HTTP-01 requires the CA to reach the challenge endpoint over HTTP.
- DNS-01 proves control through DNS records and supports wildcard issuance.
- TLS-ALPN-01 uses a special TLS handshake on the validation port.

For services that cannot be reached publicly, DNS-01 or a private CA may be
appropriate. Protect DNS API credentials as production secrets.

Do not treat certificate issuance as the entire lifecycle. Renewal must be
followed by validation, deployment, reload, and monitoring.

---

## Tools and further reading

The list below is intentionally broad. A tool can be useful without being a
runtime dependency or a recommendation for every deployment. Status notes were
checked on 15 November 2026; upstream release cadence can change, so verify the
project's releases, security policy, and supported Go versions before adopting
it.

### Go APIs, standards and protocol references

- [`crypto/tls`](https://pkg.go.dev/crypto/tls) — Go's TLS implementation and configuration contract.
- [`crypto/x509`](https://pkg.go.dev/crypto/x509) — certificate parsing, chain verification, names, constraints and pools.
- [`net/http`](https://pkg.go.dev/net/http) — HTTPS server/client behavior, transport pooling, deadlines and shutdown.
- [`io.Writer`](https://pkg.go.dev/io#Writer) — write contract; short writes must be accompanied by a non-nil error.
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3 protocol.
- [RFC 9325 — Recommendations for Secure Use of TLS and DTLS](https://www.rfc-editor.org/rfc/rfc9325) — current operational recommendations for TLS deployments.
- [RFC 9525 — Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525) — service identity and certificate name verification.
- [RFC 5280 — PKIX Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280) — X.509 certificate and CRL profile.
- [RFC 8555 — ACME](https://www.rfc-editor.org/rfc/rfc8555) — automated certificate issuance protocol.
- [RFC 6962 — Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962) — CT architecture (supplement with current ecosystem documents).
- [RFC 9155 — Deprecating SHA-1 in TLS 1.2](https://www.rfc-editor.org/rfc/rfc9155).
- [Go release history](https://go.dev/doc/devel/release), [GODEBUG compatibility policy](https://go.dev/doc/godebug), and [Go vulnerability database](https://vuln.go.dev/).

### Certificate authoring, CA operations and PKI

| Tool | Classification and when it is useful |
|---|---|
| [XCA](https://github.com/chris2511/xca) ([downloads](https://hohnstaedt.de/xca/index.php/download)) | **Desktop X.509/PKI manager.** Manage keys, CSRs, certificates, templates, CRLs and a small CA through a GUI. Useful when a person needs to inspect or author certificate material without building a CA workflow by hand. Not an ACME automation service. The upstream download page lists XCA 2.9.0. |
| [CFSSL](https://github.com/cloudflare/cfssl) | **PKI/TLS toolkit.** CLI and HTTP API for signing, verifying, bundling and inspecting certificates. Restored from the original list; it is actively releasing (v1.7.1 was published in October 2026) and the current repository states Go 1.27+ is required to build. |
| [Smallstep `step-ca`](https://github.com/smallstep/certificates) | **Private CA service.** Useful for internal PKI, ACME-compatible issuance and managed identities. |
| [HashiCorp Vault PKI](https://developer.hashicorp.com/vault/docs/secrets/pki) | **Secrets-manager-backed CA.** Issue short-lived dynamic certificates under Vault authentication and authorization policy. |
| [`mkcert`](https://github.com/FiloSottile/mkcert) | **Local development CA.** Convenient trusted certificates for developer workstations; do not distribute its CA private key. |
| [`minica`](https://github.com/jsha/minica) | **Minimal local CA.** Useful for tests and simple local certificate chains, not a complete production PKI. |
| [OpenSSL documentation](https://docs.openssl.org/) | **Low-level certificate and key utility.** `req`, `x509`, `verify`, `s_client` and related commands are useful for controlled issuance and diagnosis. |

### ACME, renewal and deployment automation

- [`autocert`](https://pkg.go.dev/golang.org/x/crypto/acme/autocert) — ACME integration for Go HTTP services. Review its storage, challenge reachability, host policy and renewal behavior before deployment.
- [`CertMagic`](https://github.com/caddyserver/certmagic) — certificate automation library with storage, renewal and distributed coordination capabilities.
- [`lego`](https://github.com/go-acme/lego) — maintained Go ACME client/library with broad DNS-provider support; useful outside a Go application as well.
- [cert-manager](https://cert-manager.io/docs/) — Kubernetes certificate lifecycle controller; relevant when Kubernetes owns workload certificate reconciliation.
- [Let's Encrypt documentation](https://letsencrypt.org/docs/) — challenge types, rate limits and production/staging environments.

### Certificate inspection, linting and policy validation

- [`zlint`](https://github.com/zmap/zlint) — actively maintained X.509 certificate linter for RFC, CA/Browser Forum and other PKI requirements; v3.7.2 was released in September 2026. It checks certificate profile conformance, not whether a deployment's trust model is correct.
- [`certlint`](https://github.com/globalsign/certlint) — **archived** GlobalSign certificate-linting project. Retained as historical context; prefer ZLint for a maintained linter. The upstream repository is archived.
- [`openssl x509`](https://docs.openssl.org/master/man1/openssl-x509/) and [`openssl verify`](https://docs.openssl.org/master/man1/openssl-verification-options/) — inspect fields and verify chains locally.
- [`gocertifi`](https://github.com/certifi/gocertifi) — embedded Mozilla-derived root bundle for environments where Go cannot find an appropriate system bundle or a pinned CA set is a deliberate requirement. **Do not add it by default**: an embedded root set needs an explicit update and rollout policy.

### TLS endpoint scanners and protocol testing

| Tool | Best use | Status / caveat |
|---|---|---|
| [`testssl.sh`](https://testssl.sh/) | Broad TLS protocol, cipher, certificate and server-option inspection from the command line. | A useful first-pass scanner; still validate findings against the target's intended policy. |
| [SSLyze](https://github.com/nabla-c0d3/sslyze) | Scriptable TLS configuration and certificate analysis. | Use this active upstream repository; the old [`iSECPartners/sslyze`](https://github.com/iSECPartners/sslyze) repository explicitly points development to it. |
| [Qualys SSL Labs](https://www.ssllabs.com/ssltest/) | External assessment of a publicly reachable TLS endpoint. | Public service; results are a point-in-time observation, not a complete security audit. Review its terms before bulk use. |
| [`ssllabs-scan`](https://github.com/ssllabs/ssllabs-scan) | CLI client for automating the SSL Labs API. | Supplementary automation; repository activity is less frequent than the scanners above, so verify API and client compatibility before depending on it. |
| [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) | Reference profiles for supported TLS terminators such as NGINX, Apache and HAProxy. | It is not a generator for Go `tls.Config`; translate the policy rather than copying cipher lists into Go. |
| [`badssl.com`](https://badssl.com/) | Test client behavior against deliberately broken certificates and TLS configurations. | Excellent integration-test target; do not send sensitive data to test endpoints. |
| [`genkiroid/cert`](https://github.com/genkiroid/cert) | Go CLI to inspect a remote TLS certificate, SANs, issuer, validity and chain details. | Latest GitHub release shown is 1.0.0 (April 2023). It exposes a `-k`/`-skip-verify` option; do not use that option when checking the validity of a peer. |
| [`tlsfuzzer`](https://github.com/tlsfuzzer/tlsfuzzer) | TLS protocol conformance, negative testing and fuzzing. | Active project; this is a test harness, not an endpoint hardening scanner. Use in controlled test environments. |
| [Google Certificate Transparency Go](https://github.com/google/certificate-transparency-go) | CT log, monitor and ecosystem components. | Specialist Go code for CT systems; not needed for ordinary TLS client/server setup. |

### Certificate expiry and operational monitoring

- [`chexpire`](https://github.com/Evolix/chexpire) — self-hosted web application for domain and TLS-certificate expiry checks. Useful when a dashboard and notification workflow are desired; review deployment and maintenance requirements.

### Go networking and HTTP security helpers

- [`tcplisten`](https://github.com/valyala/tcplisten) — specialised `net.Listener` options such as `SO_REUSEPORT` and `TCP_DEFER_ACCEPT`. This is a performance/networking concern, not a TLS requirement. The repository has had a long release gap; benchmark and check OS-specific behavior before adding it.
- [`unrolled/secure`](https://github.com/unrolled/secure) — `net/http` middleware for host checks, HTTPS redirects and security headers. It is adjacent to TLS: it does not configure the TLS handshake or replace correct proxy trust.
- [TrustKit](https://github.com/datatheorem/TrustKit) — certificate/public-key pinning for Apple-platform client applications. **Not a Go server library.** Pinning creates an outage risk when keys rotate; use only with a documented threat model, backup pins and a recovery channel.

### Learning projects and alternative TLS implementations

These projects are useful for reading protocol code or studying implementation trade-offs. They are **not drop-in replacements** for Go's standard `crypto/tls` in production:

- [`bifurcation/mint`](https://github.com/bifurcation/mint) — explicitly a learning-oriented minimal TLS 1.3 implementation; its own description warns that software engineering and compatibility are not its primary goals.
- [`cloudflare/tls-tris`](https://github.com/cloudflare/tls-tris) — experimental `crypto/tls` fork. Its README says the API is unstable and documentation is not guaranteed. Keep for research/history, not application dependencies.
- [Mimoo's CryptoBible TLS notes](https://github.com/mimoo/cryptobible/blob/master/protocols/tls.mediawiki) — protocol-learning material; verify against the RFCs because cryptographic protocol explanations can age.

### Application security and operational reading

- [OWASP Go Secure Coding Practices](https://devguide.owasp.org/en/05-implementation/01-documentation/02-go-scp/) — broad secure Go coding guidance, beyond TLS alone.
- [Cloudflare: The complete guide to Go `net/http` timeouts](https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/) — valuable conceptual explanation of deadlines and HTTP timeout phases (published in 2016); read it alongside current [`net/http`](https://pkg.go.dev/net/http) documentation and the examples above.
- [Gophish: Building Web Servers in Go](https://getgophish.com/blog/post/2018-12-02-building-web-servers-in-go/) — a 2018 end-to-end `net/http` walkthrough covering middleware, ACME and graceful shutdown. Useful as supplementary reading; validate details against current Go docs.
- [Go security policy](https://go.dev/security) and [Go vulnerability management](https://go.dev/doc/security/vuln/) — supported release and dependency-security guidance.
- [Security Headers](https://securityheaders.com/) — HTTP response-header assessment, not a TLS scanner; useful for adjacent web hardening.
- [IndieWeb: HTTPS](https://indieweb.org/HTTPS) — supplementary deployment and adoption context, not an implementation reference.



---

## Legacy and specialist references

The original README accumulated links over many years. They are not all equally
current, and a historical link should not silently become a current security
recommendation.

| Original reference | Disposition |
|---|---|
| [Mozilla TLS Observatory](https://github.com/mozilla/tls-observatory) | **Archived on 1 December 2025.** Retained here only as historical source code; do not present it as a currently maintained Mozilla service or scanner. |
| [Mozilla CipherScan](https://github.com/mozilla/cipherscan) | Legacy wrapper around `openssl s_client`. Useful for understanding older cipher-order testing, but prefer `testssl.sh` or SSLyze for current TLS versions and workflows. |
| [GlobalSign certlint](https://github.com/globalsign/certlint) | Repository is archived; use ZLint for maintained certificate linting. |
| [Xeoncross/secureserver](https://github.com/Xeoncross/secureserver) | Older Go HTTPS-server helper with historical hardening ideas. Its original guidance predates current Go TLS defaults and it lists graceful shutdown as unfinished; do not copy its TLS configuration as a modern baseline. |
| [BraceLab “Perfect SSL Labs Score with Go”](https://blog.bracelab.com/achieving-perfect-ssl-labs-score-with-go) and [`cipherli.st`](https://cipherli.st/) | Historical cipher-suite recipes. Their fixed cipher lists and score-driven approach are not suitable as modern Go defaults; see the TLS defaults section instead. |
| [Posener HTTP/2 article](https://posener.github.io/http2/) | Historical Go HTTP/2 explanation. Use current Go `net/http` docs and the Go release notes for current behavior. |
| [CaptainCodeman ACME article](https://www.captaincodeman.com/2017/05/07/automatic-https-with-free-ssl-certificates-using-go-lets-encrypt) | 2017 walkthrough; replaced by current ACME documentation, `autocert`, CertMagic and lego references. |
| [DigitalElf certificate article](https://digitalelf.net/2016/02/creating-ssl-certificates-in-3-easy-steps/) and [2013 ECDSA certificate article](https://www.guyrutenberg.com/2013/12/28/creating-self-signed-ecdsa-ssl-certificate-using-openssl/) | Old certificate-generation walkthroughs. Kept out of the primary path because command syntax, recommended profiles and Go hostname-verification behavior have evolved; prefer current OpenSSL documentation and the SAN-based examples above. |
| [Old Echo guide](https://web.archive.org/web/20150925030955/http://echo.labstack.com/guide) | Archived framework documentation and not relevant to the standard-library TLS core. |
| [GopherAcademy: Exposing Go on the Internet](https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/) | 2016 deployment article. Useful historical context, but not normative guidance for current Go versions. |
| [`tidwall/modern-server`](https://github.com/tidwall/modern-server) | Older convenience wrapper for HTTP/2 and Let's Encrypt. Kept as historical reading, not a current baseline; prefer standard `net/http` and maintained ACME tooling. |
| [`cmrunton/tls-dashboard`](https://github.com/cmrunton/tls-dashboard) | Certificate-expiry dashboard whose repository appears to have had no commits for about a decade. Kept only as historical inspiration; do not adopt it without reviewing dependencies and security. |
| [`kaihag.com/https-and-go`](http://www.kaihag.com/https-and-go/) | Older Go HTTPS article; omitted from the primary path because current APIs and defaults have moved on. |
| [jsrsasign ECDSA sample](https://kjur.github.io/jsrsasign/sample-ecdsa.html), [OpenSSL prompt workaround](https://superuser.com/a/226229/205366), and [miscellaneous TLS Gists](https://gist.github.com/spikebike/2232102) | Removed from the core recommendations: they are narrow, non-Go, or unmaintained snippets rather than durable TLS engineering references. Retain only when investigating the specific technique. |
| [HTTP-to-HTTPS redirect Gist](https://gist.github.com/d-schmidt/587ceec34ce1334a5e60) and [certificate-fetcher Gist](https://gist.github.com/jtwaleson/1fdd77260bcb48377b6b) | Community snippets rather than maintained packages. The guide's server and certificate-lifecycle sections cover the underlying patterns with current APIs. |
| [shaaaaaaaaaaaaa](https://github.com/konklone/shaaaaaaaaaaaaa) and the 2018 oss-sec mailing-list item | Excluded from the practical tool index because they do not materially help implement or operate a modern Go TLS endpoint. |

This classification is not a judgment that the projects have no historical
value. It prevents readers from confusing protocol education, old recipes,
monitoring utilities, and production dependencies.

---

## Project maintenance

This repository is an educational reference, not a TLS implementation or a
replacement for the Go standard library.

Contributions should:

1. Prefer standard-library APIs and current Go conventions.
2. Include a reproducible example or a precise explanation of the behavior.
3. Identify the Go versions and operating systems tested.
4. Explain security and compatibility trade-offs.
5. Avoid weakening verification or protocol defaults to make a failing example
   appear to work.
6. Keep commands copy-pasteable and avoid destructive shell behavior.
7. Link to primary documentation, specifications, or the upstream issue that
   supports version-specific claims.
8. Comment security-sensitive examples at the decision points: explain trust
   roots, identity verification, deadlines, concurrency, fallback behavior,
   and cleanup. Avoid comments that only repeat the Go statement below them.
9. Mark specialist, archived, and experimental tools as such; do not silently
   promote an old link into a current recommendation.

When reporting a problem, include the Go version, operating system, exact
command, relevant TLS configuration, certificate SANs and chain, and whether a
proxy or load balancer is in the connection path. Never attach private keys.

## License

CC0-1.0. Use anything here without attribution, See [LICENSE](LICENSE).

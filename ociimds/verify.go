package ociimds

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// validRegion matches OCI region identifiers (e.g. "us-ashburn-1",
// "eu-frankfurt-1"). Restrictive on purpose: only lowercase letters,
// digits, and single hyphens. Rejecting anything else closes an SSRF
// hole in fetchRegionalRoots's URL construction, where a crafted region
// string like "evil.com/x" could otherwise repoint the fetch to an
// attacker-controlled host.
var validRegion = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// defaultRootFetchTimeout bounds a single regional-root-CA fetch when
// the caller doesn't supply their own *http.Client. 15s leaves headroom
// for slow networks without letting a stuck auth.<region>.oraclecloud.com
// endpoint hang the verifier forever.
const defaultRootFetchTimeout = 15 * time.Second

// maxRootCABodyBytes caps the size of the regional root CA response
// body we will read. Oracle's real response is on the order of a few
// KiB; 1 MiB is two orders of magnitude larger than anything
// legitimate and far below anything that would OOM a verifier. Caps
// a hostile or misconfigured endpoint returning a multi-GB body.
const maxRootCABodyBytes = 1 << 20 // 1 MiB

var (
	defaultRootFetchClientOnce sync.Once
	defaultRootFetchClient     *http.Client
)

// rootFetchHardTimeout is the upper bound applied inside the
// singleflight callback to defend against caller-supplied *http.Client
// values with Timeout == 0. It defaults to defaultRootFetchTimeout and
// is a var (rather than a const) so tests can shrink it without
// blocking for 15s. Production callers should not mutate it.
var rootFetchHardTimeout = defaultRootFetchTimeout

// newDefaultRootFetchClient returns a hardened *http.Client for the
// VerifyIdentityDocument fetch path when the caller did not supply
// one: it has an explicit 15s Timeout so a stalled Oracle endpoint
// can't hang the caller, and it blocks redirects so a
// misconfigured/hostile endpoint can't 3xx the fetch to another host.
func newDefaultRootFetchClient() *http.Client {
	defaultRootFetchClientOnce.Do(func() {
		defaultRootFetchClient = &http.Client{
			Timeout: defaultRootFetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	})
	return defaultRootFetchClient
}

// VerifyOption configures optional behavior on VerifyIdentityDocument.
type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	httpClient *http.Client
	// rootBaseURL is the full URL used to fetch the regional root CA
	// JSON response when set — fetchRegionalRoots does NOT append the
	// /v1/instancePrincipalRootCACertificates path to it. Test-only
	// hook, set via the unexported withRootBaseURL option.
	rootBaseURL string
}

// WithFetchHTTPClient injects the *http.Client used by VerifyIdentityDocument
// when fetching Oracle's regional root CA bundle. Use it to plug in a
// client with custom proxies, timeouts, or TLS roots. If not set, a
// hardened default client is used (15s timeout, redirect blocking).
func WithFetchHTTPClient(c *http.Client) VerifyOption {
	return func(o *verifyOptions) { o.httpClient = c }
}

// withRootBaseURL is a test hook that overrides the full URL used to
// fetch the regional root CA JSON response, so hermetic tests can
// serve a fake response from an arbitrary endpoint. The override is
// the complete request URL — fetchRegionalRoots does NOT append the
// /v1/instancePrincipalRootCACertificates path to it. Unexported so
// production callers can't accidentally point the fetch at an
// untrusted host.
func withRootBaseURL(u string) VerifyOption {
	return func(o *verifyOptions) { o.rootBaseURL = u }
}

// Claims holds the verified fields extracted from an OCI instance
// identity document.
type Claims struct {
	TenancyID     string    // from opc-tenant: subject attribute
	InstanceID    string    // from opc-instance: subject attribute
	CompartmentID string    // from opc-compartment: subject attribute, if present
	NotBefore     time.Time // from leaf cert.NotBefore
	NotAfter      time.Time // from leaf cert.NotAfter
}

// rootCacheKey is the composite (region, baseURLOverride) cache key.
// Using a struct instead of string concatenation means the two
// components can't collide even if baseURLOverride contains any byte
// that might appear in a region (or vice versa).
type rootCacheKey struct {
	region   string
	override string
}

// rootKeyString encodes a rootCacheKey for singleflight.Do, which
// takes a string key. NUL is forbidden in valid URLs and in our region
// regex, so it's an unambiguous separator.
func rootKeyString(k rootCacheKey) string {
	return k.region + "\x00" + k.override
}

var (
	rootCacheMu sync.Mutex
	rootCache   = map[rootCacheKey]*x509.CertPool{}
	// rootCacheGlobalGen is bumped by ClearRootCache. It invalidates
	// any in-flight fetch's pending writeback regardless of region.
	rootCacheGlobalGen uint64
	// rootCacheRegionGen[region] is bumped by ClearRegionRootCache.
	// It invalidates only in-flight fetches for that specific region,
	// so clearing one region doesn't cause in-flight fetches for
	// *other* regions to drop their results (which would turn
	// ClearRegionRootCache into an unintentional global invalidation).
	// Missing keys read as 0 (Go map zero value).
	rootCacheRegionGen = map[string]uint64{}
	rootFetchGroup     singleflight.Group // dedupes concurrent misses for the same rootCacheKey
)

// VerifyIdentityDocument validates an OCI instance identity document
// against Oracle's regional root CA bundle for the given region:
//
//  1. Parses the leaf and intermediate PEMs.
//  2. Fetches Oracle's regional root CA bundle (cached per region) from
//     https://auth.<region>.oraclecloud.com/v1/instancePrincipalRootCACertificates
//     and validates the chain: leaf <- intermediate <- oracle root.
//  3. Extracts tenancy/instance/compartment IDs from the leaf cert's
//     Subject.Names attributes.
//  4. If expectedNonce is non-nil, verifies doc.Signature is a valid
//     RSA PKCS1v15 SHA256 signature over expectedNonce using the leaf
//     cert's public key. This is the only way to prove the document
//     wasn't replayed from a captured copy.
//
// region must be an OCI region identifier the caller already knows
// out-of-band (e.g. "us-ashburn-1"). Remote verifiers typically learn
// the region from the same channel that delivered the document. The
// region is validated against a strict lowercase-alphanumeric-plus-
// hyphen regex before interpolation, so an attacker-controlled region
// string cannot redirect the fetch to another host. If you can't reach
// auth.<region>.oraclecloud.com (off-cloud verifiers, air-gapped
// environments, hermetic tests), use VerifyIdentityDocumentWithRoots
// with a pre-fetched root pool.
//
// WithFetchHTTPClient lets the caller plug in a custom *http.Client for the
// fetch (e.g. to configure proxies or custom TLS roots). Without it, a
// hardened default client with a 15s timeout and redirect blocking is
// used.
func VerifyIdentityDocument(ctx context.Context, doc *IdentityDocument, region string, expectedNonce []byte, opts ...VerifyOption) (*Claims, error) {
	if region == "" {
		return nil, fmt.Errorf("ociimds: region is required")
	}
	if !validRegion.MatchString(region) {
		return nil, fmt.Errorf("ociimds: invalid region %q: must match %s", region, validRegion.String())
	}
	o := verifyOptions{}
	for _, fn := range opts {
		fn(&o)
	}
	if o.httpClient == nil {
		o.httpClient = newDefaultRootFetchClient()
	}

	leaf, intermediate, err := parseCerts(doc)
	if err != nil {
		return nil, err
	}

	roots, err := fetchRegionalRoots(ctx, region, o.httpClient, o.rootBaseURL)
	if err != nil {
		return nil, fmt.Errorf("ociimds: fetch regional root CA: %w", err)
	}

	return verifyParsed(leaf, intermediate, roots, doc, expectedNonce)
}

// VerifyIdentityDocumentWithRoots is like VerifyIdentityDocument but
// accepts an explicit root CA pool instead of fetching one from Oracle.
// Used by tests that inject a throwaway test root, and by off-OCI
// verifiers that have pre-fetched Oracle's regional root CA bundle into
// their own trust material. roots must be non-nil — passing nil would
// fall back to the host system trust store inside x509.Verify, which
// would silently accept any publicly-trusted CA as an OCI instance
// principal signer, defeating the point of an explicit trust pool.
func VerifyIdentityDocumentWithRoots(doc *IdentityDocument, roots *x509.CertPool, expectedNonce []byte) (*Claims, error) {
	if roots == nil {
		return nil, fmt.Errorf("ociimds: roots cert pool is nil")
	}
	leaf, intermediate, err := parseCerts(doc)
	if err != nil {
		return nil, err
	}
	return verifyParsed(leaf, intermediate, roots, doc, expectedNonce)
}

func parseCerts(doc *IdentityDocument) (*x509.Certificate, *x509.Certificate, error) {
	if doc == nil {
		return nil, nil, fmt.Errorf("ociimds: identity document is nil")
	}
	leaf, err := parsePEMCert(doc.LeafCert)
	if err != nil {
		return nil, nil, fmt.Errorf("ociimds: parse leaf: %w", err)
	}
	intermediate, err := parsePEMCert(doc.Intermediate)
	if err != nil {
		return nil, nil, fmt.Errorf("ociimds: parse intermediate: %w", err)
	}
	return leaf, intermediate, nil
}

// parsePEMCert is an internal helper whose errors are always wrapped
// by parseCerts with an "ociimds: parse leaf:" / "parse intermediate:"
// prefix, so its own errors are deliberately unprefixed to avoid the
// doubled "ociimds: parse leaf: ociimds: ..." look.
func parsePEMCert(data []byte) (*x509.Certificate, error) {
	// Reject leading non-PEM content. pem.Decode silently skips any
	// bytes before the first "-----BEGIN" marker, so a crafted bundle
	// with attacker-controlled prefix bytes could otherwise be
	// accepted (polyglot input). Whitespace is tolerated because
	// real responses may start with a newline.
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		return nil, fmt.Errorf("unexpected leading content before CERTIFICATE PEM block")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("not a CERTIFICATE PEM block")
	}
	// Reject any trailing PEM content so a crafted bundle with a
	// benign-looking first block followed by an attacker-chosen second
	// block can't slip through. Trailing whitespace is tolerated.
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("unexpected trailing PEM content after CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func verifyParsed(leaf, intermediate *x509.Certificate, roots *x509.CertPool, doc *IdentityDocument, expectedNonce []byte) (*Claims, error) {
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)

	// Constrain to ClientAuth: OCI instance-principal leaf certs are
	// used by the instance to authenticate as a client when calling
	// OCI services, so ExtKeyUsageClientAuth is the correct
	// constraint. ExtKeyUsageAny would accept certs intended for
	// entirely different purposes that happen to chain to an Oracle
	// root — tightening this closes that surface.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("ociimds: verify cert chain: %w", err)
	}

	if expectedNonce != nil {
		// Treat a missing or empty signature the same way: a zero-byte
		// slice is not a valid RSA signature and would otherwise fall
		// through to rsa.VerifyPKCS1v15 with a cryptic verification
		// error rather than the clearer "no signature" path.
		if len(doc.Signature) == 0 {
			return nil, fmt.Errorf("ociimds: expectedNonce set but document has no signature")
		}
		// Preserve the nil/empty distinction: bytes.Equal(nil, []byte{})
		// returns true, so without this explicit check an
		// expectedNonce of []byte{} would silently accept a document
		// whose Nonce was never populated. The IdentityDocument
		// contract says Nonce is non-nil whenever WithNonce was used,
		// so a nil Nonce here means the instance never signed — treat
		// as mismatch.
		if doc.Nonce == nil {
			return nil, fmt.Errorf("ociimds: expectedNonce set but document has no nonce")
		}
		// Plain bytes.Equal: the nonce is chosen by the verifier and
		// shipped to the instance, so it is not a long-term secret
		// where timing leaks matter. subtle.ConstantTimeCompare would
		// also return 0 immediately on a length mismatch, so using it
		// here would be cargo-cult.
		if !bytes.Equal(doc.Nonce, expectedNonce) {
			return nil, fmt.Errorf("ociimds: signed nonce does not match expected nonce")
		}
		pubKey, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ociimds: leaf cert public key is not RSA")
		}
		hash := sha256.Sum256(expectedNonce)
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], doc.Signature); err != nil {
			return nil, fmt.Errorf("ociimds: verify signature over nonce: %w", err)
		}
	}

	claims := claimsFromCert(leaf)
	// A chain-valid cert with no tenancy/instance OCIDs is useless for
	// identity decisions — accepting it would leave the caller with a
	// Claims struct holding empty strings and no safe way to reason
	// about who signed the document. Treat missing identity claims as
	// a verification failure rather than a silent success.
	if claims.TenancyID == "" || claims.InstanceID == "" {
		return nil, fmt.Errorf("ociimds: leaf cert missing required identity claims (tenancy/instance)")
	}
	return claims, nil
}

func claimsFromCert(cert *x509.Certificate) *Claims {
	c := &Claims{
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}
	for _, attr := range cert.Subject.Names {
		v, ok := attr.Value.(string)
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(v, "opc-tenant:"):
			c.TenancyID = strings.TrimPrefix(v, "opc-tenant:")
		case strings.HasPrefix(v, "opc-instance:"):
			c.InstanceID = strings.TrimPrefix(v, "opc-instance:")
		case strings.HasPrefix(v, "opc-compartment:"):
			c.CompartmentID = strings.TrimPrefix(v, "opc-compartment:")
		}
	}
	return c
}

// ClearRootCache wipes every cached Oracle regional root CA bundle.
// Long-lived verifier processes can call this after Oracle rotates its
// regional roots, or at a chosen refresh interval, to force a refetch
// on the next VerifyIdentityDocument call. Tests also use it to get a
// deterministic cache state.
//
// Concurrent fetches that were in flight at the moment of the clear
// will complete normally (returning the pool to their caller) but
// will not write their result back to the cache, so the clear is
// never silently undone by a race.
func ClearRootCache() {
	rootCacheMu.Lock()
	defer rootCacheMu.Unlock()
	rootCache = map[rootCacheKey]*x509.CertPool{}
	rootCacheGlobalGen++
}

// ClearRegionRootCache wipes every cached Oracle regional root CA
// bundle for a single region, including any entries created under a
// test baseURLOverride (the cache is keyed by region+override, so one
// region may have multiple entries in tests). A no-op if region is
// empty. Same in-flight-race protection as ClearRootCache, scoped so
// that clearing region A does NOT cause in-flight fetches for
// unrelated regions to drop their results.
func ClearRegionRootCache(region string) {
	if region == "" {
		return
	}
	rootCacheMu.Lock()
	defer rootCacheMu.Unlock()
	for k := range rootCache {
		if k.region == region {
			delete(rootCache, k)
		}
	}
	rootCacheRegionGen[region]++
}

func fetchRegionalRoots(ctx context.Context, region string, httpClient *http.Client, baseURLOverride string) (*x509.CertPool, error) {
	// The cache (and the singleflight dedupe) are keyed by the
	// composite (region, baseURLOverride). Without the override in
	// the key, two test hooks pointing at different fake servers for
	// the same region would collide and the second caller would get
	// the first caller's pool back, and an override-fetched pool
	// could leak into production lookups (which use an empty override).
	key := rootCacheKey{region: region, override: baseURLOverride}
	sfKey := rootKeyString(key)

	rootCacheMu.Lock()
	if pool, ok := rootCache[key]; ok {
		rootCacheMu.Unlock()
		return pool, nil
	}
	rootCacheMu.Unlock()

	// Dedupe concurrent cache misses via singleflight. A burst of
	// goroutines all missing the cache at the same time would otherwise
	// each fire the same HTTP GET — a small thundering herd that
	// wastes bandwidth, CPU, and Oracle-side rate budget. singleflight
	// collapses them into a single in-flight fetch per key, with
	// waiters piggybacking on the first caller's result.
	//
	// Use DoChan + per-caller select on ctx.Done so each caller's own
	// context cancellation/deadline is honored even when piggybacking
	// on another goroutine's in-flight fetch. With plain Do, a caller
	// with a 1s deadline would block up to the full httpClient
	// timeout (15s) waiting on an unrelated caller's fetch.
	//
	// The callback uses context.WithoutCancel(ctx) so that one caller
	// bailing out via its own ctx doesn't cancel the shared fetch —
	// other waiters that still have live contexts get the pool
	// they're waiting for. We then wrap that detached ctx with a hard
	// WithTimeout(defaultRootFetchTimeout) so the fetch is bounded
	// even if the caller injected a *http.Client whose Timeout is 0
	// (a common pattern when relying purely on ctx for cancellation).
	// Without this guard, an unresponsive Oracle endpoint plus a
	// no-timeout client would hang the singleflight goroutine
	// indefinitely, blocking all future cache-miss callers for the
	// same key (since singleflight only collapses concurrent calls).
	ch := rootFetchGroup.DoChan(sfKey, func() (any, error) {
		// Re-check the cache under singleflight and capture the
		// generation counters so we can detect a concurrent Clear.
		// We capture both the global generation (bumped by
		// ClearRootCache) and the per-region generation (bumped by
		// ClearRegionRootCache for this specific region) so that
		// clearing a different region doesn't invalidate our
		// writeback.
		rootCacheMu.Lock()
		if pool, ok := rootCache[key]; ok {
			rootCacheMu.Unlock()
			return pool, nil
		}
		globalBefore := rootCacheGlobalGen
		regionBefore := rootCacheRegionGen[region]
		rootCacheMu.Unlock()

		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rootFetchHardTimeout)
		defer cancel()
		pool, err := doFetchRegionalRoots(fetchCtx, region, httpClient, baseURLOverride)
		if err != nil {
			return nil, err
		}
		rootCacheMu.Lock()
		// Only write back to the cache if neither a global nor a
		// region-scoped Clear happened while we were on the network.
		// Otherwise drop the fetched pool on the floor (waiters whose
		// contexts are still alive still receive it) so a concurrent
		// Clear isn't silently undone.
		if rootCacheGlobalGen == globalBefore && rootCacheRegionGen[region] == regionBefore {
			rootCache[key] = pool
		}
		rootCacheMu.Unlock()
		return pool, nil
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		pool, ok := res.Val.(*x509.CertPool)
		if !ok {
			return nil, fmt.Errorf("ociimds: singleflight returned unexpected type %T", res.Val)
		}
		return pool, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func doFetchRegionalRoots(ctx context.Context, region string, httpClient *http.Client, baseURLOverride string) (*x509.CertPool, error) {
	var url string
	if baseURLOverride != "" {
		// Test hook: baseURLOverride is the full endpoint.
		url = baseURLOverride
	} else {
		// region has already been validated against validRegion by the
		// caller, so this interpolation is safe.
		url = fmt.Sprintf("https://auth.%s.oraclecloud.com/v1/instancePrincipalRootCACertificates", region)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ociimds: build root CA request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ociimds: fetch root CA: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Read a bounded snippet for diagnostics, then drain the rest so
		// the connection can be reused by net/http's default Transport.
		const maxErrorBodyBytes = 1024
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		_, _ = io.Copy(io.Discard, resp.Body)
		if msg := strings.TrimSpace(string(snippet)); msg != "" {
			return nil, fmt.Errorf("ociimds: unexpected status %d from %s: %s", resp.StatusCode, url, msg)
		}
		return nil, fmt.Errorf("ociimds: unexpected status %d from %s", resp.StatusCode, url)
	}
	// Bound the body read: a legitimate Oracle response is a few KiB,
	// but a hostile or misconfigured endpoint could otherwise stream
	// an unbounded body until we OOM. Read one extra byte so oversized
	// responses are rejected explicitly instead of silently truncated
	// (which could yield a parse error far from the real cause).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRootCABodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("ociimds: read root CA response: %w", err)
	}
	if len(body) > maxRootCABodyBytes {
		return nil, fmt.Errorf("ociimds: root CA response exceeds maximum size of %d bytes", maxRootCABodyBytes)
	}

	var wrapper struct {
		Certificates []string `json:"certificates"`
	}
	var pems []string
	if err := json.Unmarshal(body, &wrapper); err == nil && len(wrapper.Certificates) > 0 {
		pems = wrapper.Certificates
	} else {
		var arr []string
		if err := json.Unmarshal(body, &arr); err == nil {
			pems = arr
		}
	}

	pool := x509.NewCertPool()
	if len(pems) == 0 {
		if !pool.AppendCertsFromPEM(body) {
			return nil, fmt.Errorf("ociimds: could not parse regional root CA response")
		}
	} else {
		for _, p := range pems {
			if !pool.AppendCertsFromPEM([]byte(p)) {
				return nil, fmt.Errorf("ociimds: could not parse one of the regional root certs")
			}
		}
	}
	return pool, nil
}

package azureimds

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.mozilla.org/pkcs7"
)

// Claims is the set of verified claims from an Azure attested document.
type Claims struct {
	// VMID is the Azure-assigned unique VM identifier (GUID).
	VMID string `json:"vmId"`
	// SubscriptionID is the Azure subscription the VM belongs to.
	SubscriptionID string `json:"subscriptionId"`
	// SKU is the VM image SKU (e.g. "18.04-LTS").
	SKU string `json:"sku"`
	// LicenseType indicates a BYOL license scheme if set (e.g. "Windows_Server").
	LicenseType string `json:"licenseType"`
	// Nonce is the value Azure echoed back inside the signed payload.
	// Only meaningful if the verifier supplied a nonce at fetch time.
	Nonce string `json:"nonce"`
	// Plan is the Azure Marketplace plan the VM was deployed from, if any.
	Plan AttestedPlan `json:"plan"`
	// CreatedOn is the issue timestamp Azure stamped on the attested document.
	CreatedOn time.Time `json:"-"`
	// ExpiresOn is the document expiry; verification rejects anything at or past this moment.
	ExpiresOn time.Time `json:"-"`
}

// AttestedPlan is the Azure Marketplace plan info embedded in the attested doc.
type AttestedPlan struct {
	Name      string `json:"name"`
	Product   string `json:"product"`
	Publisher string `json:"publisher"`
}

type attestedPayload struct {
	VMID           string       `json:"vmId"`
	SubscriptionID string       `json:"subscriptionId"`
	SKU            string       `json:"sku"`
	LicenseType    string       `json:"licenseType"`
	Nonce          string       `json:"nonce"`
	Plan           AttestedPlan `json:"plan"`
	TimeStamp      struct {
		CreatedOn string `json:"createdOn"`
		ExpiresOn string `json:"expiresOn"`
	} `json:"timeStamp"`
}

// Microsoft uses this historical timestamp format in attested documents:
// month/day/yy hh:mm:ss Z. Example: "04/11/26 13:00:00 -0000"
const attestedTimeLayout = "01/02/06 15:04:05 -0700"

var (
	systemPoolOnce sync.Once
	systemPool     *x509.CertPool
	systemPoolErr  error
)

func loadSystemPool() (*x509.CertPool, error) {
	systemPoolOnce.Do(func() {
		systemPool, systemPoolErr = x509.SystemCertPool()
	})
	return systemPool, systemPoolErr
}

// VerifyAttestedDocument parses the PKCS7 blob, validates its cert chain
// against the system cert pool, enforces that the signer certificate was
// issued by Microsoft Azure's attestation CA, extracts the inner JSON
// payload, and validates the expiresOn timestamp.
//
// expectedNonce should only be non-empty if the verifier (i.e. the caller
// of this function) is the party that originally picked the nonce and
// shipped it out-of-band to the instance. Otherwise pass the empty
// string and the nonce check is skipped.
//
// A nonce-based replay check is ONLY meaningful when the verifier picks
// the value — if the instance (or Azure's default-to-timestamp fallback)
// picks the nonce, the verifier has nothing to compare against. See the
// WithNonce doc comment in attested.go for alternative replay-protection
// strategies suitable for push-style flows.
//
// Even with expectedNonce == "", the signature, chain, Azure issuer,
// and expiresOn window are still verified; the returned Claims are
// authentic, they just may be replayable within the ~5 minute
// expiresOn window.
func VerifyAttestedDocument(signature []byte, expectedNonce string) (*Claims, error) {
	roots, err := loadSystemPool()
	if err != nil {
		return nil, fmt.Errorf("azureimds: load system cert pool: %w", err)
	}
	// Defense in depth: with the system cert pool, any publicly-trusted
	// CA could issue a certificate that would pass a pure chain check.
	// Require the signer cert's Issuer CN to come from Microsoft Azure's
	// attestation CA family so only certs issued by Azure's attestation
	// infrastructure are accepted.
	return verifyAttestedDocument(signature, expectedNonce, roots, true)
}

// VerifyAttestedDocumentWithRoots is like VerifyAttestedDocument but
// accepts an explicit root CA pool and does NOT enforce the Microsoft
// Azure issuer check on the signer certificate. Used by tests with a
// throwaway CA, and by off-cloud verifiers that have already narrowed
// their trust to Azure-specific roots in the supplied pool. roots must
// be non-nil — passing nil would fall back to the host's system trust
// store inside x509.Verify, which defeats the point of an explicit
// escape hatch and would accidentally tie off-cloud verification to
// whatever CAs happen to be trusted on the verifier machine.
//
// If you're passing a pool that includes any CA besides Azure's own
// attestation CAs, you should add your own signer-cert issuer check
// on the returned Claims — otherwise any trusted CA in the pool could
// issue a certificate that signs a forged attested document.
func VerifyAttestedDocumentWithRoots(signature []byte, expectedNonce string, roots *x509.CertPool) (*Claims, error) {
	if roots == nil {
		return nil, fmt.Errorf("azureimds: roots cert pool is nil")
	}
	return verifyAttestedDocument(signature, expectedNonce, roots, false)
}

func verifyAttestedDocument(signature []byte, expectedNonce string, roots *x509.CertPool, requireAzureIssuer bool) (*Claims, error) {
	p7, err := pkcs7.Parse(signature)
	if err != nil {
		return nil, fmt.Errorf("azureimds: parse PKCS7: %w", err)
	}

	// VerifyWithChain verifies the PKCS7 cryptographic signature AND
	// validates that the actual signer certificate chains to a root in
	// the supplied pool. This ties chain validation to the cert that
	// produced the signature, so a malicious PKCS7 cannot satisfy the
	// check by including an unrelated publicly-trusted leaf alongside
	// a self-signed signer cert.
	if err := p7.VerifyWithChain(roots); err != nil {
		return nil, fmt.Errorf("azureimds: verify PKCS7 signature/chain: %w", err)
	}

	if requireAzureIssuer {
		signer := p7.GetOnlySigner()
		if signer == nil {
			return nil, fmt.Errorf("azureimds: PKCS7 must have exactly one signer")
		}
		if !isAzureIssuer(signer.Issuer.CommonName) {
			return nil, fmt.Errorf("azureimds: signer certificate not issued by Microsoft Azure (issuer CN = %q)", signer.Issuer.CommonName)
		}
	}

	var payload attestedPayload
	if err := json.Unmarshal(p7.Content, &payload); err != nil {
		return nil, fmt.Errorf("azureimds: parse attested payload: %w", err)
	}

	createdOn, err := time.Parse(attestedTimeLayout, payload.TimeStamp.CreatedOn)
	if err != nil {
		return nil, fmt.Errorf("azureimds: parse createdOn: %w", err)
	}
	expiresOn, err := time.Parse(attestedTimeLayout, payload.TimeStamp.ExpiresOn)
	if err != nil {
		return nil, fmt.Errorf("azureimds: parse expiresOn: %w", err)
	}
	// Treat expiresOn == now as already expired — matches the PR
	// description's intent of "expiresOn > now" rather than ">=".
	if !time.Now().Before(expiresOn) {
		return nil, fmt.Errorf("azureimds: attested document expired at %v", expiresOn)
	}

	// Regular equality is sufficient here: the nonce was chosen by the
	// verifier (not a secret in the usual sense), and subtle.Constant
	// TimeCompare only runs in constant time when both slices have the
	// same length anyway. The standard `==` check is clearer about
	// what's going on.
	if expectedNonce != "" && payload.Nonce != expectedNonce {
		return nil, fmt.Errorf("azureimds: nonce mismatch")
	}

	return &Claims{
		VMID:           payload.VMID,
		SubscriptionID: payload.SubscriptionID,
		SKU:            payload.SKU,
		LicenseType:    payload.LicenseType,
		Nonce:          payload.Nonce,
		Plan:           payload.Plan,
		CreatedOn:      createdOn,
		ExpiresOn:      expiresOn,
	}, nil
}

// isAzureIssuer reports whether the given Issuer CN looks like one of
// Microsoft Azure's attestation signing CAs. Matched by case-insensitive
// substring so the check stays valid across CA rotations — Azure has
// historically rotated through "Microsoft Azure RSA TLS Issuing CA
// 03/04/05/07/08" and counting. The common substring "microsoft azure"
// is stable.
func isAzureIssuer(issuerCN string) bool {
	return strings.Contains(strings.ToLower(issuerCN), "microsoft azure")
}

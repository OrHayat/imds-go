package alibabaimds

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"go.mozilla.org/pkcs7"
)

// Claims holds the verified fields from an Alibaba ECS instance
// identity document.
type Claims struct {
	OwnerAccountID string
	InstanceID     string
	MAC            string
	RegionID       string
	SerialNumber   string
	ZoneID         string
	InstanceType   string
	ImageID        string
	PrivateIPv4    string
	Audience       string // what was in the signed payload; empty if no audience was passed
}

type rawClaims struct {
	OwnerAccountID string `json:"owner-account-id"`
	InstanceID     string `json:"instance-id"`
	MAC            string `json:"mac"`
	RegionID       string `json:"region-id"`
	SerialNumber   string `json:"serial-number"`
	ZoneID         string `json:"zone-id"`
	InstanceType   string `json:"instance-type"`
	ImageID        string `json:"image-id"`
	PrivateIPv4    string `json:"private-ipv4"`
	Audience       string `json:"audience"`
}

// VerifyIdentity validates an Alibaba ECS instance identity: parses the
// detached PKCS7 signature, verifies it against the baked-in Alibaba
// public certificate, asserts the signed content matches document
// byte-for-byte, unmarshals the JSON payload, and (if expectedAudience
// is non-empty) checks that the audience field equals it.
//
// expectedAudience should only be non-empty if the verifier itself
// picked the audience value and shipped it out-of-band to the instance.
// Otherwise pass an empty string and the audience check is skipped —
// the signature + content are still verified.
func VerifyIdentity(document, signature []byte, expectedAudience string) (*Claims, error) {
	certs, err := loadAlibabaCert()
	if err != nil {
		return nil, err
	}
	return VerifyIdentityWithCerts(document, signature, expectedAudience, certs)
}

// VerifyIdentityWithCerts is like VerifyIdentity but accepts an
// explicit slice of trusted signer certificates. The supplied certs
// are pinned directly — no chain validation is performed against
// them, they are treated as leaf signing certs whose raw DER must
// match the PKCS7 signer. Used by tests that inject a throwaway
// signing cert, and by callers who want to pin against a rotated
// Alibaba cert out-of-band.
//
// Trust model: the signer certificate is pinned by equality against
// one of the supplied certs, not validated through a chain. Alibaba's
// published cert has all-"Unknown" subject fields and no
// BasicConstraints extension, so it cannot serve as an x509 trust
// anchor; Alibaba's own docs instruct callers to use
// `openssl smime -verify -noverify`, which skips chain validation.
// We follow the same approach: pkcs7.Verify() (no truststore) checks
// the signature, and we separately assert the signer cert matches
// one of the trusted certs by raw DER.
func VerifyIdentityWithCerts(document, signature []byte, expectedAudience string, certs []*x509.Certificate) (*Claims, error) {
	// Validate the pinned signer set up front so that the later
	// `signer.Raw` / `c.Raw` comparisons can't hit a nil pointer from
	// an untrusted caller passing a sparse slice.
	if len(certs) == 0 {
		return nil, fmt.Errorf("alibabaimds: certs slice is empty")
	}
	for i, c := range certs {
		if c == nil {
			return nil, fmt.Errorf("alibabaimds: certs[%d] is nil", i)
		}
	}
	// pem.Decode silently skips any leading non-PEM bytes before the
	// first "-----BEGIN" marker. Match the strict trailing-content
	// rule below by also rejecting leading non-whitespace content, so
	// a polyglot input with attacker-chosen prefix bytes fails closed.
	trimmed := bytes.TrimLeft(signature, " \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		return nil, fmt.Errorf("alibabaimds: signature has unexpected leading content before PEM block")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, fmt.Errorf("alibabaimds: signature is not PEM-encoded")
	}
	// Alibaba's /dynamic/instance-identity/pkcs7 endpoint returns a
	// single PEM block of type "PKCS7". Anything else (a CERTIFICATE
	// block, a private key, etc.) is a misuse — reject it with a
	// clear error instead of passing it to pkcs7.Parse, which would
	// surface a cryptic "asn1: structure error" from the wrong
	// content.
	if block.Type != "PKCS7" {
		return nil, fmt.Errorf("alibabaimds: signature PEM block type %q, want %q", block.Type, "PKCS7")
	}
	// Reject any trailing PEM content so a crafted bundle can't
	// append extra blocks after the legitimate PKCS7 one. Trailing
	// whitespace (newlines the server may add) is tolerated.
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("alibabaimds: unexpected trailing content after PKCS7 PEM block")
	}
	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("alibabaimds: parse PKCS7: %w", err)
	}
	// Alibaba's PKCS7 is detached — we supply the external content to
	// verify against.
	p7.Content = document
	// Pin the signer cert list to our trusted set. pkcs7.Verify looks
	// up the signer by IssuerAndSerialNumber in p7.Certificates, so
	// forcing this list to the trusted certs means any signer not in
	// the trusted set cannot be located and verification fails.
	p7.Certificates = certs
	if err := p7.Verify(); err != nil {
		return nil, fmt.Errorf("alibabaimds: verify PKCS7 signature: %w", err)
	}
	// Belt and braces: even though pkcs7.Verify looked up the signer
	// from p7.Certificates, confirm the resolved signer is byte-for-
	// byte one of the trusted certs. Guards against any future pkcs7
	// change that might fall back to signer certs from other sources.
	signer := p7.GetOnlySigner()
	if signer == nil {
		return nil, fmt.Errorf("alibabaimds: PKCS7 has zero or multiple signers")
	}
	trusted := false
	for _, c := range certs {
		if subtle.ConstantTimeCompare(signer.Raw, c.Raw) == 1 {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil, fmt.Errorf("alibabaimds: signer certificate is not in trusted set")
	}

	var raw rawClaims
	if err := json.Unmarshal(document, &raw); err != nil {
		return nil, fmt.Errorf("alibabaimds: parse identity document: %w", err)
	}

	// Plain equality: the audience is chosen by the verifier and
	// shipped to the instance, so it's not a long-term secret where
	// timing leaks would matter. subtle.ConstantTimeCompare is also
	// not truly constant-time for mismatched lengths (returns 0
	// immediately) so using it here would be cargo-cult.
	if expectedAudience != "" && raw.Audience != expectedAudience {
		return nil, fmt.Errorf("alibabaimds: audience mismatch")
	}

	return &Claims{
		OwnerAccountID: raw.OwnerAccountID,
		InstanceID:     raw.InstanceID,
		MAC:            raw.MAC,
		RegionID:       raw.RegionID,
		SerialNumber:   raw.SerialNumber,
		ZoneID:         raw.ZoneID,
		InstanceType:   raw.InstanceType,
		ImageID:        raw.ImageID,
		PrivateIPv4:    raw.PrivateIPv4,
		Audience:       raw.Audience,
	}, nil
}

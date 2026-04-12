package alibabaimds

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
)

// alibabaSigningCertPEM is the public certificate Alibaba publishes for
// verifying ECS instance-identity PKCS7 signatures. Source:
// https://www.alibabacloud.com/help/en/ecs/user-guide/use-instance-identities
//
// Named "Signing" (not "Root") deliberately: Alibaba publishes this
// cert with all subject fields set to "Unknown" and no BasicConstraints
// extension — it is not a CA cert and it is not self-signed in the
// x509-chain sense. Alibaba's own verification instructions use
// `openssl smime -verify -noverify`, explicitly skipping trust-chain
// validation. We follow the same model: the cert is used as a pinned
// signing key, not as a trust anchor. See verify.go for details.
const alibabaSigningCertPEM = `-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEZmbRhzANBgkqhkiG9w0BAQsFADBsMRAwDgYDVQQGEwdV
bmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYD
VQQKEwdVbmtub3duMRAwDgYDVQQLEwdVbmtub3duMRAwDgYDVQQDEwdVbmtub3du
MB4XDTE4MDIyMzAxMjkzOFoXDTM4MDIxODAxMjkzOFowbDEQMA4GA1UEBhMHVW5r
bm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93bjEQMA4GA1UE
ChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHVW5rbm93bjCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIJwy5sbZDiNyX4mvdP32pqM
YMK4k7+5lRnVR2Fky/5uwyGSPbddNXaXzwEm+u4wIsJiaAN3OZgJpYIoCGik+9lG
5gVAIr0+/3rZ61IbeVE+vDenDd8g/m/YIdYBfC2IbzgS9EVGAf/gJdtDODXrDfQj
Fk2rQsvpftVOUs3Vpl9O+jeCQLoRbZYm0c5v7jP/L2lK0MjhiywPF2kpDeisMtnD
/ArkSPIlg1qVYm3F19v3pa6ZioM2hnwXg5DibYlgVvsIBGhvYqdQ1KosNVcVGGQa
HCUuVGdS7vHJYp3byH0vQYYygzxUJT2TqvK7pD57eYMN5drc7e19oyRQvbPQ3kkC
AwEAAaMhMB8wHQYDVR0OBBYEFAwwrnHlRgFvPGo+UD5zS1xAkC91MA0GCSqGSIb3
DQEBCwUAA4IBAQBBLhDRgezd/OOppuYEVNB9+XiJ9dNmcuHUhjNTnjiKQWVk/YDA
v+T2V3t9yl8L8o61tRIVKQ++lDhjlVmur/mbBN25/UNRpJllfpUH6oOaqvQAze4a
nRgyTnBwVBZkdJ0d1sivL9NZ4pKelJF3Ylw6rp0YMqV+cwkt/vRtzRJ31ZEeBhs7
vKh7F6BiGCHL5ZAwEUYe8O3akQwjgrMUcfuiFs4/sAeDMnmgN6Uq8DFEBXDpAxVN
sV/6Hockdfinx85RV2AUwJGfClcVcu4hMhOvKROpcH27xu9bBIeMuY0vvzP2VyOm
DoJeqU7qZjyCaUBkPimsz/1eRod6d4P5qxTj
-----END CERTIFICATE-----
`

var (
	certOnce sync.Once
	certPool []*x509.Certificate
	certErr  error
)

func loadAlibabaCert() ([]*x509.Certificate, error) {
	certOnce.Do(func() {
		block, _ := pem.Decode([]byte(alibabaSigningCertPEM))
		if block == nil || block.Type != "CERTIFICATE" {
			certErr = fmt.Errorf("alibabaimds: no CERTIFICATE PEM block in baked-in cert")
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			certErr = fmt.Errorf("alibabaimds: parse baked-in cert: %w", err)
			return
		}
		certPool = []*x509.Certificate{cert}
	})
	return certPool, certErr
}

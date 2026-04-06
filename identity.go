package imds

// DocFormat identifies the format of an identity document.
type DocFormat string

const (
	FormatJWT    DocFormat = "jwt"
	FormatPKCS7  DocFormat = "pkcs7"
	FormatRSA    DocFormat = "rsa2048"
	FormatX509   DocFormat = "x509"
)

// IdentityDocument holds a signed identity proof from a cloud provider.
type IdentityDocument struct {
	Provider  ID        `json:"provider"`
	Raw       []byte    `json:"raw"`
	Format    DocFormat `json:"format"`
	Signature []byte    `json:"signature,omitempty"`
}

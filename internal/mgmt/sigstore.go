package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
)

const sigstoreMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

var keySHARE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// sigstoreBundle wraps a DSSE envelope in a Sigstore bundle that cosign verifies offline against a
// public key: the key hint is the SHA-256 of the raw public key, and the bundle holds no
// transparency log entry. The envelope bytes sit in the bundle unchanged.
func sigstoreBundle(envelope []byte, keySHA string) ([]byte, error) {
	if !keySHARE.MatchString(keySHA) {
		return nil, errors.New("key digest is not 64 lowercase hex characters")
	}
	trimmed := bytes.TrimSpace(envelope)
	var probe map[string]json.RawMessage
	if len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(trimmed, &probe) != nil {
		return nil, errors.New("envelope is not a JSON object")
	}
	var b bytes.Buffer
	b.WriteString(`{"mediaType":"` + sigstoreMediaType + `","verificationMaterial":{"publicKey":{"hint":"` + keySHA + `"}},"dsseEnvelope":`)
	b.Write(trimmed)
	b.WriteByte('}')
	return b.Bytes(), nil
}

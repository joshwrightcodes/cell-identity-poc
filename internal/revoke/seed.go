package revoke

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// SeedPrefix starts the one line that holds an operator seed. The token scan of the gate looks for it.
const SeedPrefix = "OPERATOR-ED25519-SEED:"

// maxSeedRead is the most bytes that ParseSeed reads.
const maxSeedRead = 256

// MaxKeys is the most operator public keys in force at once: the key, and the next key during a
// rotation.
const MaxKeys = 2

// FormatSeed returns the seed line of k without a line break: SeedPrefix and the standard base64 of
// the 32-byte seed. It returns the empty string when k is not an Ed25519 private key.
func FormatSeed(k ed25519.PrivateKey) string {
	if len(k) != ed25519.PrivateKeySize {
		return ""
	}
	return SeedPrefix + base64.StdEncoding.EncodeToString(k.Seed())
}

// WriteSeed writes the seed line of k and one line break to w, from a buffer that it clears
// afterwards. Its error text never holds seed bytes.
func WriteSeed(w io.Writer, k ed25519.PrivateKey) error {
	if len(k) != ed25519.PrivateKeySize {
		return errors.New("operator seed: key is not an Ed25519 private key")
	}
	seed := k.Seed()
	defer clear(seed)
	enc := base64.StdEncoding
	line := make([]byte, 0, len(SeedPrefix)+enc.EncodedLen(len(seed))+1)
	defer func() { clear(line[:cap(line)]) }()
	line = append(line, SeedPrefix...)
	line = enc.AppendEncode(line, seed)
	line = append(line, '\n')
	if _, err := w.Write(line); err != nil {
		return errors.New("operator seed: write failed")
	}
	return nil
}

// The errors of ParseSeed. Their text is fixed, so no error carries a byte of the input.
var (
	errSeedRead   = errors.New("operator seed: read failed")
	errSeedLines  = errors.New("operator seed: input is not one line")
	errSeedFormat = errors.New("operator seed: line has the wrong format")
	errSeedLength = errors.New("operator seed: seed is not 32 bytes")
)

// ParseSeed reads one seed line from r, as FormatSeed writes it, with an optional "\n" or "\r\n"
// at the end. It reads at most 256 bytes. Its error text never holds input bytes, and it clears its
// copy of the input before it returns.
func ParseSeed(r io.Reader) (ed25519.PrivateKey, error) {
	buf := make([]byte, maxSeedRead)
	defer clear(buf)
	n, err := io.ReadFull(r, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, errSeedRead
	}
	line := buf[:n]
	if l, ok := bytes.CutSuffix(line, []byte("\n")); ok {
		line = bytes.TrimSuffix(l, []byte("\r"))
	}
	if n == maxSeedRead || bytes.ContainsAny(line, "\r\n") {
		return nil, errSeedLines
	}
	body, ok := bytes.CutPrefix(line, []byte(SeedPrefix))
	if !ok || len(body) != base64.StdEncoding.EncodedLen(ed25519.SeedSize) {
		return nil, errSeedFormat
	}
	seed := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
	defer clear(seed)
	m, err := base64.StdEncoding.Strict().Decode(seed, body)
	if err != nil {
		return nil, errSeedFormat
	}
	if m != ed25519.SeedSize {
		return nil, errSeedLength
	}
	return ed25519.NewKeyFromSeed(seed[:m]), nil
}

// ParseKeys parses the pin of the operator keys: one or two lines, each the standard base64 of a
// 32-byte Ed25519 public key, with an optional line break at the end. Two equal keys are refused.
func ParseKeys(text []byte) ([]ed25519.PublicKey, error) {
	s := strings.TrimSuffix(string(text), "\n")
	if s == "" {
		return nil, errors.New("operator keys: no key")
	}
	if strings.Contains(s, "\r") {
		return nil, errors.New("operator keys: carriage return in the text")
	}
	lines := strings.Split(s, "\n")
	if len(lines) > MaxKeys {
		return nil, fmt.Errorf("operator keys: %d lines, at most %d", len(lines), MaxKeys)
	}
	keys := make([]ed25519.PublicKey, 0, len(lines))
	for i, l := range lines {
		raw, err := base64.StdEncoding.Strict().DecodeString(l)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("operator keys: line %d is not the standard base64 of a 32-byte key", i+1)
		}
		k := ed25519.PublicKey(raw)
		for _, prev := range keys {
			if prev.Equal(k) {
				return nil, fmt.Errorf("operator keys: line %d repeats a key", i+1)
			}
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// KeySHA256 returns the lowercase hex SHA-256 of the 32 raw bytes of k.
func KeySHA256(k ed25519.PublicKey) string {
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:])
}

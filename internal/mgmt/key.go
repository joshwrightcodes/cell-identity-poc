// Package mgmt is the core of the management plane: it holds the signing key, the intent, the
// state and the nonces, binds cells, checks their keys, and signs the specs and records.
package mgmt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const maxKeyFile = 4096

// LoadOrCreateKey reads the Ed25519 signing key at path. When the file is absent it makes a key,
// writes it with mode 0400 and returns true. It refuses a file with group or other permissions.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, bool, error) {
	f, err := os.Open(path)
	switch {
	case err == nil:
		defer f.Close()
		key, err := readKey(f)
		return key, false, err
	case errors.Is(err, fs.ErrNotExist):
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("make signing key: %w", err)
		}
		if err := WriteKey(path, key); err != nil {
			return nil, false, err
		}
		return key, true, nil
	default:
		return nil, false, fmt.Errorf("open signing key: %w", err)
	}
}

func readKey(f *os.File) (ed25519.PrivateKey, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat signing key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("signing key path is not a regular file")
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("signing key file has mode %04o, group and other must have no access", perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	if len(data) > maxKeyFile {
		return nil, errors.New("signing key file is too large")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("signing key file holds no PKCS#8 PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("signing key file does not parse as PKCS#8")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not an Ed25519 key")
	}
	return key, nil
}

// WriteKey replaces the key file with key, through a temporary file, a sync and a rename. The new
// file has mode 0400.
func WriteKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode signing key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic(path, data, 0o400); err != nil {
		return fmt.Errorf("write signing key: %w", err)
	}
	return nil
}

// fingerprint is the lowercase hex SHA-256 of the raw public key bytes.
func fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// writeFileAtomic writes data to a temporary file next to path, syncs it, renames it over path and
// syncs the directory, so a reader sees the old file or the whole new one.
func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

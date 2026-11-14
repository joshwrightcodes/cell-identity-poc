package hostsvc

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// reloadEvery is how often a file source looks at its files again.
const reloadEvery = 10 * time.Second

// FileBundles is an x509bundle.Source with one file for each trust domain. A file is read again
// when its modification time, size or identity changes, checked at most every 10 seconds. Each
// load applies the rules of LoadClientRoots. A missing or bad file gives no bundle for its trust
// domain, so its handshakes fail.
type FileBundles struct {
	now   func() time.Time
	mu    sync.Mutex
	files map[spiffeid.TrustDomain]*fileRoots
}

type fileRoots struct {
	path    string
	checked time.Time
	info    os.FileInfo
	roots   *ClientRoots
	err     error
}

// FileBundleSet returns a source for the given trust domains. A request for another trust domain
// is an error.
func FileBundleSet(paths map[spiffeid.TrustDomain]string) *FileBundles {
	return newFileBundleSet(paths, time.Now)
}

func newFileBundleSet(paths map[spiffeid.TrustDomain]string, now func() time.Time) *FileBundles {
	f := &FileBundles{now: now, files: map[spiffeid.TrustDomain]*fileRoots{}}
	for td, p := range paths {
		f.files[td] = &fileRoots{path: p}
	}
	return f
}

// GetX509BundleForTrustDomain implements x509bundle.Source.
func (f *FileBundles) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	r, err := f.roots(td)
	if err != nil {
		return nil, err
	}
	return r.GetX509BundleForTrustDomain(td)
}

// SHA256 returns the hex SHA-256 of the roots that are loaded for td, and empty when there are none.
func (f *FileBundles) SHA256(td spiffeid.TrustDomain) string {
	r, err := f.roots(td)
	if err != nil {
		return ""
	}
	return r.SHA256()
}

func (f *FileBundles) roots(td spiffeid.TrustDomain) (*ClientRoots, error) {
	fr, ok := f.files[td]
	if !ok {
		return nil, fmt.Errorf("no bundle file for trust domain %q", td)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if !fr.checked.IsZero() && now.Sub(fr.checked) < reloadEvery && !now.Before(fr.checked) {
		return fr.roots, fr.err
	}
	fr.checked = now
	info, err := os.Stat(fr.path)
	if err != nil {
		fr.info, fr.roots, fr.err = nil, nil, fmt.Errorf("bundle file for %q: %w", td, err)
		return nil, fr.err
	}
	if fr.info != nil && os.SameFile(fr.info, info) && fr.info.ModTime().Equal(info.ModTime()) && fr.info.Size() == info.Size() {
		return fr.roots, fr.err
	}
	fr.info = info
	fr.roots, fr.err = LoadClientRoots(fr.path, td, now)
	return fr.roots, fr.err
}

// multiSource asks each source for the trust domains that it knows.
type multiSource map[spiffeid.TrustDomain]x509bundle.Source

// MultiSource returns a source that sends each trust domain to its own source.
func MultiSource(m map[spiffeid.TrustDomain]x509bundle.Source) x509bundle.Source {
	return multiSource(m)
}

func (m multiSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s, ok := m[td]
	if !ok {
		return nil, fmt.Errorf("no bundle for trust domain %q", td)
	}
	return s.GetX509BundleForTrustDomain(td)
}

// KeysFromDir returns a function that reads the public keys in dir. A key file ends in .pub, does
// not start with a dot, and holds the standard base64 of 32 bytes. Symbolic links are followed, as
// in a ConfigMap volume. A bad file is left out and the others stay. The directory is listed again
// at most every 10 seconds, so a removed file leaves the set.
func KeysFromDir(dir string) func() []ed25519.PublicKey {
	return keysFromDir(dir, time.Now)
}

func keysFromDir(dir string, now func() time.Time) func() []ed25519.PublicKey {
	var (
		mu      sync.Mutex
		checked time.Time
		keys    []ed25519.PublicKey
	)
	return func() []ed25519.PublicKey {
		mu.Lock()
		defer mu.Unlock()
		if t := now(); checked.IsZero() || t.Sub(checked) >= reloadEvery || t.Before(checked) {
			checked, keys = t, readKeyDir(dir)
		}
		return slices.Clone(keys)
	}
}

func readKeyDir(dir string) []ed25519.PublicKey {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []ed25519.PublicKey
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".pub") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		out = append(out, ed25519.PublicKey(raw))
	}
	return out
}

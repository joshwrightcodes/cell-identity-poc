package hostsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var devTD = spiffeid.RequireTrustDomainFromString(StepClientTrustDomain)

func TestFileBundleSetUnknownTD(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dev.pem")
	if err := os.WriteFile(p, newURICA(t, StepClientTrustDomain).pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	src := FileBundleSet(map[spiffeid.TrustDomain]string{devTD: p})
	if _, err := src.GetX509BundleForTrustDomain(devTD); err != nil {
		t.Fatalf("known trust domain: %v", err)
	}
	if _, err := src.GetX509BundleForTrustDomain(mgmtTD); err == nil {
		t.Error("an unknown trust domain gave a bundle")
	}
	// Each trust domain gets its own file only: the dev file holds a dev root, and a request for
	// the management domain never reads it.
	both := FileBundleSet(map[spiffeid.TrustDomain]string{devTD: p, mgmtTD: filepath.Join(dir, "absent.pem")})
	if _, err := both.GetX509BundleForTrustDomain(mgmtTD); err == nil {
		t.Error("the management domain got a bundle from another file")
	}
	if sum := both.SHA256(devTD); sum == "" {
		t.Error("SHA256 of a loaded root is empty")
	}
	if both.SHA256(mgmtTD) != "" {
		t.Error("SHA256 of an absent file is not empty")
	}
}

func TestFileBundleSetReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dev.pem")
	clock := &fakeClock{t: time.Now()}
	src := newFileBundleSet(map[spiffeid.TrustDomain]string{devTD: p}, clock.Now)
	get := func() error { _, err := src.GetX509BundleForTrustDomain(devTD); return err }
	if get() == nil {
		t.Fatal("a missing file gave a bundle")
	}
	first := newURICA(t, StepClientTrustDomain)
	if err := os.WriteFile(p, first.pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	if get() == nil {
		t.Error("the file was read again within 10 s")
	}
	clock.Advance(11 * time.Second)
	if err := get(); err != nil {
		t.Fatalf("after 11 s: %v", err)
	}
	sum1 := src.SHA256(devTD)
	// A changed file loads after the next check.
	second := newURICA(t, StepClientTrustDomain)
	if err := os.WriteFile(p, append(first.pem(), second.pem()...), 0o600); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Second)
	if err := get(); err != nil || src.SHA256(devTD) == sum1 {
		t.Errorf("a changed file did not load: %v", err)
	}
	// A bad file fails closed: no bundle, not the old one.
	if err := os.WriteFile(p, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Second)
	if get() == nil {
		t.Error("a bad file kept the old bundle")
	}
	// A root of another trust domain is refused.
	if err := os.WriteFile(p, newURICA(t, MgmtTrustDomain).pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Second)
	if get() == nil {
		t.Error("a root with another trust domain loaded")
	}
	// An unchanged file is not parsed again: replace it with the same bytes, and the same mtime.
	if err := os.WriteFile(p, first.pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Second)
	if err := get(); err != nil {
		t.Errorf("the file came back: %v", err)
	}
}

func TestServerTLSDevRootLoadsLater(t *testing.T) {
	dir := t.TempDir()
	mgmt := newURICA(t, MgmtTrustDomain)
	dev := newURICA(t, StepClientTrustDomain)
	devFile := filepath.Join(dir, "dev-root.crt")
	clock := &fakeClock{t: time.Now()}
	mgmtFile := filepath.Join(dir, "mgmt.pem")
	if err := os.WriteFile(mgmtFile, mgmt.pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	mgmtRoots, err := LoadClientRoots(mgmtFile, mgmtTD, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	devRoots := newFileBundleSet(map[spiffeid.TrustDomain]string{devTD: devFile}, clock.Now)
	roots := MultiSource(map[spiffeid.TrustDomain]x509bundle.Source{mgmtTD: mgmtRoots, devTD: devRoots})
	cert, _ := SelfSignedCert(KeyServerHost, time.Now())
	mgmtID, stepsID := spiffeid.RequireFromString(mgmtAPIID), spiffeid.RequireFromString(cellControllerID)
	srv := NewKeyServer(NewRouter(okHandler("keys"), okHandler("spec"), okHandler("steps"), mgmtID, stepsID, 4), ServerTLS(cert, roots, mgmtID, stepsID), discardLog())
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeKeys(ctx, srv, ln, discardLog(), nil) }()
	t.Cleanup(func() { cancel(); <-done })
	sum := sha256.Sum256(cert.Leaf.Raw)
	call := func(src svidSource, id string) error {
		kc, err := NewKeyClient(KeyClientConfig{Addr: ln.Addr().String(), ServerName: KeyServerHost, Pin: sum[:], SVIDs: src, Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		_, err = kc.call(context.Background(), "GET", id, nil)
		return err
	}
	ccSrc := svidSource{dev.issue(t, dev.cert, dev.key, cellControllerID, time.Hour)}
	mgmtSrc := svidSource{mgmt.issue(t, mgmt.cert, mgmt.key, mgmtAPIID, time.Hour)}
	if err := call(ccSrc, stepsPath); err == nil {
		t.Fatal("the cell controller connected before the dev root existed")
	}
	if err := call(mgmtSrc, keysPath); err != nil {
		t.Fatalf("the management peer must work with no dev root: %v", err)
	}
	if err := os.WriteFile(devFile, dev.pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := call(ccSrc, stepsPath); err == nil {
		t.Fatal("the dev root was read again within 10 s")
	}
	clock.Advance(11 * time.Second)
	if err := call(ccSrc, stepsPath); err != nil {
		t.Fatalf("after the dev root appeared: %v", err)
	}
	// The dev root is replaced by another one: the old leaf fails after the next check.
	if err := os.WriteFile(devFile, newURICA(t, StepClientTrustDomain).pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Second)
	if err := call(ccSrc, stepsPath); err == nil {
		t.Fatal("a leaf of the replaced dev root still works")
	}
}

func TestKeysFromDirReload(t *testing.T) {
	newKeyFile := func(t *testing.T, path string) ed25519.PublicKey {
		t.Helper()
		pub, _ := newKey(t)
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return pub
	}
	has := func(keys []ed25519.PublicKey, k ed25519.PublicKey) bool {
		for _, x := range keys {
			if x.Equal(k) {
				return true
			}
		}
		return false
	}
	t.Run("removed_file", func(t *testing.T) {
		dir := t.TempDir()
		clock := newFakeClock()
		keys := keysFromDir(dir, clock.Now)
		spec := newKeyFile(t, filepath.Join(dir, "spec.pub"))
		next := newKeyFile(t, filepath.Join(dir, "next.pub"))
		if got := keys(); len(got) != 2 || !has(got, spec) || !has(got, next) {
			t.Fatalf("keys = %d, want both", len(got))
		}
		if err := os.Remove(filepath.Join(dir, "next.pub")); err != nil {
			t.Fatal(err)
		}
		clock.Advance(5 * time.Second)
		if got := keys(); len(got) != 2 {
			t.Errorf("the directory was listed again within 10 s: %d keys", len(got))
		}
		clock.Advance(6 * time.Second)
		if got := keys(); len(got) != 1 || !has(got, spec) || has(got, next) {
			t.Errorf("after removal: %d keys, a discarded key must leave the set", len(got))
		}
	})
	t.Run("added_file", func(t *testing.T) {
		dir := t.TempDir()
		clock := newFakeClock()
		keys := keysFromDir(dir, clock.Now)
		if got := keys(); len(got) != 0 {
			t.Fatalf("empty directory: %d keys", len(got))
		}
		k := newKeyFile(t, filepath.Join(dir, "spec.pub"))
		clock.Advance(11 * time.Second)
		if got := keys(); len(got) != 1 || !has(got, k) {
			t.Errorf("after adding: %d keys", len(got))
		}
	})
	t.Run("configmap_layout", func(t *testing.T) {
		// A ConfigMap volume: spec.pub is a link to ..data/spec.pub, and ..data links to a
		// timestamped directory.
		dir := t.TempDir()
		real := filepath.Join(dir, "..2026_11_10_12_00_00.123")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		k := newKeyFile(t, filepath.Join(real, "spec.pub"))
		next := newKeyFile(t, filepath.Join(real, "next.pub"))
		if err := os.Symlink(filepath.Base(real), filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"spec.pub", "next.pub"} {
			if err := os.Symlink(filepath.Join("..data", n), filepath.Join(dir, n)); err != nil {
				t.Fatal(err)
			}
		}
		// A dot file with a key must not count, and neither must a file that is not .pub.
		newKeyFile(t, filepath.Join(real, ".hidden.pub"))
		newKeyFile(t, filepath.Join(dir, "other.txt"))
		got := KeysFromDir(dir)()
		if len(got) != 2 || !has(got, k) || !has(got, next) {
			t.Errorf("configmap layout: %d keys, want spec.pub and next.pub only", len(got))
		}
	})
	t.Run("bad_file_skipped", func(t *testing.T) {
		dir := t.TempDir()
		good := newKeyFile(t, filepath.Join(dir, "spec.pub"))
		for name, content := range map[string]string{
			"notbase64.pub": "!!!", "short.pub": base64.StdEncoding.EncodeToString([]byte("short")),
			"empty.pub": "", "urlsafe.pub": base64.URLEncoding.EncodeToString(make([]byte, 32)) + "x",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Mkdir(filepath.Join(dir, "dir.pub"), 0o755); err != nil {
			t.Fatal(err)
		}
		got := KeysFromDir(dir)()
		if len(got) != 1 || !has(got, good) {
			t.Errorf("bad files: %d keys, want the good one only", len(got))
		}
	})
	t.Run("missing_directory", func(t *testing.T) {
		if got := KeysFromDir(filepath.Join(t.TempDir(), "none"))(); len(got) != 0 {
			t.Errorf("missing directory: %d keys", len(got))
		}
	})
}

func okHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, name) })
}

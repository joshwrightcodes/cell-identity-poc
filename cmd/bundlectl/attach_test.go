package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore/ocitest"
)

const mtIndex = "application/vnd.oci.image.index.v1+json"

// sigstoreFile writes a cosign bundle as mgmtd makes it. n makes the content differ.
func sigstoreFile(t *testing.T, dir string, n int) (string, []byte) {
	t.Helper()
	body := []byte(fmt.Sprintf(`{"mediaType":"%s","verificationMaterial":{"publicKey":{"hint":"%064x"}},"dsseEnvelope":{"payload":"e30=","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"AA=="}]}}`, sigstoreMediaType, n))
	return writeFile(t, dir, fmt.Sprintf("sigstore-%d.json", n), string(body)), body
}

type attachFix struct {
	reg    *ocitest.Registry
	host   string
	target string
	root   string
	lock   string
	dir    string
}

// newAttachFix pushes the root of a set to a mirror, as push-root does.
func newAttachFix(t *testing.T) *attachFix {
	t.Helper()
	reg, host := newMirror(t)
	file, _ := cellSet(t)
	r := decodeRoot(t, mustRun(t, "", "push-root", "--role", "cell", "--target", "dev-cell-1", "--set", file, "--registry", host))
	dir := t.TempDir()
	return &attachFix{reg: reg, host: host, target: "dev-cell-1", root: r.Digest, lock: filepath.Join(dir, "build", "bundle-attach.lock"), dir: dir}
}

func (f *attachFix) args(bundleFile string, extra ...string) []string {
	return append([]string{"attach", "--target", f.target, "--digest", f.root, "--bundle", bundleFile, "--registry", f.host, "--lock", f.lock}, extra...)
}

func (f *attachFix) store(t *testing.T) *ocistore.Store {
	t.Helper()
	s, err := ocistore.New(ocistore.Client{Base: f.host})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func puts(reg *ocitest.Registry) int {
	n := 0
	for _, r := range reg.Requests() {
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			n++
		}
	}
	return n
}

// attach pushes the cosign bundle as a referrer of the root, in the layout of the cosign spike.
func TestAttachReferrer(t *testing.T) {
	f := newAttachFix(t)
	file, body := sigstoreFile(t, f.dir, 1)
	out := mustRun(t, "", f.args(file)...)
	var res map[string]string
	if err := json.Unmarshal([]byte(out), &res); err != nil || res["root"] != f.root || res["referrer"] == "" {
		t.Fatalf("output %q: %v", out, err)
	}
	repo := "bundles/dev-cell-1/root"
	raw, ok := f.reg.Manifest(repo, res["referrer"])
	if !ok {
		t.Fatal("referrer manifest is missing")
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	rootRaw, _ := f.reg.Manifest(repo, f.root)
	if m.MediaType != ocispec.MediaTypeImageManifest || m.ArtifactType != "application/vnd.dev.sigstore.bundle.v0.3+json" {
		t.Errorf("media type %q, artifact type %q", m.MediaType, m.ArtifactType)
	}
	if m.Subject == nil || m.Subject.Digest.String() != f.root || m.Subject.Size != int64(len(rootRaw)) || m.Subject.MediaType != bundle.MediaTypeManifest {
		t.Errorf("subject = %+v", m.Subject)
	}
	if len(m.Layers) != 1 || m.Layers[0].MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json" || m.Layers[0].Digest.String() != ocitest.Digest(body) || m.Layers[0].Size != int64(len(body)) {
		t.Errorf("layers = %+v", m.Layers)
	}
	if m.Config.MediaType != "application/vnd.oci.empty.v1+json" || m.Config.Size != 2 {
		t.Errorf("config = %+v", m.Config)
	}
	if m.Annotations["dev.sigstore.bundle.content"] != "dsse-envelope" || m.Annotations["dev.sigstore.bundle.predicateType"] != "https://cell.poc.internal/bundle-set/v1" {
		t.Errorf("annotations = %v", m.Annotations)
	}
	if l, ok := f.reg.Blob(repo, m.Layers[0].Digest.String()); !ok || !bytes.Equal(l, body) {
		t.Error("the layer is not the file")
	}
	if _, ok := f.reg.Blob(repo, m.Config.Digest.String()); !ok {
		t.Error("the config blob is missing")
	}
	refs, err := f.store(t).Referrers(t.Context(), repo, f.root)
	if err != nil || len(refs) != 1 || refs[0].Digest.String() != res["referrer"] || refs[0].ArtifactType != m.ArtifactType {
		t.Fatalf("referrers = %+v, %v", refs, err)
	}
	for _, r := range f.reg.Requests() {
		if strings.Contains(r.Path, "/referrers/") {
			t.Fatalf("the referrers API was called: %s", r.Path)
		}
	}

	// A repeat attach changes nothing, and another bundle adds a second referrer.
	before := puts(f.reg)
	if again := mustRun(t, "", f.args(file)...); again != out {
		t.Errorf("repeat output %q, want %q", again, out)
	}
	if n := puts(f.reg) - before; n != 0 {
		t.Errorf("a repeat attach wrote %d times", n)
	}
	file2, _ := sigstoreFile(t, f.dir, 2)
	mustRun(t, "", f.args(file2)...)
	if refs, err := f.store(t).Referrers(t.Context(), repo, f.root); err != nil || len(refs) != 2 {
		t.Fatalf("referrers after two bundles = %d, %v", len(refs), err)
	}
}

// The attach reads the index and the root, so its client must not be write-only.
func TestAttachUsesReadingClient(t *testing.T) {
	f := newAttachFix(t)
	file, _ := sigstoreFile(t, f.dir, 1)
	before := len(f.reg.Requests())
	mustRun(t, "", f.args(file)...)
	var tagGets, rootGets int
	for _, r := range f.reg.Requests()[before:] {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			continue
		}
		if strings.Contains(r.Path, "/manifests/sha256-") {
			tagGets++
		}
		if strings.HasSuffix(r.Path, "/manifests/"+f.root) {
			rootGets++
		}
	}
	if tagGets == 0 || rootGets == 0 {
		t.Fatalf("no read of the index (%d) or of the root (%d)", tagGets, rootGets)
	}
}

// Two attaches never run at once on this Mac: the second one waits for the lock file, and gives up
// without a request when the lock stays held.
func TestAttachTakesLock(t *testing.T) {
	f := newAttachFix(t)
	file, _ := sigstoreFile(t, f.dir, 1)
	if err := os.MkdirAll(filepath.Dir(f.lock), 0o755); err != nil {
		t.Fatal(err)
	}
	held, err := os.OpenFile(f.lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	before := len(f.reg.Requests())
	code, out := runCLI(t, "", f.args(file, "--lock-wait", "150ms")...)
	if code != 1 {
		t.Fatalf("exit %d with the lock held: %s", code, out)
	}
	if msg := errorLine(t, out); !strings.Contains(msg, "lock") {
		t.Errorf("error %q does not name the lock", msg)
	}
	if n := len(f.reg.Requests()) - before; n != 0 {
		t.Errorf("%d requests reached the mirror while the lock was held", n)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "", f.args(file, "--lock-wait", "150ms")...)
	// The lock is free again after the attach.
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("the attach kept the lock: %v", err)
	}
}

func TestAttachManyInTurn(t *testing.T) {
	f := newAttachFix(t)
	var wg sync.WaitGroup
	errs := make(chan string, 6)
	for i := 1; i <= 6; i++ {
		file, _ := sigstoreFile(t, f.dir, i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out bytes.Buffer
			if code := execute(t.Context(), f.args(file), strings.NewReader(""), &out); code != 0 {
				errs <- out.String()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("attach failed: %s", e)
	}
	if refs, err := f.store(t).Referrers(t.Context(), "bundles/dev-cell-1/root", f.root); err != nil || len(refs) != 6 {
		t.Fatalf("referrers = %d, %v", len(refs), err)
	}
}

// afterPut runs fn after each PUT of the fallback index of the root.
type afterPut struct {
	base http.RoundTripper
	tag  string
	fn   func(n int)
	mu   sync.Mutex
	n    int
}

func (a *afterPut) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := a.base.RoundTrip(req)
	if err == nil && req.Method == http.MethodPut && strings.HasSuffix(req.URL.Path, "/manifests/"+a.tag) {
		a.mu.Lock()
		a.n++
		n := a.n
		a.mu.Unlock()
		a.fn(n)
	}
	return resp, err
}

func (a *afterPut) writes() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

func useTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	storeTransport = rt
	t.Cleanup(func() { storeTransport = nil })
}

// Another process can replace the index between the write and the read back. The attach tries once more.
func TestAttachRetriesOnceOnLost(t *testing.T) {
	other := []byte(`{"schemaVersion":2,"mediaType":"` + mtIndex + `","manifests":[]}`)
	t.Run("lost once", func(t *testing.T) {
		f := newAttachFix(t)
		file, _ := sigstoreFile(t, f.dir, 1)
		tag, _ := ocistore.FallbackTag(f.root)
		rt := &afterPut{base: http.DefaultTransport, tag: tag, fn: func(n int) {
			if n == 1 {
				f.reg.SeedManifest("bundles/dev-cell-1/root", tag, mtIndex, other)
			}
		}}
		useTransport(t, rt)
		mustRun(t, "", f.args(file)...)
		if rt.writes() != 2 {
			t.Errorf("index written %d times, want 2", rt.writes())
		}
		if refs, err := f.store(t).Referrers(t.Context(), "bundles/dev-cell-1/root", f.root); err != nil || len(refs) != 1 {
			t.Fatalf("referrers = %d, %v", len(refs), err)
		}
	})
	t.Run("lost twice", func(t *testing.T) {
		f := newAttachFix(t)
		file, _ := sigstoreFile(t, f.dir, 1)
		tag, _ := ocistore.FallbackTag(f.root)
		rt := &afterPut{base: http.DefaultTransport, tag: tag, fn: func(int) {
			f.reg.SeedManifest("bundles/dev-cell-1/root", tag, mtIndex, other)
		}}
		useTransport(t, rt)
		code, out := runCLI(t, "", f.args(file)...)
		if code != 1 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if msg := errorLine(t, out); !strings.Contains(msg, "lost") {
			t.Errorf("error %q does not say that the entry was lost", msg)
		}
		if rt.writes() != 2 {
			t.Errorf("index written %d times, want 2 (one retry)", rt.writes())
		}
	})
}

func TestAttachRefusals(t *testing.T) {
	f := newAttachFix(t)
	good, _ := sigstoreFile(t, f.dir, 1)
	dir := t.TempDir()
	cases := map[string][]string{
		"bad digest":      f.args(good, "--digest", "sha256:zz"),
		"no digest":       {"attach", "--target", f.target, "--bundle", good, "--registry", f.host, "--lock", f.lock},
		"no bundle":       {"attach", "--target", f.target, "--digest", f.root, "--registry", f.host, "--lock", f.lock},
		"missing bundle":  f.args(filepath.Join(dir, "none.json")),
		"not json":        f.args(writeFile(t, dir, "a.json", "not json")),
		"wrong media":     f.args(writeFile(t, dir, "b.json", `{"mediaType":"application/json","dsseEnvelope":{}}`)),
		"no envelope":     f.args(writeFile(t, dir, "c.json", `{"mediaType":"`+sigstoreMediaType+`"}`)),
		"too large":       f.args(writeFile(t, dir, "d.json", `{"mediaType":"`+sigstoreMediaType+`","dsseEnvelope":{"x":"`+strings.Repeat("a", maxSigstoreBundle)+`"}}`)),
		"root not there":  f.args(good, "--digest", ocitest.Digest([]byte("nothing"))),
		"another host":    f.args(good, "--registry", "10.0.0.5:5001"),
		"unknown target":  f.args(good, "--target", "dev-cell-2"),
		"target not name": f.args(good, "--target", "Dev_Cell"),
	}
	for name, args := range cases {
		before := puts(f.reg)
		code, out := runCLI(t, "", args...)
		if code != 1 {
			t.Errorf("%s: exit %d: %s", name, code, out)
			continue
		}
		errorLine(t, out)
		if n := puts(f.reg) - before; n != 0 {
			t.Errorf("%s: %d writes reached the mirror", name, n)
		}
	}
}

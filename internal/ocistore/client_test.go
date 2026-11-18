package ocistore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore/ocitest"
)

const (
	testRepo  = "bundles/dev-cell-1/argocd"
	mtOCIMan  = "application/vnd.oci.image.manifest.v1+json"
	mtOCIIdx  = "application/vnd.oci.image.index.v1+json"
	mtOctet   = "application/octet-stream"
	bigLimit  = 1 << 20
	smallSize = 1024
)

func newStore(t *testing.T, reg *ocitest.Registry, mut ...func(*Client)) *Store {
	t.Helper()
	c := Client{Base: reg.URL(), MaxManifest: bigLimit, MaxBlob: bigLimit}
	for _, m := range mut {
		m(&c)
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func is(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestManifestDigestVerified(t *testing.T) {
	ctx := context.Background()
	t.Run("manifest", func(t *testing.T) {
		reg := ocitest.NewRegistry(t)
		s := newStore(t, reg)
		data := []byte(`{"schemaVersion":2}`)
		d := reg.SeedManifest(testRepo, "", mtOCIMan, data)
		got, err := s.Manifest(ctx, testRepo, d)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("Manifest = %q, %v", got, err)
		}
		reg.Corrupt(d)
		_, err = s.Manifest(ctx, testRepo, d)
		is(t, err, ErrDigestMismatch)
	})
	t.Run("blob", func(t *testing.T) {
		reg := ocitest.NewRegistry(t)
		s := newStore(t, reg)
		data := []byte("layer bytes")
		d := reg.Seed(testRepo, data)
		got, err := s.Blob(ctx, testRepo, d)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("Blob = %q, %v", got, err)
		}
		reg.Corrupt(d)
		_, err = s.Blob(ctx, testRepo, d)
		is(t, err, ErrDigestMismatch)
	})
}

func TestNotFoundIsTyped(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	d := ocitest.Digest([]byte("nothing"))
	_, err := s.Blob(ctx, testRepo, d)
	is(t, err, ErrNotFound)
	_, err = s.Manifest(ctx, testRepo, d)
	is(t, err, ErrNotFound)
	_, err = s.Resolve(ctx, testRepo, "nope")
	is(t, err, ErrNotFound)
	ok, err := s.HasBlob(ctx, testRepo, d)
	if ok || err != nil {
		t.Fatalf("HasBlob = %v, %v", ok, err)
	}
}

func TestInputsAreChecked(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	for _, repo := range []string{"", "Upper", "a//b", "../x", "a b", "a@b"} {
		if _, err := s.Blob(ctx, repo, ocitest.Digest(nil)); err == nil {
			t.Errorf("repository %q was accepted", repo)
		}
	}
	for _, d := range []string{"", "sha256:abc", "sha512:" + strings.Repeat("a", 128), "sha256:" + strings.Repeat("A", 64)} {
		if _, err := s.Blob(ctx, testRepo, d); err == nil {
			t.Errorf("digest %q was accepted", d)
		}
	}
	for _, base := range []string{"", "https://x:1", "x:1/path", "http://x:1/v2"} {
		if _, err := New(Client{Base: base}); err == nil {
			t.Errorf("base %q was accepted", base)
		}
	}
}

// countTransport counts the bytes that the client reads from response bodies.
type countTransport struct {
	base http.RoundTripper
	read atomic.Int64
}

type countBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b countBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

func (c *countTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err == nil {
		resp.Body = countBody{resp.Body, &c.read}
	}
	return resp, err
}

func TestBlobTooLarge(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	over := bytes.Repeat([]byte{'x'}, smallSize+1)
	big := bytes.Repeat([]byte{'y'}, 1<<20)
	exact := bytes.Repeat([]byte{'z'}, smallSize)
	dOver, dBig, dExact := reg.Seed(testRepo, over), reg.Seed(testRepo, big), reg.Seed(testRepo, exact)

	ct := &countTransport{base: http.DefaultTransport.(*http.Transport).Clone()}
	s := newStore(t, reg, func(c *Client) { c.MaxBlob = smallSize; c.Transport = ct })

	got, err := s.Blob(ctx, testRepo, dExact)
	if err != nil || !bytes.Equal(got, exact) {
		t.Fatalf("a blob at the limit failed: %v", err)
	}
	for name, d := range map[string]string{"one over": dOver, "a megabyte": dBig} {
		ct.read.Store(0)
		_, err := s.Blob(ctx, testRepo, d)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("%s: error = %v, want ErrTooLarge", name, err)
		}
		if n := ct.read.Load(); n > smallSize+1 {
			t.Fatalf("%s: the client read %d bytes, want at most %d", name, n, smallSize+1)
		}
	}
}

func TestManifestTooLarge(t *testing.T) {
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg, func(c *Client) { c.MaxManifest = 64 })
	d := reg.SeedManifest(testRepo, "", mtOCIMan, []byte(`{"schemaVersion":2,"pad":"`+strings.Repeat("p", 100)+`"}`))
	_, err := s.Manifest(context.Background(), testRepo, d)
	is(t, err, ErrTooLarge)
	err = s.PushBlob(context.Background(), testRepo, ocitest.Digest(make([]byte, 2000)), make([]byte, 2000))
	if err != nil {
		t.Fatalf("a push below MaxBlob failed: %v", err)
	}
	_, err = s.PushManifest(context.Background(), testRepo, "t", mtOCIMan, bytes.Repeat([]byte{' '}, 65))
	is(t, err, ErrTooLarge)
}

func TestPushIdempotent(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	data := []byte("pushed twice")
	d := ocitest.Digest(data)

	ok, err := s.HasBlob(ctx, testRepo, d)
	if ok || err != nil {
		t.Fatalf("HasBlob before = %v, %v", ok, err)
	}
	for i := 0; i < 2; i++ {
		if err := s.PushBlob(ctx, testRepo, d, data); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	ok, err = s.HasBlob(ctx, testRepo, d)
	if !ok || err != nil {
		t.Fatalf("HasBlob after = %v, %v", ok, err)
	}
	got, err := s.Blob(ctx, testRepo, d)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("Blob = %q, %v", got, err)
	}
	posts := 0
	for _, r := range reg.Requests() {
		if r.Method == http.MethodPost {
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("%d uploads started, want 1", posts)
	}
	// A new Store pushes the same blob without a new upload.
	if err := newStore(t, reg).PushBlob(ctx, testRepo, d, data); err != nil {
		t.Fatal(err)
	}
	// A blob that does not match its digest is refused before any request.
	before := len(reg.Requests())
	is(t, s.PushBlob(ctx, testRepo, ocitest.Digest([]byte("other")), data), ErrDigestMismatch)
	if len(reg.Requests()) != before {
		t.Fatal("a mismatched blob reached the registry")
	}
}

func TestPushManifestByTag(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	data := []byte(`{"schemaVersion":2,"mediaType":"` + mtOCIMan + `"}`)
	want := ocitest.Digest(data)

	d, err := s.PushManifest(ctx, testRepo, "v1", mtOCIMan, data)
	if err != nil || d != want {
		t.Fatalf("PushManifest = %q, %v", d, err)
	}
	if got, ok := reg.Manifest(testRepo, "v1"); !ok || !bytes.Equal(got, data) {
		t.Fatal("the tag does not hold the manifest")
	}
	// Same digest under a second tag, from the same Store: it must reach the registry.
	if _, err := s.PushManifest(ctx, testRepo, "v2", mtOCIMan, data); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Manifest(testRepo, "v2"); !ok {
		t.Fatal("the second tag was skipped")
	}
	// By digest, and a push of existing content succeeds.
	for _, ref := range []string{want, "", "v1"} {
		if d, err := s.PushManifest(ctx, testRepo, ref, mtOCIMan, data); err != nil || d != want {
			t.Fatalf("PushManifest(%q) = %q, %v", ref, d, err)
		}
	}
	// A digest reference that does not match the data is a mismatch.
	_, err = s.PushManifest(ctx, testRepo, ocitest.Digest([]byte("x")), mtOCIMan, data)
	is(t, err, ErrDigestMismatch)
	if _, err := s.PushManifest(ctx, testRepo, "bad tag", mtOCIMan, data); err == nil {
		t.Fatal("a tag with a space was accepted")
	}
	if _, err := s.PushManifest(ctx, testRepo, "v3", mtOctet, data); err == nil {
		t.Fatal("a blob media type was accepted for a manifest")
	}
	// The tag moves when new content is pushed.
	next := []byte(`{"schemaVersion":2,"mediaType":"` + mtOCIMan + `","x":1}`)
	if _, err := s.PushManifest(ctx, testRepo, "v1", mtOCIMan, next); err != nil {
		t.Fatal(err)
	}
	if got, _ := reg.Manifest(testRepo, "v1"); !bytes.Equal(got, next) {
		t.Fatal("the tag did not move")
	}
}

func TestResolve(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	data := []byte(`{"schemaVersion":2}`)
	want := reg.SeedManifest(testRepo, "stable", mtOCIMan, data)
	got, err := s.Resolve(ctx, testRepo, "stable")
	if err != nil || got != want {
		t.Fatalf("Resolve = %q, %v, want %q", got, err, want)
	}
	if _, err := s.Resolve(ctx, testRepo, "bad tag"); err == nil {
		t.Fatal("a bad tag was accepted")
	}
}

func TestTokenHeader(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	d := reg.Seed(testRepo, []byte("secret data"))
	calls := 0
	s := newStore(t, reg, func(c *Client) {
		c.Token = func() (string, error) { calls++; return "tok-1", nil }
	})
	if _, err := s.Blob(ctx, testRepo, d); err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HasBlob(ctx, testRepo, d); err != nil {
		t.Fatal(err)
	}
	reqs := reg.Requests()
	if len(reqs) < 3 {
		t.Fatalf("%d requests", len(reqs))
	}
	for _, r := range reqs {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-1" {
			t.Errorf("%s %s sent Authorization %q", r.Method, r.Path, got)
		}
	}
	if calls < len(reqs) {
		t.Errorf("the token function ran %d times for %d requests", calls, len(reqs))
	}

	t.Run("no token function", func(t *testing.T) {
		reg := ocitest.NewRegistry(t)
		s := newStore(t, reg)
		if err := s.Ping(ctx); err != nil {
			t.Fatal(err)
		}
		if got := reg.Requests()[0].Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q", got)
		}
	})
	t.Run("token error stops the request", func(t *testing.T) {
		reg := ocitest.NewRegistry(t)
		boom := errors.New("no token today")
		s := newStore(t, reg, func(c *Client) { c.Token = func() (string, error) { return "", boom } })
		is(t, s.Ping(ctx), boom)
		if len(reg.Requests()) != 0 {
			t.Fatal("a request went out without a token")
		}
	})
	t.Run("other host", func(t *testing.T) {
		var hits atomic.Int64
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if r.Header.Get("Authorization") != "" {
				t.Error("the token reached another host")
			}
		}))
		defer other.Close()
		s := newStore(t, ocitest.NewRegistry(t), func(c *Client) {
			c.Token = func() (string, error) { return "tok-2", nil }
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, other.URL+"/v2/", nil)
		req.Header.Set("Authorization", "Bearer caller-set")
		_, err := s.hc.Transport.RoundTrip(req)
		is(t, err, ErrOffHost)
		if hits.Load() != 0 {
			t.Fatal("a request reached another host")
		}
	})
}

func TestNoRedirectOffHost(t *testing.T) {
	ctx := context.Background()
	other := ocitest.NewRegistry(t)
	reg := ocitest.NewRegistry(t)
	data := []byte("redirected")
	d := reg.Seed(testRepo, data)
	other.Seed(testRepo, data)
	reg.RedirectTo(other.URL())
	s := newStore(t, reg, func(c *Client) {
		c.Token = func() (string, error) { return "tok-3", nil }
	})
	_, err := s.Blob(ctx, testRepo, d)
	is(t, err, ErrOffHost)
	if !strings.Contains(err.Error(), "redirect to") {
		t.Fatalf("the redirect check did not refuse the redirect: %v", err)
	}
	if n := len(other.Requests()); n != 0 {
		t.Fatalf("the other host got %d requests", n)
	}
	md := reg.SeedManifest(testRepo, "", mtOCIMan, []byte(`{}`))
	_, err = s.Manifest(ctx, testRepo, md)
	is(t, err, ErrOffHost)
	_, err = s.Resolve(ctx, testRepo, "t")
	if err == nil {
		t.Fatal("Resolve followed nothing and still succeeded")
	}
	ok, err := s.HasBlob(ctx, testRepo, d)
	is(t, err, ErrOffHost)
	if ok || len(other.Requests()) != 0 {
		t.Fatal("HasBlob left the host")
	}

	t.Run("same host is followed", func(t *testing.T) {
		reg := ocitest.NewRegistry(t)
		d := reg.Seed(testRepo, data)
		reg.RedirectTo(reg.URL())
		s := newStore(t, reg, func(c *Client) {
			c.Token = func() (string, error) { return "tok-3", nil }
		})
		got, err := s.Blob(ctx, testRepo, d)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("Blob = %q, %v", got, err)
		}
		for _, r := range reg.Requests() {
			if r.Header.Get("Authorization") != "Bearer tok-3" {
				t.Errorf("%s lost the token", r.Path)
			}
		}
	})
}

func TestContentEncodingRefused(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	d := reg.Seed(testRepo, []byte("plain"))
	md := reg.SeedManifest(testRepo, "t", mtOCIMan, []byte(`{}`))
	s := newStore(t, reg)

	if _, err := s.Blob(ctx, testRepo, d); err != nil {
		t.Fatal(err)
	}
	for _, r := range reg.Requests() {
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("%s %s sent Accept-Encoding %q", r.Method, r.Path, got)
		}
	}
	for _, enc := range []string{"gzip", "zstd", "deflate", "br", "identity"} {
		reg.Encode(enc)
		_, err := s.Blob(ctx, testRepo, d)
		if !errors.Is(err, ErrContentEncoding) {
			t.Errorf("Blob with %s: %v", enc, err)
		}
		_, err = s.Manifest(ctx, testRepo, md)
		if !errors.Is(err, ErrContentEncoding) {
			t.Errorf("Manifest with %s: %v", enc, err)
		}
		_, err = s.Resolve(ctx, testRepo, "t")
		if !errors.Is(err, ErrContentEncoding) {
			t.Errorf("Resolve with %s: %v", enc, err)
		}
		if _, err := s.HasBlob(ctx, testRepo, d); !errors.Is(err, ErrContentEncoding) {
			t.Errorf("HasBlob with %s: %v", enc, err)
		}
	}
}

func TestDeniedIsTyped(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{http.StatusForbidden, http.StatusUnauthorized} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			reg := ocitest.NewRegistry(t)
			d := reg.Seed(testRepo, []byte("x"))
			s := newStore(t, reg)
			reg.Deny(status)
			_, err := s.Blob(ctx, testRepo, d)
			is(t, err, ErrDenied)
			if n := len(reg.Requests()); n != 1 {
				t.Fatalf("Blob sent %d requests, want 1 (no retry)", n)
			}
			_, err = s.Manifest(ctx, testRepo, d)
			is(t, err, ErrDenied)
			is(t, s.PushBlob(ctx, testRepo, ocitest.Digest([]byte("n")), []byte("n")), ErrDenied)
			_, err = s.Resolve(ctx, testRepo, "t")
			is(t, err, ErrDenied)
			is(t, s.Ping(ctx), ErrDenied)
			_, err = s.HasBlob(ctx, testRepo, d)
			is(t, err, ErrDenied)
		})
	}
}

func packArtifact(t *testing.T, files map[string][]byte) bundle.Artifact {
	t.Helper()
	a, err := bundle.Pack(files)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func pushArtifact(t *testing.T, s *Store, a bundle.Artifact, tag string) {
	t.Helper()
	ctx := context.Background()
	for _, b := range []struct {
		d    string
		data []byte
	}{{a.ConfigDigest, a.Config}, {a.LayerDigest, a.Layer}} {
		if err := s.PushBlob(ctx, testRepo, b.d, b.data); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := s.PushManifest(ctx, testRepo, tag, bundle.MediaTypeManifest, a.Manifest); err != nil || d != a.Digest {
		t.Fatalf("PushManifest = %q, %v", d, err)
	}
}

func TestFetchOneLayer(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	a := packArtifact(t, map[string][]byte{"app.yaml": []byte("kind: Application\n"), "values.yaml": []byte("a: 1\n")})
	pushArtifact(t, s, a, "v1")

	got, err := Fetch(ctx, s, testRepo, a.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != a.Digest || got.LayerDigest != a.LayerDigest || got.ConfigDigest != a.ConfigDigest ||
		!bytes.Equal(got.Layer, a.Layer) || !bytes.Equal(got.Config, a.Config) || !bytes.Equal(got.Manifest, a.Manifest) {
		t.Fatalf("Fetch result differs: %+v", got)
	}
	files, err := bundle.Unpack(got.Layer, bundle.MaxUnpackedBytes)
	if err != nil || string(files["app.yaml"]) != "kind: Application\n" {
		t.Fatalf("Unpack = %v, %v", files, err)
	}

	t.Run("layer corrupt", func(t *testing.T) {
		reg.Corrupt(a.LayerDigest)
		_, err := Fetch(ctx, s, testRepo, a.Digest)
		is(t, err, ErrDigestMismatch)
	})
}

func seedManifestJSON(t *testing.T, reg *ocitest.Registry, a bundle.Artifact, edit func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(a.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return reg.SeedManifest(testRepo, "", mtOCIMan, b)
}

func TestFetchLayout(t *testing.T) {
	ctx := context.Background()
	a := packArtifact(t, map[string][]byte{"a.yaml": []byte("a: 1\n")})
	layer := func(m map[string]any) map[string]any { return m["layers"].([]any)[0].(map[string]any) }
	cases := map[string]func(m map[string]any){
		"two layers": func(m map[string]any) { m["layers"] = append(m["layers"].([]any), layer(m)) },
		"no layers":  func(m map[string]any) { m["layers"] = []any{} },
		"layer type": func(m map[string]any) { layer(m)["mediaType"] = "application/vnd.oci.image.layer.v1.tar+gzip" },
		"config type": func(m map[string]any) {
			m["config"].(map[string]any)["mediaType"] = "application/vnd.oci.image.config.v1+json"
		},
		"schema":                          func(m map[string]any) { m["schemaVersion"] = 1 },
		"manifest type":                   func(m map[string]any) { m["mediaType"] = "application/vnd.docker.distribution.manifest.v2+json" },
		"layer size larger than the blob": func(m map[string]any) { layer(m)["size"] = layer(m)["size"].(float64) + 1 },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			reg := ocitest.NewRegistry(t)
			s := newStore(t, reg)
			pushArtifact(t, s, a, "v1")
			d := seedManifestJSON(t, reg, a, edit)
			_, err := Fetch(ctx, s, testRepo, d)
			is(t, err, ErrLayout)
		})
	}
}

func TestFetchDeclaredSizeBoundsTheRead(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	a := packArtifact(t, map[string][]byte{"a.yaml": []byte("a: 1\n")})
	pushArtifact(t, s, a, "v1")
	d := seedManifestJSON(t, reg, a, func(m map[string]any) { m["layers"].([]any)[0].(map[string]any)["size"] = 1 })
	_, err := Fetch(ctx, s, testRepo, d)
	is(t, err, ErrTooLarge)
}

func TestFetchRefusesURLs(t *testing.T) {
	ctx := context.Background()
	a := packArtifact(t, map[string][]byte{"a.yaml": []byte("a: 1\n")})
	var hits atomic.Int64
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write(a.Layer)
	}))
	defer foreign.Close()
	for name, edit := range map[string]func(m map[string]any){
		"layer": func(m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["urls"] = []string{foreign.URL + "/layer"}
		},
		"config": func(m map[string]any) {
			m["config"].(map[string]any)["urls"] = []string{foreign.URL + "/config"}
		},
		"subject": func(m map[string]any) {
			m["subject"] = map[string]any{"mediaType": mtOCIMan, "digest": a.Digest, "size": 1, "urls": []string{foreign.URL}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			reg := ocitest.NewRegistry(t)
			s := newStore(t, reg)
			pushArtifact(t, s, a, "v1")
			d := seedManifestJSON(t, reg, a, edit)
			_, err := Fetch(ctx, s, testRepo, d)
			is(t, err, ErrLayout)
			_, err = s.Manifest(ctx, testRepo, d)
			is(t, err, ErrLayout)
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("the foreign host got %d requests", hits.Load())
	}
}

func TestResolverLogsThroughSlog(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)
	var std bytes.Buffer
	stdLogger := logrus.StandardLogger()
	oldOut := stdLogger.Out
	stdLogger.SetOutput(&std)
	defer stdLogger.SetOutput(oldOut)

	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	_, err := s.Resolve(context.Background(), testRepo, "missing")
	is(t, err, ErrNotFound)
	if std.Len() != 0 {
		t.Fatalf("the resolver wrote to the global logrus logger: %q", std.String())
	}
	if !strings.Contains(buf.String(), `"level":"INFO"`) {
		t.Fatalf("no slog record for the failed resolve: %q", buf.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("slog line is not JSON: %q", line)
		}
	}
}

func TestPingAndHasBlob(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	d := reg.Seed(testRepo, []byte("here"))
	if ok, err := s.HasBlob(ctx, testRepo, d); !ok || err != nil {
		t.Fatalf("HasBlob = %v, %v", ok, err)
	}
	dead, err := New(Client{Base: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := dead.Ping(cctx); err == nil {
		t.Fatal("Ping of a closed port succeeded")
	}
}

func referrerManifest(t *testing.T, s *Store, n int) (string, int64) {
	t.Helper()
	data := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","n":%d}`, mtOCIMan, n))
	d, err := s.PushManifest(context.Background(), testRepo, "", mtOCIMan, data)
	if err != nil {
		t.Fatal(err)
	}
	return d, int64(len(data))
}

func TestReferrersFallbackRead(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	s := newStore(t, reg)
	subject := ocitest.Digest([]byte("subject"))

	got, err := s.Referrers(ctx, testRepo, subject)
	if err != nil || len(got) != 0 {
		t.Fatalf("Referrers of nothing = %v, %v", got, err)
	}
	tag, err := FallbackTag(subject)
	if err != nil || tag != "sha256-"+strings.TrimPrefix(subject, "sha256:") {
		t.Fatalf("FallbackTag = %q, %v", tag, err)
	}
	if _, err := FallbackTag("sha256:zz"); err == nil {
		t.Fatal("a bad digest was accepted")
	}
	for _, r := range reg.Requests() {
		if strings.Contains(r.Path, "/referrers/") {
			t.Fatalf("the client called the referrers API: %s", r.Path)
		}
	}

	d, size := referrerManifest(t, s, 1)
	idx := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","manifests":[{"mediaType":"%s","digest":"%s","size":%d,"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","annotations":{"dev.sigstore.bundle.content":"dsse-envelope"}}]}`, mtOCIIdx, mtOCIMan, d, size)
	reg.SeedManifest(testRepo, tag, mtOCIIdx, []byte(idx))
	got, err = s.Referrers(ctx, testRepo, subject)
	if err != nil || len(got) != 1 || got[0].Digest.String() != d || got[0].ArtifactType != "application/vnd.dev.sigstore.bundle.v0.3+json" ||
		got[0].Annotations["dev.sigstore.bundle.content"] != "dsse-envelope" {
		t.Fatalf("Referrers = %+v, %v", got, err)
	}

	t.Run("index with urls", func(t *testing.T) {
		reg := ocitest.NewRegistry(t)
		s := newStore(t, reg)
		idx := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","manifests":[{"mediaType":"%s","digest":"%s","size":1,"urls":["http://127.0.0.1:1/x"]}]}`, mtOCIIdx, mtOCIMan, d)
		reg.SeedManifest(testRepo, tag, mtOCIIdx, []byte(idx))
		_, err := s.Referrers(ctx, testRepo, subject)
		is(t, err, ErrLayout)
	})
	t.Run("not an index", func(t *testing.T) {
		reg := ocitest.NewRegistry(t)
		s := newStore(t, reg)
		reg.SeedManifest(testRepo, tag, mtOCIMan, []byte(`{"schemaVersion":2,"mediaType":"`+mtOCIMan+`"}`))
		_, err := s.Referrers(ctx, testRepo, subject)
		is(t, err, ErrLayout)
	})
}

func TestAttachSerialized(t *testing.T) {
	ctx := context.Background()
	reg := ocitest.NewRegistry(t)
	reg.Delay(5 * time.Millisecond)
	s := newStore(t, reg)
	subject := ocitest.Digest([]byte("subject"))
	const n = 12

	descs := make([]Referrer, n)
	for i := range descs {
		d, size := referrerManifest(t, s, i)
		descs[i] = Referrer{Digest: d, Size: size, MediaType: mtOCIMan,
			ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json",
			Annotations:  map[string]string{"n": fmt.Sprint(i)}}
	}
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for _, r := range descs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine has its own Store, as separate callers would.
			errs <- newStore(t, reg).AttachReferrer(ctx, testRepo, subject, r)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Referrers(ctx, testRepo, subject)
	if err != nil || len(got) != n {
		t.Fatalf("Referrers = %d entries, %v; want %d", len(got), err, n)
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g.Digest.String()] = true
	}
	for _, r := range descs {
		if !seen[r.Digest] {
			t.Errorf("referrer %s was lost", r.Digest)
		}
	}
	// A repeat attach changes nothing.
	before := len(reg.Requests())
	if err := s.AttachReferrer(ctx, testRepo, subject, descs[0]); err != nil {
		t.Fatal(err)
	}
	got2, _ := s.Referrers(ctx, testRepo, subject)
	if len(got2) != n {
		t.Fatalf("a repeat attach changed the index: %d entries", len(got2))
	}
	for _, r := range reg.Requests()[before:] {
		if r.Method == http.MethodPut {
			t.Fatal("a repeat attach wrote the index again")
		}
	}
	// A referrer with a bad digest is refused.
	if err := s.AttachReferrer(ctx, testRepo, subject, Referrer{Digest: "sha256:x", Size: 1, MediaType: mtOCIMan}); err == nil {
		t.Fatal("a bad referrer was accepted")
	}
}

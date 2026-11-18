package cellproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTokenClientFixture(t *testing.T, upstream *recordingUpstream, file string) *httptest.Server {
	t.Helper()
	h, err := NewTokenClient(TokenClientConfig{Upstream: upstream.hostPort(), TokenFile: file, Log: nil})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTokenClientAddsBearer(t *testing.T) {
	up := newRecordingUpstream(t)
	srv := newTokenClientFixture(t, up, writeTokenFile(t, "projected-token\n"))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+pathManifest, nil)
	// A token that the caller sends is replaced.
	req.Header.Set("Authorization", "Bearer caller-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	hits := up.got()
	if resp.StatusCode != http.StatusOK || len(hits) != 1 || hits[0].Authorization != "Bearer projected-token" || hits[0].URI != pathManifest {
		t.Fatalf("status %d, hits %+v, want one request with the token of the file", resp.StatusCode, hits)
	}
}

func TestTokenClientRereadsFile(t *testing.T) {
	up := newRecordingUpstream(t)
	file := writeTokenFile(t, "first")
	srv := newTokenClientFixture(t, up, file)
	get := func() {
		resp, err := http.Get(srv.URL + "/v2/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	get()
	if err := os.WriteFile(file, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	get()
	hits := up.got()
	if len(hits) != 2 || hits[0].Authorization != "Bearer first" || hits[1].Authorization != "Bearer second" {
		t.Fatalf("hits %+v, want the old token and then the rotated token", hits)
	}
}

func TestTokenClientSendsOnlyToUpstream(t *testing.T) {
	up, other := newRecordingUpstream(t), newRecordingUpstream(t)
	srv := newTokenClientFixture(t, up, writeTokenFile(t, "projected-token"))
	// Origin-form with another Host header, and absolute-form with another host.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/", nil)
	req.Host = other.hostPort()
	if resp, err := http.DefaultClient.Do(req); err == nil {
		_ = resp.Body.Close()
	}
	conn := strings.TrimPrefix(srv.URL, "http://")
	absolute, _ := http.NewRequest(http.MethodGet, other.srv.URL+"/v2/", nil)
	tr := &http.Transport{Proxy: http.ProxyURL(mustURL(t, "http://"+conn))}
	if resp, err := (&http.Client{Transport: tr}).Do(absolute); err == nil {
		_ = resp.Body.Close()
	}
	if n := len(other.got()); n != 0 {
		t.Fatalf("another host got %d requests: %+v", n, other.got())
	}
	if n := len(up.got()); n != 2 {
		t.Fatalf("upstream got %d requests, want 2", n)
	}
}

func TestTokenClientNoToken(t *testing.T) {
	up := newRecordingUpstream(t)
	for name, file := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "none"),
		"empty":   writeTokenFile(t, "\n"),
		"newline": writeTokenFile(t, "a\nb"),
	} {
		t.Run(name, func(t *testing.T) {
			srv := newTokenClientFixture(t, up, file)
			resp, err := http.Get(srv.URL + "/v2/")
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable || len(up.got()) != 0 {
				t.Fatalf("status %d, upstream hits %d, want 503 and none", resp.StatusCode, len(up.got()))
			}
		})
	}
}

func TestTokenClientConfigErrors(t *testing.T) {
	for name, c := range map[string]TokenClientConfig{
		"no upstream": {TokenFile: "x"},
		"no file":     {Upstream: "127.0.0.1:1"},
	} {
		if _, err := NewTokenClient(c); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestTokenClientSlowUpstream(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	defer slow.Close()
	h, err := NewTokenClient(TokenClientConfig{Upstream: strings.TrimPrefix(slow.URL, "http://"), TokenFile: writeTokenFile(t, "tok"), UpstreamTimeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	start := time.Now()
	resp, err := http.Get(srv.URL + "/v2/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || time.Since(start) > time.Second {
		t.Fatalf("status %d after %v, want 503 within the timeout", resp.StatusCode, time.Since(start))
	}
}

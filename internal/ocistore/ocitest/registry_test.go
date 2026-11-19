package ocitest

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func get(t *testing.T, client *http.Client, method, url string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestRegistryBlobAndManifest(t *testing.T) {
	r := NewRegistry(t)
	base := "http://" + r.URL()
	d := r.Seed("a/b", []byte("blob"))
	resp, body := get(t, http.DefaultClient, http.MethodGet, base+"/v2/a/b/blobs/"+d)
	if resp.StatusCode != 200 || string(body) != "blob" || resp.Header.Get("Docker-Content-Digest") != d {
		t.Fatalf("blob read: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	md := r.SeedManifest("a/b", "v1", "application/vnd.oci.image.manifest.v1+json", []byte(`{}`))
	for _, ref := range []string{"v1", md} {
		resp, body = get(t, http.DefaultClient, http.MethodGet, base+"/v2/a/b/manifests/"+ref)
		if resp.StatusCode != 200 || string(body) != "{}" {
			t.Fatalf("manifest %s: %d %q", ref, resp.StatusCode, body)
		}
	}
	resp, _ = get(t, http.DefaultClient, http.MethodHead, base+"/v2/a/b/manifests/v1")
	if resp.Header.Get("Docker-Content-Digest") != md || resp.ContentLength != 2 {
		t.Fatalf("head: %v %d", resp.Header, resp.ContentLength)
	}
	resp, _ = get(t, http.DefaultClient, http.MethodGet, base+"/v2/a/b/referrers/"+md)
	if resp.StatusCode != 404 {
		t.Fatalf("referrers API must not exist, got %d", resp.StatusCode)
	}
	if n := len(r.Requests()); n != 5 {
		t.Fatalf("recorded %d requests, want 5", n)
	}
}

func TestRegistryUploadAndPut(t *testing.T) {
	r := NewRegistry(t)
	base := "http://" + r.URL()
	resp, _ := get(t, http.DefaultClient, http.MethodPost, base+"/v2/x/blobs/uploads/")
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 202 || loc == "" {
		t.Fatalf("post: %d %q", resp.StatusCode, loc)
	}
	d := Digest([]byte("data"))
	req, _ := http.NewRequest(http.MethodPut, base+loc+"?digest="+d, strings.NewReader("data"))
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 201 {
		t.Fatalf("put: %d", resp2.StatusCode)
	}
	bad, _ := http.NewRequest(http.MethodPut, base+loc+"?digest="+d, strings.NewReader("data"))
	resp3, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 404 {
		t.Fatalf("a finished upload must be unknown, got %d", resp3.StatusCode)
	}
}

func TestRegistryCorruptMissingDenyEncode(t *testing.T) {
	r := NewRegistry(t)
	base := "http://" + r.URL()
	d := r.Seed("n", []byte("abc"))
	r.Corrupt(d)
	_, body := get(t, http.DefaultClient, http.MethodGet, base+"/v2/n/blobs/"+d)
	if string(body) == "abc" || len(body) != 3 {
		t.Fatalf("corrupt body %q", body)
	}
	r.Missing(d)
	if resp, _ := get(t, http.DefaultClient, http.MethodGet, base+"/v2/n/blobs/"+d); resp.StatusCode != 404 {
		t.Fatalf("missing: %d", resp.StatusCode)
	}
	r.Deny(403)
	resp, _ := get(t, http.DefaultClient, http.MethodGet, base+"/v2/")
	if resp.StatusCode != 403 || resp.Header.Get("WWW-Authenticate") != "" {
		t.Fatalf("deny: %d %v", resp.StatusCode, resp.Header)
	}
	r.Deny(0)
	r.Encode("gzip")
	resp, _ = get(t, http.DefaultClient, http.MethodGet, base+"/v2/")
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("encode: %v", resp.Header)
	}
}

func TestRegistryRedirect(t *testing.T) {
	other := NewRegistry(t)
	r := NewRegistry(t)
	d := other.Seed("n", []byte("far"))
	r.RedirectTo(other.URL())
	_, body := get(t, http.DefaultClient, http.MethodGet, "http://"+r.URL()+"/v2/n/blobs/"+d)
	if string(body) != "far" {
		t.Fatalf("redirected body %q", body)
	}
	self := NewRegistry(t)
	d = self.Seed("n", []byte("near"))
	self.RedirectTo(self.URL())
	_, body = get(t, http.DefaultClient, http.MethodGet, "http://"+self.URL()+"/v2/n/blobs/"+d)
	if string(body) != "near" {
		t.Fatalf("same-host redirect body %q", body)
	}
}

func TestRegistryDenyReadsAndAccept(t *testing.T) {
	r := NewRegistry(t)
	base := "http://" + r.URL()
	idx := "application/vnd.oci.image.index.v1+json"
	d := r.SeedManifest("n", "t", idx, []byte(`{}`))
	for _, c := range []struct {
		accept string
		want   int
	}{{"", 200}, {idx, 200}, {"application/vnd.oci.image.manifest.v1+json, */*", 404}} {
		req, _ := http.NewRequest(http.MethodGet, base+"/v2/n/manifests/"+d, nil)
		if c.accept != "" {
			req.Header.Set("Accept", c.accept)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Fatalf("Accept %q: %d, want %d", c.accept, resp.StatusCode, c.want)
		}
	}
	r.DenyReads(403)
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if resp, _ := get(t, http.DefaultClient, m, base+"/v2/n/manifests/t"); resp.StatusCode != 403 {
			t.Fatalf("%s: %d", m, resp.StatusCode)
		}
	}
	if resp, _ := get(t, http.DefaultClient, http.MethodPost, base+"/v2/n/blobs/uploads/"); resp.StatusCode != 202 {
		t.Fatalf("POST: %d", resp.StatusCode)
	}
}

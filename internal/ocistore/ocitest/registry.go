// Package ocitest is an in-process OCI registry for tests. It speaks the part of the distribution
// API that a bundle store needs: blob upload, blob and manifest reads, tags and digests. It has no
// referrers API, like Distribution 3.1.2, so a client must use the fallback tag.
package ocitest

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// redirectPrefix marks a path that this registry serves without a further redirect.
const redirectPrefix = "/redirected"

// Request is one request that the registry received.
type Request struct {
	Method string
	Path   string
	Header http.Header
}

type manifest struct {
	mediaType string
	data      []byte
}

type repo struct {
	blobs     map[string][]byte
	manifests map[string]manifest // by tag and by digest
}

// Registry is a test registry. Make one with NewRegistry.
type Registry struct {
	srv *httptest.Server

	mu         sync.Mutex
	repos      map[string]*repo
	requests   []Request
	corrupt    map[string]bool
	missing    map[string]bool
	redirect   string
	deny       int
	denyReads  int
	noDigest   bool
	uploadLoc  string
	encoding   string
	delay      time.Duration
	uploadSeq  int
	uploadRepo map[string]string
}

var (
	pathRe    = regexp.MustCompile(`^(?:` + redirectPrefix + `)?/v2/(.+)/(blobs|manifests)/([^/]+)$`)
	uploadRe  = regexp.MustCompile(`^(?:` + redirectPrefix + `)?/v2/(.+)/blobs/uploads/([^/]*)$`)
	digestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	redirects = regexp.MustCompile(`^` + redirectPrefix)
)

// NewRegistry starts a registry that stops when the test ends.
func NewRegistry(t testing.TB) *Registry {
	t.Helper()
	r := &Registry{
		repos:      map[string]*repo{},
		corrupt:    map[string]bool{},
		missing:    map[string]bool{},
		uploadRepo: map[string]string{},
	}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

// URL returns the host and port of the registry, with no scheme.
func (r *Registry) URL() string { return strings.TrimPrefix(r.srv.URL, "http://") }

// Requests returns a copy of every request so far, oldest first.
func (r *Registry) Requests() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Request, len(r.requests))
	copy(out, r.requests)
	return out
}

// Corrupt makes every read of the digest return changed bytes under the original headers.
func (r *Registry) Corrupt(digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.corrupt[digest] = true
}

// Missing makes every read of the digest return 404.
func (r *Registry) Missing(digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.missing[digest] = true
}

// RedirectTo makes every blob and manifest read answer 307 to the same path under url, a host and
// port with no scheme or a full http URL. Use the URL of the registry itself for a same-host
// redirect.
func (r *Registry) RedirectTo(url string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if url != "" && !strings.Contains(url, "://") {
		url = "http://" + url
	}
	r.redirect = strings.TrimSuffix(url, "/")
}

// Deny makes every request answer with the status and no authentication challenge. Zero turns it off.
func (r *Registry) Deny(status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deny = status
}

// DenyReads makes every GET and HEAD answer with the status and no authentication challenge, and
// lets POST, PATCH and PUT through, like a proxy for a writer that may not read. Zero turns it off.
func (r *Registry) DenyReads(status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denyReads = status
}

// OmitDigestHeader leaves the Docker-Content-Digest header out of every manifest and blob read.
func (r *Registry) OmitDigestHeader(on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.noDigest = on
}

// UploadLocation makes the answer to a blob upload start name this host and port as the
// Location, an absolute URL, instead of a path on this registry. An empty value turns it off.
func (r *Registry) UploadLocation(hostPort string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.uploadLoc = hostPort
}

// Encode sets a Content-Encoding header on every response. An empty value turns it off.
func (r *Registry) Encode(encoding string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.encoding = encoding
}

// Delay makes every manifest read wait before it answers.
func (r *Registry) Delay(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delay = d
}

// Seed stores a blob in a repository and returns its digest.
func (r *Registry) Seed(name string, data []byte) string {
	d := Digest(data)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repo(name).blobs[d] = append([]byte(nil), data...)
	return d
}

// SeedManifest stores a manifest in a repository under its digest and, when tag is not empty,
// under the tag. It returns the digest.
func (r *Registry) SeedManifest(name, tag, mediaType string, data []byte) string {
	d := Digest(data)
	r.mu.Lock()
	defer r.mu.Unlock()
	rp := r.repo(name)
	m := manifest{mediaType: mediaType, data: append([]byte(nil), data...)}
	rp.manifests[d] = m
	if tag != "" {
		rp.manifests[tag] = m
	}
	return d
}

// Blob returns the stored blob of a repository.
func (r *Registry) Blob(name, digest string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.repo(name).blobs[digest]
	return b, ok
}

// Manifest returns the stored manifest under a tag or digest.
func (r *Registry) Manifest(name, ref string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.repo(name).manifests[ref]
	return m.data, ok
}

// Digest returns sha256:<hex> of the data.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *Registry) repo(name string) *repo {
	rp, ok := r.repos[name]
	if !ok {
		rp = &repo{blobs: map[string][]byte{}, manifests: map[string]manifest{}}
		r.repos[name] = rp
	}
	return rp
}

func (r *Registry) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, Request{Method: req.Method, Path: req.URL.RequestURI(), Header: req.Header.Clone()})
	deny, encoding, redirect, delay, denyReads := r.deny, r.encoding, r.redirect, r.delay, r.denyReads
	r.mu.Unlock()

	if encoding != "" {
		w.Header().Set("Content-Encoding", encoding)
	}
	if deny != 0 {
		http.Error(w, "denied", deny)
		return
	}
	if denyReads != 0 && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
		http.Error(w, "denied", denyReads)
		return
	}
	path := req.URL.Path
	switch {
	case path == "/v2/" || path == "/v2":
		w.WriteHeader(http.StatusOK)
	case uploadRe.MatchString(path):
		r.upload(w, req)
	case pathRe.MatchString(path):
		m := pathRe.FindStringSubmatch(path)
		name, kind, ref := m[1], m[2], m[3]
		if redirect != "" && !redirects.MatchString(path) && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
			http.Redirect(w, req, redirect+redirectPrefix+path, http.StatusTemporaryRedirect)
			return
		}
		if kind == "manifests" {
			if delay > 0 {
				time.Sleep(delay)
			}
			r.manifest(w, req, name, ref)
		} else {
			r.blob(w, req, name, ref)
		}
	default:
		http.NotFound(w, req)
	}
}

func (r *Registry) isMissing(ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.missing[ref]
}

func (r *Registry) isCorrupt(ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.corrupt[ref]
}

func (r *Registry) send(w http.ResponseWriter, req *http.Request, mediaType, digest string, data []byte) {
	if r.isCorrupt(digest) && len(data) > 0 {
		data = append([]byte(nil), data...)
		data[0] ^= 0xff
	}
	w.Header().Set("Content-Type", mediaType)
	r.mu.Lock()
	noDigest := r.noDigest
	r.mu.Unlock()
	if !noDigest {
		w.Header().Set("Docker-Content-Digest", digest)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	if req.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func (r *Registry) blob(w http.ResponseWriter, req *http.Request, name, d string) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.mu.Lock()
	data, ok := r.repo(name).blobs[d]
	r.mu.Unlock()
	if !ok || r.isMissing(d) {
		http.Error(w, "blob unknown", http.StatusNotFound)
		return
	}
	r.send(w, req, "application/octet-stream", d, data)
}

func (r *Registry) manifest(w http.ResponseWriter, req *http.Request, name, ref string) {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		r.mu.Lock()
		m, ok := r.repo(name).manifests[ref]
		r.mu.Unlock()
		d := Digest(m.data)
		if !ok || r.isMissing(d) || r.isMissing(ref) {
			http.Error(w, "manifest unknown", http.StatusNotFound)
			return
		}
		if !accepts(req.Header.Get("Accept"), m.mediaType) {
			http.Error(w, "MANIFEST_UNKNOWN: "+m.mediaType+" found, but the Accept header does not support it", http.StatusNotFound)
			return
		}
		r.send(w, req, m.mediaType, d, m.data)
	case http.MethodPut:
		data, err := io.ReadAll(io.LimitReader(req.Body, 8<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d := Digest(data)
		if digestRe.MatchString(ref) && ref != d {
			http.Error(w, "digest invalid", http.StatusBadRequest)
			return
		}
		m := manifest{mediaType: req.Header.Get("Content-Type"), data: data}
		r.mu.Lock()
		rp := r.repo(name)
		rp.manifests[d] = m
		rp.manifests[ref] = m
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", d)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *Registry) upload(w http.ResponseWriter, req *http.Request) {
	m := uploadRe.FindStringSubmatch(req.URL.Path)
	name, id := m[1], m[2]
	switch req.Method {
	case http.MethodPost:
		r.mu.Lock()
		r.uploadSeq++
		id = strconv.Itoa(r.uploadSeq)
		r.uploadRepo[id] = name
		r.mu.Unlock()
		loc := "/v2/" + name + "/blobs/uploads/" + id
		r.mu.Lock()
		if r.uploadLoc != "" {
			loc = "http://" + r.uploadLoc + loc
		}
		r.mu.Unlock()
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		r.mu.Lock()
		owner, ok := r.uploadRepo[id]
		r.mu.Unlock()
		d := req.URL.Query().Get("digest")
		if !ok || owner != name {
			http.Error(w, "upload unknown", http.StatusNotFound)
			return
		}
		data, err := io.ReadAll(io.LimitReader(req.Body, 64<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if Digest(data) != d {
			http.Error(w, "digest invalid", http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.repo(name).blobs[d] = data
		delete(r.uploadRepo, id)
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", d)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// accepts reports whether an Accept header lists the media type by name, as Distribution 3.1.2 does
// for manifests and indexes: the wildcard does not match. An empty header accepts anything.
func accepts(accept, mediaType string) bool {
	if strings.TrimSpace(accept) == "" {
		return true
	}
	for _, part := range strings.Split(accept, ",") {
		name, _, _ := strings.Cut(part, ";")
		if strings.TrimSpace(name) == mediaType {
			return true
		}
	}
	return false
}

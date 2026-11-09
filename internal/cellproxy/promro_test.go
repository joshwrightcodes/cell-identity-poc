package cellproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeProm records each request that reaches it.
type fakeProm struct {
	srv    *httptest.Server
	hits   atomic.Int64
	mu     sync.Mutex
	method string
	uri    string
	header http.Header
	body   []byte
}

func newFakeProm(t *testing.T) *fakeProm {
	t.Helper()
	p := &fakeProm{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.method, p.uri, p.header, p.body = r.Method, r.URL.RequestURI(), r.Header.Clone(), body
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{}}`)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProm) last() (string, string, []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.method, p.uri, p.body
}

// promReads are the requests that Kiali v2.34.0 makes to Prometheus, through client_golang
// v1.23.2 (api/prometheus/v1/api.go): Query and QueryRange send a form POST and fall back to GET
// on 405 or 501 (DoGetFallback); LabelValues, Buildinfo, Config and Runtimeinfo send GET. The
// health probe is GET <url>/-/healthy (prometheus/lazy_client.go lines 64 to 66,
// business/istio_status.go lines 547 to 548).
var promReads = []struct {
	name, method, target, form string
}{
	{"query GET", "GET", "/api/v1/query?query=up&time=1700000000", ""},
	{"query POST", "POST", "/api/v1/query", "query=sum%28istio_requests_total%29&time=1700000000"},
	{"query_range GET", "GET", "/api/v1/query_range?query=up&start=1&end=2&step=15", ""},
	{"query_range POST", "POST", "/api/v1/query_range", "query=up&start=1&end=2&step=15"},
	{"label __name__ values", "GET", "/api/v1/label/__name__/values?start=0&end=1700000000", ""},
	{"status buildinfo", "GET", "/api/v1/status/buildinfo", ""},
	{"status config", "GET", "/api/v1/status/config", ""},
	{"status runtimeinfo", "GET", "/api/v1/status/runtimeinfo", ""},
	{"healthy", "GET", "/-/healthy", ""},
	{"query POST of 1 MiB", "POST", "/api/v1/query", "query=" + strings.Repeat("a", 1<<20-len("query="))},
}

var promDenied = []struct {
	name, method, target, contentType string
	body                              string
}{
	{"POST write", "POST", "/api/v1/write", "application/x-protobuf", "x"},
	{"POST otlp metrics", "POST", "/api/v1/otlp/v1/metrics", "application/x-protobuf", "x"},
	{"POST admin delete_series", "POST", "/api/v1/admin/tsdb/delete_series", "application/x-www-form-urlencoded", "match%5B%5D=up"},
	{"PUT admin delete_series", "PUT", "/api/v1/admin/tsdb/delete_series?match[]=up", "", ""},
	{"POST admin snapshot", "POST", "/api/v1/admin/tsdb/snapshot", "", ""},
	{"POST admin clean_tombstones", "POST", "/api/v1/admin/tsdb/clean_tombstones", "", ""},
	{"GET federate", "GET", "/federate?match[]=up", "", ""},
	{"POST reload", "POST", "/-/reload", "", ""},
	{"PUT quit", "PUT", "/-/quit", "", ""},
	{"GET ready", "GET", "/-/ready", "", ""},
	{"POST healthy", "POST", "/-/healthy", "application/x-www-form-urlencoded", ""},
	{"GET series", "GET", "/api/v1/series?match[]=up", "", ""},
	{"DELETE series", "DELETE", "/api/v1/series?match[]=up", "", ""},
	{"GET labels", "GET", "/api/v1/labels", "", ""},
	{"GET label job values", "GET", "/api/v1/label/job/values", "", ""},
	{"GET targets", "GET", "/api/v1/targets", "", ""},
	{"GET rules", "GET", "/api/v1/rules", "", ""},
	{"GET alerts", "GET", "/api/v1/alerts", "", ""},
	{"GET query_exemplars", "GET", "/api/v1/query_exemplars?query=up", "", ""},
	{"GET status flags", "GET", "/api/v1/status/flags", "", ""},
	{"GET status tsdb", "GET", "/api/v1/status/tsdb", "", ""},
	{"POST status buildinfo", "POST", "/api/v1/status/buildinfo", "application/x-www-form-urlencoded", ""},
	{"POST query with JSON", "POST", "/api/v1/query", "application/json", `{"query":"up"}`},
	{"POST query with no content type", "POST", "/api/v1/query", "", "query=up"},
	{"POST query of 1 MiB and 1 byte", "POST", "/api/v1/query", "application/x-www-form-urlencoded", "query=" + strings.Repeat("a", 1<<20+1-len("query="))},
	{"PUT query", "PUT", "/api/v1/query", "application/x-www-form-urlencoded", "query=up"},
	{"GET dot-dot to write", "GET", "/api/v1/query/../write", "", ""},
	{"GET escaped slash", "GET", "/api/v1%2Fquery", "", ""},
	{"GET empty segment", "GET", "/api/v1//query", "", ""},
	{"GET trailing slash", "GET", "/api/v1/query/", "", ""},
	{"GET graph", "GET", "/graph", "", ""},
	{"GET root", "GET", "/", "", ""},
}

func TestPromProxyStripsIdentity(t *testing.T) {
	prom := newFakeProm(t)
	upstream, _ := url.Parse(prom.srv.URL)
	h := NewPromProxy(upstream, jsonLog(&syncBuffer{}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/query?query=up", nil)
	req.Header.Set("Authorization", "Bearer kiali-token")
	req.Header.Set("Impersonate-User", "admin")
	req.Header.Set("X-Real-Ip", "1.2.3.4")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	prom.mu.Lock()
	defer prom.mu.Unlock()
	for _, k := range []string{"Authorization", "Impersonate-User", "X-Real-Ip"} {
		if v := prom.header.Values(k); len(v) != 0 {
			t.Errorf("the upstream got %s: %v", k, v)
		}
	}
}

func TestPromAllowList(t *testing.T) {
	prom := newFakeProm(t)
	upstream, _ := url.Parse(prom.srv.URL)
	h := NewPromProxy(upstream, jsonLog(&syncBuffer{}))
	for _, c := range promReads {
		t.Run("allowed/"+c.name, func(t *testing.T) {
			if !PromAllowed(c.method, parseTarget(t, c.target)) {
				t.Errorf("PromAllowed denies %s %s", c.method, c.target)
			}
			var body io.Reader
			if c.method == http.MethodPost {
				body = strings.NewReader(c.form)
			}
			req := httptest.NewRequest(c.method, c.target, body)
			if c.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			method, uri, got := prom.last()
			if method != c.method || uri != c.target || !bytes.Equal(got, []byte(c.form)) {
				t.Fatalf("upstream got %s %s with %d body bytes, want %s %s with %d", method, uri, len(got), c.method, c.target, len(c.form))
			}
		})
	}
	before := prom.hits.Load()
	for _, c := range promDenied {
		t.Run("denied/"+c.name, func(t *testing.T) {
			if c.body == "" && PromAllowed(c.method, parseTarget(t, c.target)) {
				t.Errorf("PromAllowed accepts %s %s", c.method, c.target)
			}
			req := httptest.NewRequest(c.method, c.target, strings.NewReader(c.body))
			if c.contentType != "" {
				req.Header.Set("Content-Type", c.contentType)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assertDenied(t, rec.Code, rec.Body.Bytes())
		})
	}
	if n := prom.hits.Load() - before; n != 0 {
		t.Fatalf("the upstream got %d denied requests", n)
	}
}

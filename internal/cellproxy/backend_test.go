package cellproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestServerRecoversAfterUpstreamRestart(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	conn := h.dial(t)
	if err := unaryCall(withToken(t.Context(), t), conn, "/test.Echo/Unary"); err != nil {
		t.Fatal(err)
	}
	h.upstreams[0].Stop()
	s := grpc.NewServer()
	h.up.register(s)
	h.upstreams[0] = s
	go func() { _ = s.Serve(newChanListener(h.split.targets[0], h.split.Addr())) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(withToken(t.Context(), t), 500*time.Millisecond)
		err := unaryCall(ctx, conn, "/test.Echo/Unary")
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("calls on the same client still fail 5 seconds after the upstream restart: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if n := len(h.split.accepted()); n != 2 {
		t.Fatalf("%d upstream connections, want a new one after the restart", n)
	}
}

func TestServerClosesDownstreamWhenUpstreamIsDown(t *testing.T) {
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	out := &syncBuffer{}
	log := jsonLog(out)
	// Port 1 on the loopback address refuses connections.
	srv := NewServer(ServerConfig{TLS: ServerTLS(source(mgmt.svid(t, principalID)), env.bundle(), regexp.MustCompile(viewPattern), testRegistry(t), log)},
		NewHeaderBackend("127.0.0.1:1", "x-cell-agent", log), log)
	addr, _, _ := serveOn(t, srv, out, env)
	c := dialHeld(t, addr, clientConfig(t, env, agentID1))
	if !closedWithin(c, 2*time.Second) {
		t.Fatal("the downstream stayed open with no upstream connection")
	}
	waitForLog(t, out, "upstream dial failed", UpstreamUnavailable, "")
}

// countingTransport answers every request with gRPC status OK, and counts the requests.
type countingTransport struct{ n atomic.Int64 }

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/grpc"}, "Grpc-Status": {"0"}},
		Body: http.NoBody, Request: r, ContentLength: 0,
	}, nil
}

func TestHeaderBackendRefusesOtherRequests(t *testing.T) {
	cell := Source{Env: "dev", Cluster: "dev-cell-1", Plane: PlaneCell, Cell: "dev-cell-1", Role: "argocd-agent"}
	env := Source{Env: "dev", Cluster: "dev-cp", Plane: PlaneEnvironment, Role: "argocd-agent"}
	token := accessToken(t, "dev-dev-cell-1", "autonomous")
	cases := []struct {
		name, method, target, contentType string
		src                               Source
		want                              Reason
	}{
		{"good", http.MethodPost, "/test.Echo/Unary", "application/grpc", cell, ""},
		{"environment plane", http.MethodPost, "/test.Echo/Unary", "application/grpc", env, RequestNotAllowed},
		{"query", http.MethodPost, "/test.Echo/Unary?x=1", "application/grpc", cell, RequestNotAllowed},
		{"escaped path", http.MethodPost, "/test.Echo/%55nary", "application/grpc", cell, RequestNotAllowed},
		{"GET", http.MethodGet, "/test.Echo/Unary", "application/grpc", cell, RequestNotAllowed},
		{"not gRPC", http.MethodPost, "/test.Echo/Unary", "application/json", cell, RequestNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := &syncBuffer{}
			b := &headerBackend{upstream: "upstream:1", header: "X-Cell-Agent", log: jsonLog(out)}
			h := &headerHandler{backend: b, src: c.src, log: jsonLog(out), end: func() {}}
			tr := &countingTransport{}
			h.proxy = &httputil.ReverseProxy{Rewrite: h.rewrite, Transport: tr}
			req := httptest.NewRequest(c.method, c.target, http.NoBody)
			req.Header.Set("Content-Type", c.contentType)
			req.Header.Set("Authorization", token)
			h.ServeHTTP(httptest.NewRecorder(), req)
			if c.want == "" {
				if tr.n.Load() != 1 {
					t.Fatalf("the good request did not reach the upstream:\n%s", out.String())
				}
				return
			}
			if tr.n.Load() != 0 {
				t.Fatal("the request reached the upstream")
			}
			waitForLog(t, out, "request denied", c.want, "")
		})
	}
}

// frame returns a gRPC frame with the compressed flag and the message.
func frame(compressed byte, msg []byte) []byte {
	out := []byte{compressed, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(msg)))
	return append(out, msg...)
}

func field(num protowire.Number, v string) []byte {
	return protowire.AppendString(protowire.AppendTag(nil, num, protowire.BytesType), v)
}

func TestRefreshFrameRules(t *testing.T) {
	good := field(1, "a.b.c")
	if _, tok, err := readRefreshFrame(bytes.NewReader(frame(0, good))); err != nil || tok != "a.b.c" {
		t.Fatalf("good frame: token %q, error %v", tok, err)
	}
	bad := map[string][]byte{
		"compressed":      frame(1, good),
		"above 16 KiB":    frame(0, field(1, strings.Repeat("a", maxRefreshFrame))),
		"two frames":      append(frame(0, good), frame(0, good)...),
		"field 1 twice":   frame(0, append(field(1, "a.b.c"), field(1, "d.e.f")...)),
		"another field":   frame(0, append(field(1, "a.b.c"), field(2, "x")...)),
		"no field":        frame(0, nil),
		"short frame":     frame(0, good)[:7],
		"varint field 1":  frame(0, protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1)),
		"truncated field": frame(0, good[:len(good)-1]),
	}
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			if _, tok, err := readRefreshFrame(bytes.NewReader(data)); err == nil {
				t.Fatalf("got token %q, want an error", tok)
			}
		})
	}
}

func TestClientClosesBothSidesOnHalfClose(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	c, err := net.Dial("tcp", h.client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !closedWithin(c, time.Second) {
		t.Fatal("a half-close of the plaintext side did not close the connection within 1 second")
	}
}

func TestRefreshTokenBodyDeadline(t *testing.T) {
	saved := bodyReadTimeout
	bodyReadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { bodyReadTimeout = saved })
	h := newHarness(t, harnessConfig{})

	tr := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
	body, stall := io.Pipe()
	defer func() { _ = stall.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+h.client+pathRefreshToken, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("a stalled RefreshToken body got no answer: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Grpc-Status"); got != "7" {
		t.Fatalf("grpc-status %q, want 7", got)
	}
	waitForLog(t, h.serverLog, "request denied", SubjectMismatch, "")
}

func TestServerNormalCloseLogsNoWarn(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	conn, err := grpc.NewClient("passthrough:///"+h.client, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	if err := unaryCall(withToken(t.Context(), t), conn, "/test.Echo/Unary"); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !hasMsg(t, h.serverLog, "connection closed") {
		if time.Now().After(deadline) {
			t.Fatalf("no connection closed line:\n%s", h.serverLog.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(closeGrace + 200*time.Millisecond)
	for _, l := range logLines(t, h.serverLog) {
		if l["level"] == "WARN" || l["level"] == "ERROR" {
			t.Fatalf("a normal close logged %v", l)
		}
	}
}

// TestServerKeepsDownstreamAtUpstreamStreamLimit fills the one stream that the upstream allows,
// and lets a second call time out while it waits for that stream. The healthy upstream must not
// end the downstream connection.
func TestServerKeepsDownstreamAtUpstreamStreamLimit(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	h.upstreams[0].Stop()
	s := grpc.NewServer(grpc.MaxConcurrentStreams(1))
	h.up.register(s)
	h.upstreams[0] = s
	go func() { _ = s.Serve(newChanListener(h.split.targets[0], h.split.Addr())) }()
	conn := h.dial(t)

	held, err := conn.NewStream(withToken(t.Context(), t), bidiDesc(), "/test.Echo/Bidi")
	if err != nil {
		t.Fatal(err)
	}
	send(t, held, "1")
	recv(t, held, "1")
	ctx, cancel := context.WithTimeout(withToken(t.Context(), t), 300*time.Millisecond)
	_ = unaryCall(ctx, conn, "/test.Echo/Unary")
	cancel()
	send(t, held, "2")
	recv(t, held, "2")
	if err := held.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if err := held.RecvMsg(&wrapperspb.StringValue{}); !errors.Is(err, io.EOF) {
		t.Fatalf("held stream ended with %v", err)
	}
	time.Sleep(closeGrace + 300*time.Millisecond)
	if err := unaryCall(withToken(t.Context(), t), conn, "/test.Echo/Unary"); err != nil {
		t.Fatal(err)
	}
	if n := len(h.split.accepted()); n != 1 {
		t.Fatalf("%d upstream connections, want the first one kept", n)
	}
	if hasMsg(t, h.serverLog, "upstream connection ended") {
		t.Fatalf("a healthy upstream at its stream limit ended the downstream:\n%s", h.serverLog.String())
	}
}

func hasMsg(t *testing.T, out *syncBuffer, msg string) bool {
	t.Helper()
	for _, l := range logLines(t, out) {
		if l["msg"] == msg {
			return true
		}
	}
	return false
}

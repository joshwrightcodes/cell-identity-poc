package connlimit

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// bound is the longest that a test waits for something that must happen.
const bound = 3 * time.Second

func newInner(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func dial(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

type acceptResult struct {
	c   net.Conn
	err error
}

func acceptAsync(l net.Listener) <-chan acceptResult {
	ch := make(chan acceptResult, 1)
	go func() { c, err := l.Accept(); ch <- acceptResult{c, err} }()
	return ch
}

func accept(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	select {
	case r := <-acceptAsync(l):
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.c
	case <-time.After(bound):
		t.Fatal("accept did not return in time")
		return nil
	}
}

// readEnds reads from c until it fails and returns how long that took. It fails the test when the
// read is still blocked after limit.
func readEnds(t *testing.T, c net.Conn, limit time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read returned data")
		}
		return time.Since(start)
	case <-time.After(limit):
		c.Close()
		t.Fatalf("read still blocked after %v", limit)
		return 0
	}
}

func TestConnlimitCapAndDeadline(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	const age, grace = 100 * time.Millisecond, 100 * time.Millisecond

	t.Run("cap", func(t *testing.T) {
		l := Listen(newInner(t), 2, time.Hour, time.Hour, clock.Now)
		_ = dial(t, l)
		s1 := accept(t, l)
		_ = dial(t, l)
		_ = accept(t, l)

		_ = dial(t, l)
		got := acceptAsync(l)
		select {
		case <-got:
			t.Fatal("third connection accepted while two are open")
		case <-time.After(150 * time.Millisecond):
		}
		s1.Close()
		select {
		case r := <-got:
			if r.err != nil {
				t.Fatal(r.err)
			}
			r.c.Close()
		case <-time.After(bound):
			t.Fatal("third connection not accepted after a close")
		}
	})

	t.Run("double_close_releases_once", func(t *testing.T) {
		l := Listen(newInner(t), 1, time.Hour, time.Hour, clock.Now)
		_ = dial(t, l)
		s := accept(t, l)
		closed := make(chan struct{})
		go func() {
			s.Close()
			s.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(bound):
			t.Fatal("a second Close blocked")
		}
		_ = dial(t, l)
		s2 := accept(t, l)
		_ = dial(t, l)
		got := acceptAsync(l)
		select {
		case <-got:
			t.Fatal("a double Close released two slots")
		case <-time.After(150 * time.Millisecond):
		}
		s2.Close()
	})

	t.Run("close_wakes_accept_at_cap", func(t *testing.T) {
		l := Listen(newInner(t), 1, time.Hour, time.Hour, clock.Now)
		_ = dial(t, l)
		_ = accept(t, l)
		got := acceptAsync(l)
		select {
		case <-got:
			t.Fatal("accept returned at the cap")
		case <-time.After(100 * time.Millisecond):
		}
		l.Close()
		select {
		case r := <-got:
			if r.err == nil {
				t.Fatal("accept returned a connection after Close")
			}
		case <-time.After(bound):
			t.Fatal("Close did not wake an Accept that waits at the cap")
		}
	})

	t.Run("deadline_is_age_plus_grace", func(t *testing.T) {
		l := Listen(newInner(t), 4, age, grace, clock.Now)
		_ = dial(t, l)
		s := accept(t, l)
		defer s.Close()
		took := readEnds(t, s, bound)
		if took < 150*time.Millisecond {
			t.Fatalf("closed after %v, before maxAge + grace", took)
		}
		if took > bound-time.Second {
			t.Fatalf("closed after %v, want about 200ms", took)
		}
	})

	t.Run("deadline_ignores_injected_clock", func(t *testing.T) {
		far := &fakeClock{t: time.Unix(1_900_000_000, 0)}
		l := Listen(newInner(t), 4, age, grace, far.Now)
		_ = dial(t, l)
		s := accept(t, l)
		defer s.Close()
		readEnds(t, s, bound)
	})

	t.Run("read_deadline_cannot_be_cleared", func(t *testing.T) {
		l := Listen(newInner(t), 4, age, grace, clock.Now)
		_ = dial(t, l)
		s := accept(t, l)
		defer s.Close()
		for _, d := range []time.Time{{}, time.Now().Add(time.Hour)} {
			if err := s.SetReadDeadline(d); err != nil {
				t.Fatal(err)
			}
		}
		readEnds(t, s, bound)
	})

	t.Run("write_deadline_cannot_be_cleared", func(t *testing.T) {
		l := Listen(newInner(t), 4, age, grace, clock.Now)
		_ = dial(t, l)
		s := accept(t, l)
		defer s.Close()
		for _, d := range []time.Time{{}, time.Now().Add(time.Hour)} {
			if err := s.SetWriteDeadline(d); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() {
			// The peer never reads, so the socket buffers fill and a write blocks.
			chunk := make([]byte, 1<<20)
			for {
				if _, err := s.Write(chunk); err != nil {
					done <- err
					return
				}
			}
		}()
		select {
		case err := <-done:
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				t.Fatalf("write error %v, want a timeout", err)
			}
		case <-time.After(bound):
			s.Close()
			t.Fatal("a blocked write outlived the hard deadline")
		}
	})

	t.Run("shorter_deadline_is_kept", func(t *testing.T) {
		l := Listen(newInner(t), 4, time.Hour, time.Hour, clock.Now)
		_ = dial(t, l)
		s := accept(t, l)
		defer s.Close()
		if err := s.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if took := readEnds(t, s, bound); took > time.Second {
			t.Fatalf("read ended after %v", took)
		}
	})

	t.Run("tls_server_clearing_deadlines_keeps_hard_deadline", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		srv.Listener = Listen(srv.Listener, 4, age, grace, clock.Now)
		// With a header timeout, net/http clears both deadlines after the handshake and then sets
		// its own per-request read deadline, an hour ahead here.
		srv.Config.ReadHeaderTimeout = time.Hour
		srv.StartTLS()
		defer srv.Close()
		c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// The client sends nothing after the handshake.
		readEnds(t, c, bound)
	})

	t.Run("max_age_header", func(t *testing.T) {
		l := Listen(newInner(t), 4, 15*time.Second, time.Hour, clock.Now)
		srv := &http.Server{
			ConnContext: ConnContext,
			Handler: MaxAge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})),
		}
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })

		conn := dial(t, l)
		br := bufio.NewReader(conn)
		get := func() *http.Response {
			t.Helper()
			if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			return resp
		}
		if r := get(); r.Close {
			t.Fatalf("young connection got Connection: close")
		}
		clock.Advance(14 * time.Second)
		if r := get(); r.Close {
			t.Fatalf("connection of 14 s got Connection: close")
		}
		clock.Advance(time.Second)
		if r := get(); !r.Close {
			t.Fatalf("connection of exactly maxAge did not get Connection: close")
		}
	})

	t.Run("expired_without_listener_value", func(t *testing.T) {
		if Expired(context.Background()) {
			t.Fatal("a context with no connection must not be expired")
		}
	})
}

func TestConnContextUnwrapsTLS(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Expired(r.Context()) {
			w.Header().Set("X-Expired", "yes")
		}
	}))
	srv.Listener = Listen(srv.Listener, 4, 15*time.Second, time.Hour, clock.Now)
	srv.Config.ConnContext = ConnContext
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	client := srv.Client()
	get := func() string {
		t.Helper()
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Get("X-Expired")
	}
	if got := get(); got != "" {
		t.Fatalf("young TLS connection reported expired: %q", got)
	}
	clock.Advance(16 * time.Second)
	if got := get(); got != "yes" {
		t.Fatalf("TLS connection past maxAge not reported expired: %q", got)
	}
}

// scriptedListener returns the scripted accepts in order, then delegates to its inner listener.
type scriptedListener struct {
	net.Listener
	mu     sync.Mutex
	script []acceptResult
}

func (s *scriptedListener) Accept() (net.Conn, error) {
	s.mu.Lock()
	if len(s.script) > 0 {
		r := s.script[0]
		s.script = s.script[1:]
		s.mu.Unlock()
		return r.c, r.err
	}
	s.mu.Unlock()
	return s.Listener.Accept()
}

type deadlineFailConn struct {
	net.Conn
	closed chan struct{}
}

func (c *deadlineFailConn) SetDeadline(time.Time) error { return errors.New("no deadline") }
func (c *deadlineFailConn) Close() error                { close(c.closed); return c.Conn.Close() }

func TestConnlimitAcceptErrors(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}

	t.Run("inner_error_releases_slot", func(t *testing.T) {
		inner := &scriptedListener{Listener: newInner(t), script: []acceptResult{{err: errors.New("temporary")}}}
		l := Listen(inner, 1, time.Hour, time.Hour, clock.Now)
		if _, err := l.Accept(); err == nil {
			t.Fatal("expected the scripted accept error")
		}
		_ = dial(t, l)
		accept(t, l)
	})

	t.Run("deadline_error_closes_that_connection_only", func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		bad := &deadlineFailConn{Conn: a, closed: make(chan struct{})}
		inner := &scriptedListener{Listener: newInner(t), script: []acceptResult{{c: bad}}}
		l := Listen(inner, 1, time.Hour, time.Hour, clock.Now)
		_ = dial(t, l)
		accept(t, l)
		select {
		case <-bad.closed:
		default:
			t.Fatal("the connection that failed SetDeadline stayed open")
		}
	})
}

func TestListenRefusesBadLimits(t *testing.T) {
	l := newInner(t)
	for name, f := range map[string]func(){
		"zero_max_age":      func() { Listen(l, 1, 0, time.Second, nil) },
		"negative_max_age":  func() { Listen(l, 1, -time.Second, time.Second, nil) },
		"negative_grace":    func() { Listen(l, 1, time.Second, -time.Second, nil) },
		"zero_max_conns":    func() { Listen(l, 0, time.Second, time.Second, nil) },
		"negative_max_conn": func() { Listen(l, -1, time.Second, time.Second, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Listen accepted a bad limit")
				}
			}()
			f()
		})
	}
	Listen(l, 1, time.Second, 0, nil)
}

// fakeConn is a connection with a chosen remote address. Close records itself.
type fakeConn struct {
	remote   net.Addr
	closed   chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
}

func newFakeConn(remote net.Addr) *fakeConn {
	return &fakeConn{remote: remote, closed: make(chan struct{})}
}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *fakeConn) Read([]byte) (int, error)         { <-c.closed; return 0, net.ErrClosed }
func (c *fakeConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *fakeConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8450} }
func (c *fakeConn) RemoteAddr() net.Addr             { return c.remote }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *fakeConn) hasDeadline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.deadline.IsZero()
}

// fakeInner hands out the connections that a test pushes, in order.
type fakeInner struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newFakeInner() *fakeInner {
	return &fakeInner{ch: make(chan net.Conn, 256), done: make(chan struct{})}
}

func (f *fakeInner) push(ip string, port int) *fakeConn {
	c := newFakeConn(&net.TCPAddr{IP: net.ParseIP(ip), Port: port})
	f.ch <- c
	return c
}

func (f *fakeInner) Accept() (net.Conn, error) {
	select {
	case c := <-f.ch:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}
func (f *fakeInner) Close() error   { f.once.Do(func() { close(f.done) }); return nil }
func (f *fakeInner) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8450} }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func recvAccept(t *testing.T, ch <-chan acceptResult) acceptResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(bound):
		t.Fatal("accept did not return in time")
		return acceptResult{}
	}
}

func notAccepted(t *testing.T, ch <-chan acceptResult, why string) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("%s (got %v %v)", why, r.c, r.err)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestListenPerSource(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	newL := func(t *testing.T, maxConns, perSource int) (net.Listener, *fakeInner) {
		inner := newFakeInner()
		l := ListenPerSource(inner, maxConns, perSource, time.Hour, time.Hour, clock.Now)
		t.Cleanup(func() { l.Close() })
		return l, inner
	}

	t.Run("forty_from_one_source_admit_four", func(t *testing.T) {
		l, inner := newL(t, 32, 4)
		var all []*fakeConn
		for p := 1; p <= 40; p++ {
			all = append(all, inner.push("192.0.2.1", 40000+p))
		}
		var admitted []net.Conn
		for i := 0; i < 4; i++ {
			admitted = append(admitted, accept(t, l))
		}
		next := acceptAsync(l)
		waitFor(t, "36 closed connections", func() bool {
			n := 0
			for _, c := range all[4:] {
				if c.isClosed() {
					n++
				}
			}
			return n == 36
		})
		for i, c := range all[:4] {
			if c.isClosed() {
				t.Errorf("admitted connection %d was closed", i)
			}
		}
		notAccepted(t, next, "Accept returned a connection that no source admitted")

		// While A holds its four, source B is admitted, and Accept returns it.
		b := inner.push("192.0.2.2", 50000)
		select {
		case r := <-next:
			if r.err != nil || r.c.RemoteAddr().String() != b.RemoteAddr().String() {
				t.Fatalf("got %v %v, want the connection of source B", r.c, r.err)
			}
		case <-time.After(bound):
			t.Fatal("source B was not admitted while A held four")
		}
		// A closed connection frees one place for A.
		admitted[0].Close()
		a := inner.push("192.0.2.1", 41000)
		if r := recvAccept(t, acceptAsync(l)); r.err != nil || r.c.RemoteAddr().String() != a.RemoteAddr().String() {
			t.Fatalf("A was not admitted after a close: %v %v", r.c, r.err)
		}
	})

	t.Run("closed_excess_never_counts_toward_max_conns", func(t *testing.T) {
		l, inner := newL(t, 8, 4)
		var a []net.Conn
		var excess []*fakeConn
		for p := 1; p <= 12; p++ {
			c := inner.push("192.0.2.1", 40000+p)
			if p <= 4 {
				continue
			}
			excess = append(excess, c)
		}
		for i := 0; i < 4; i++ {
			a = append(a, accept(t, l))
		}
		var others []net.Conn
		for i := 2; i <= 5; i++ {
			inner.push(fmt.Sprintf("192.0.2.%d", i), 50000)
		}
		for i := 0; i < 4; i++ {
			others = append(others, accept(t, l))
		}
		for _, c := range excess {
			if !c.isClosed() {
				t.Fatal("a connection above the per-source cap stayed open")
			}
		}
		// Eight are admitted, so the ninth source waits for a close.
		inner.push("192.0.2.9", 50000)
		ninth := acceptAsync(l)
		notAccepted(t, ninth, "the ninth source was admitted at the cap")
		a[0].Close()
		select {
		case r := <-ninth:
			if r.err != nil {
				t.Fatal(r.err)
			}
		case <-time.After(bound):
			t.Fatal("the ninth source was not admitted after a close")
		}
		_ = others
	})

	t.Run("eight_sources_of_one_then_ninth_waits", func(t *testing.T) {
		l, inner := newL(t, 8, 4)
		var held []net.Conn
		for i := 1; i <= 8; i++ {
			inner.push(fmt.Sprintf("192.0.2.%d", i), 40000)
			held = append(held, accept(t, l))
		}
		inner.push("192.0.2.99", 40000)
		ninth := acceptAsync(l)
		notAccepted(t, ninth, "the ninth source was admitted at the cap")
		held[3].Close()
		select {
		case r := <-ninth:
			if r.err != nil {
				t.Fatal(r.err)
			}
		case <-time.After(bound):
			t.Fatal("the ninth source was not admitted after a close")
		}
	})

	t.Run("four_in_six_counts_as_its_ipv4_source", func(t *testing.T) {
		l, inner := newL(t, 32, 4)
		for p := 1; p <= 2; p++ {
			inner.push("192.0.2.1", 40000+p)
			inner.push("::ffff:192.0.2.1", 41000+p)
		}
		for i := 0; i < 4; i++ {
			accept(t, l)
		}
		extra := inner.push("::ffff:192.0.2.1", 42000)
		extra4 := inner.push("192.0.2.1", 42001)
		next := acceptAsync(l)
		waitFor(t, "the fifth connection of the source to close", func() bool { return extra.isClosed() && extra4.isClosed() })
		notAccepted(t, next, "a fifth connection of one IPv4 source was admitted")
		// A different IPv6 source is a different source.
		inner.push("2001:db8::1", 1)
		if r := recvAccept(t, next); r.err != nil {
			t.Fatal(r.err)
		}
	})

	t.Run("string_form_of_a_four_in_six_address", func(t *testing.T) {
		inner := newFakeInner()
		l := ListenPerSource(inner, 32, 1, time.Hour, time.Hour, clock.Now)
		t.Cleanup(func() { l.Close() })
		mk := func(s string) *fakeConn {
			c := newFakeConn(stringAddr(s))
			inner.ch <- c
			return c
		}
		mk("192.0.2.1:1000")
		accept(t, l)
		second := mk("[::ffff:192.0.2.1]:2000")
		next := acceptAsync(l)
		waitFor(t, "the 4-in-6 connection to close", second.isClosed)
		notAccepted(t, next, "a 4-in-6 form of A was admitted as a second source")
	})

	t.Run("zero_max_age_sets_no_deadline", func(t *testing.T) {
		inner := newInner(t)
		l := ListenPerSource(inner, 4, 4, 0, time.Second, nil)
		client := dial(t, l)
		server := accept(t, l)
		defer server.Close()
		if err := server.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if err := server.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		go func() {
			time.Sleep(2 * time.Second)
			client.Write([]byte("x"))
		}()
		buf := make([]byte, 1)
		start := time.Now()
		if _, err := server.Read(buf); err != nil || time.Since(start) < 1500*time.Millisecond {
			t.Fatalf("read ended after %v with %v, want a live connection 2 s past the 1 s grace", time.Since(start), err)
		}
	})

	t.Run("zero_max_age_never_expires", func(t *testing.T) {
		inner := newFakeInner()
		l := ListenPerSource(inner, 4, 4, 0, time.Second, clock.Now)
		t.Cleanup(func() { l.Close() })
		c := inner.push("192.0.2.1", 1)
		server := accept(t, l)
		if c.hasDeadline() {
			t.Fatal("a zero maxAge set a deadline on the connection")
		}
		ctx := ConnContext(context.Background(), server)
		clock.Advance(48 * time.Hour)
		if Expired(ctx) {
			t.Fatal("a connection with no maxAge reports expired")
		}
	})

	t.Run("positive_max_age_sets_the_hard_deadline", func(t *testing.T) {
		inner := newFakeInner()
		l := ListenPerSource(inner, 4, 4, time.Minute, time.Minute, clock.Now)
		t.Cleanup(func() { l.Close() })
		c := inner.push("192.0.2.1", 1)
		server := accept(t, l)
		if !c.hasDeadline() {
			t.Fatal("no deadline on a connection with maxAge")
		}
		ctx := ConnContext(context.Background(), server)
		if Expired(ctx) {
			t.Fatal("expired at once")
		}
		clock.Advance(time.Minute)
		if !Expired(ctx) {
			t.Fatal("not expired after maxAge")
		}
	})

	t.Run("close_wakes_accept_at_the_cap", func(t *testing.T) {
		l, inner := newL(t, 1, 1)
		inner.push("192.0.2.1", 1)
		accept(t, l)
		got := acceptAsync(l)
		notAccepted(t, got, "accept returned at the cap")
		l.Close()
		select {
		case r := <-got:
			if r.err == nil {
				t.Fatal("accept returned a connection after Close")
			}
		case <-time.After(bound):
			t.Fatal("Close did not wake Accept")
		}
	})

	t.Run("double_close_frees_one_place", func(t *testing.T) {
		l, inner := newL(t, 8, 1)
		inner.push("192.0.2.1", 1)
		a := accept(t, l)
		a.Close()
		a.Close()
		inner.push("192.0.2.1", 2)
		accept(t, l)
		second := inner.push("192.0.2.1", 3)
		next := acceptAsync(l)
		waitFor(t, "the second connection to close", second.isClosed)
		notAccepted(t, next, "a double Close freed two places")
	})

	t.Run("inner_error_returns", func(t *testing.T) {
		l, inner := newL(t, 8, 1)
		inner.Close()
		if _, err := l.Accept(); err == nil {
			t.Fatal("expected the inner error")
		}
	})
}

type stringAddr string

func (stringAddr) Network() string  { return "tcp" }
func (s stringAddr) String() string { return string(s) }

func TestListenPerSourceRefusesBadLimits(t *testing.T) {
	l := newInner(t)
	for name, f := range map[string]func(){
		"zero_max_conns":   func() { ListenPerSource(l, 0, 1, 0, 0, nil) },
		"zero_per_source":  func() { ListenPerSource(l, 1, 0, 0, 0, nil) },
		"negative_max_age": func() { ListenPerSource(l, 1, 1, -time.Second, 0, nil) },
		"negative_grace":   func() { ListenPerSource(l, 1, 1, time.Second, -time.Second, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("ListenPerSource accepted a bad limit")
				}
			}()
			f()
		})
	}
	ListenPerSource(l, 1, 1, 0, 0, nil)
}

package connlimit

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
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

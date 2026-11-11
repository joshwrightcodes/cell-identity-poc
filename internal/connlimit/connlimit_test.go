package connlimit

import (
	"bufio"
	"context"
	"net"
	"net/http"
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

func accept(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := l.Accept(); ch <- res{c, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.c
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
		return nil
	}
}

func TestConnlimitCapAndDeadline(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}

	t.Run("cap", func(t *testing.T) {
		l := Listen(newInner(t), 2, time.Hour, time.Hour, clock.Now)
		c1 := dial(t, l)
		s1 := accept(t, l)
		_ = dial(t, l)
		s2 := accept(t, l)
		_ = c1
		_ = s2

		_ = dial(t, l)
		got := make(chan net.Conn, 1)
		go func() {
			c, err := l.Accept()
			if err == nil {
				got <- c
			}
		}()
		select {
		case <-got:
			t.Fatal("third connection accepted while two are open")
		case <-time.After(150 * time.Millisecond):
		}
		s1.Close()
		select {
		case c := <-got:
			c.Close()
		case <-time.After(5 * time.Second):
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
		case <-time.After(3 * time.Second):
			t.Fatal("a second Close blocked")
		}
		_ = dial(t, l)
		s2 := accept(t, l)
		_ = dial(t, l)
		got := make(chan struct{}, 1)
		go func() {
			if c, err := l.Accept(); err == nil {
				c.Close()
				got <- struct{}{}
			}
		}()
		select {
		case <-got:
			t.Fatal("a double Close released two slots")
		case <-time.After(150 * time.Millisecond):
		}
		s2.Close()
	})

	t.Run("silent_connection_closed_at_deadline", func(t *testing.T) {
		l := Listen(newInner(t), 4, 0, 100*time.Millisecond, clock.Now)
		client := dial(t, l)
		s := accept(t, l)
		start := time.Now()
		buf := make([]byte, 1)
		_, err := s.Read(buf)
		took := time.Since(start)
		if err == nil {
			t.Fatal("read returned data")
		}
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("read error %v, want a timeout", err)
		}
		if took < 80*time.Millisecond || took > 2*time.Second {
			t.Fatalf("deadline fired after %v, want about 100ms", took)
		}
		s.Close()
		_ = client
	})

	t.Run("handler_cannot_extend_deadline", func(t *testing.T) {
		l := Listen(newInner(t), 4, 0, 100*time.Millisecond, clock.Now)
		_ = dial(t, l)
		s := accept(t, l)
		defer s.Close()
		if err := s.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := s.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := s.Read(make([]byte, 1))
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("read returned data")
			}
		case <-time.After(3 * time.Second):
			s.Close()
			t.Fatal("a later SetDeadline extended the hard deadline")
		}
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
		if r := get(); r.Close || r.Header.Get("Connection") == "close" {
			t.Fatalf("young connection got Connection: close")
		}
		clock.Advance(14 * time.Second)
		if r := get(); r.Close {
			t.Fatalf("connection of 14 s got Connection: close")
		}
		clock.Advance(2 * time.Second)
		if r := get(); !r.Close {
			t.Fatalf("connection of 16 s did not get Connection: close")
		}
	})

	t.Run("expired_without_listener_value", func(t *testing.T) {
		if Expired(context.Background()) {
			t.Fatal("a context with no connection must not be expired")
		}
	})
}

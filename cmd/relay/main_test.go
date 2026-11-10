package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a log sink that the relay goroutines and the test share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startRelay serves one route from a local listener to upstream, and returns the listen address.
// The relay stops when the test ends.
func startRelay(t *testing.T, upstream string, tune func(*relay)) (string, *syncBuffer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	r := &relay{upstream: upstream, dialTimeout: dialTimeout, firstByteTimeout: firstByteTimeout,
		keepAlive: keepAlive, log: slog.New(slog.NewJSONHandler(logs, nil))}
	if tune != nil {
		tune(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return ln.Addr().String(), logs
}

// upstreamServer accepts connections and runs handle for each one.
func upstreamServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				handle(c)
			})
		}
	})
	return ln.Addr().String()
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRelayPassesBytes sends 1 MiB each way through the relay. Both sides get the bytes unchanged.
func TestRelayPassesBytes(t *testing.T) {
	const size = 1 << 20
	down, up := randomBytes(t, size), randomBytes(t, size)
	got := make(chan []byte, 1)
	addr := upstreamServer(t, func(c net.Conn) {
		go func() { _, _ = c.Write(up) }()
		b, _ := io.ReadAll(io.LimitReader(c, size))
		got <- b
	})
	relayAddr, _ := startRelay(t, addr, nil)
	c, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() { _, _ = c.Write(down) }()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	back := make([]byte, size)
	if _, err := io.ReadFull(c, back); err != nil {
		t.Fatalf("read 1 MiB from the upstream through the relay: %v", err)
	}
	if !bytes.Equal(back, up) {
		t.Error("the client got other bytes than the upstream sent")
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, down) {
			t.Errorf("the upstream got %d other bytes than the client sent", len(b))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream did not get 1 MiB")
	}
}

// TestRelayFirstByteTimeout connects and sends nothing. The relay closes the connection after the
// first-byte timeout, and dials no upstream.
func TestRelayFirstByteTimeout(t *testing.T) {
	dialed := make(chan struct{}, 1)
	addr := upstreamServer(t, func(net.Conn) { dialed <- struct{}{} })
	relayAddr, logs := startRelay(t, addr, func(r *relay) { r.firstByteTimeout = 200 * time.Millisecond })
	c, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read from a silent client: %v, want EOF from the relay", err)
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > 2*time.Second {
		t.Errorf("the relay closed a silent client after %s, want about 200ms", d)
	}
	select {
	case <-dialed:
		t.Error("the relay dialed the upstream for a client that sent nothing")
	case <-time.After(100 * time.Millisecond):
	}
	waitLog(t, logs, "first_byte_timeout")
}

// TestRelayPropagatesClose checks both close directions, and that no goroutine stays after 20
// connections.
func TestRelayPropagatesClose(t *testing.T) {
	type event struct{ eof bool }
	upstreamEOF := make(chan event, 32)
	closeUp := make(chan struct{})
	addr := upstreamServer(t, func(c net.Conn) {
		b := make([]byte, 1)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		switch b[0] {
		case 'h': // half-close case: wait for EOF, then answer and close
			_, err := io.ReadAll(c)
			upstreamEOF <- event{eof: err == nil}
			_, _ = c.Write([]byte("bye"))
		case 'c': // upstream close case
			<-closeUp
		}
	})
	relayAddr, _ := startRelay(t, addr, nil)

	t.Run("client half-close reaches the upstream as EOF", func(t *testing.T) {
		c, err := net.Dial("tcp", relayAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("h")); err != nil {
			t.Fatal(err)
		}
		if err := c.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		select {
		case e := <-upstreamEOF:
			if !e.eof {
				t.Fatal("the upstream got an error, want EOF")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the upstream got no EOF after the client half-closed")
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, err := io.ReadAll(c)
		if err != nil || string(b) != "bye" {
			t.Fatalf("after the half-close the client read %q, %v; want the answer bye, then EOF", b, err)
		}
	})

	t.Run("upstream close closes the client within 1s", func(t *testing.T) {
		before := runtime.NumGoroutine()
		c, err := net.Dial("tcp", relayAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("c")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		start := time.Now()
		closeUp <- struct{}{}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("read after the upstream closed: %v, want EOF", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("the client saw the close after %s, want 1s or less", d)
		}
		// The relay must release the whole connection, not only half-close it, while the client
		// stays open and silent.
		deadline := time.Now().Add(time.Second)
		for runtime.NumGoroutine() > before {
			if time.Now().After(deadline) {
				t.Fatalf("goroutines: %d before the connection, %d one second after the upstream closed; the relay still holds the client", before, runtime.NumGoroutine())
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("no goroutine stays after 20 connections", func(t *testing.T) {
		start := runtime.NumGoroutine()
		for range 20 {
			c, err := net.Dial("tcp", relayAddr)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write([]byte("c")); err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
			closeUp <- struct{}{}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.ReadAll(c)
			_ = c.Close()
		}
		deadline := time.Now().Add(5 * time.Second)
		for runtime.NumGoroutine() > start {
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<16)
				t.Fatalf("goroutines: %d at the start, %d after 20 closed connections\n%s", start, runtime.NumGoroutine(), buf[:runtime.Stack(buf, true)])
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}

// TestRelayDialTimeout routes to an address that drops packets. The relay closes the client after
// the dial timeout.
func TestRelayDialTimeout(t *testing.T) {
	// TEST-NET-1 (RFC 5737) is not routed, so a dial either times out or fails at once.
	relayAddr, logs := startRelay(t, "192.0.2.1:9", func(r *relay) { r.dialTimeout = 300 * time.Millisecond })
	c, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read while the dial fails: %v, want EOF", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the client stayed open %s, want the dial timeout of 300ms", d)
	}
	line := waitLog(t, logs, "upstream_unavailable")
	if strings.Contains(line, "i/o timeout") && time.Since(start) < 250*time.Millisecond {
		t.Errorf("the dial timed out before the dial timeout: %s", line)
	}
	t.Logf("relay log: %s", line)
}

// TestRelayRouteParse gives bad routes. Each one fails with one JSON error line and exit status 2.
func TestRelayRouteParse(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--route", "8443"},
		{"--route", "8443="},
		{"--route", "=10.0.0.1:31443"},
		{"--route", "0=10.0.0.1:31443"},
		{"--route", "70000=10.0.0.1:31443"},
		{"--route", "x=10.0.0.1:31443"},
		{"--route", "8443=10.0.0.1"},
		{"--route", "8443=10.0.0.1:0"},
		{"--route", "8443=:31443"},
		{"--route", "8443=10.0.0.1:31443", "--route", "8443=10.0.0.2:31443"},
		{"--route", "8443=10.0.0.1:31443", "extra"},
		{"--health", "bad", "--route", "8443=10.0.0.1:31443"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out bytes.Buffer
			if code := execute(context.Background(), args, &out); code != 2 {
				t.Errorf("exit status %d, want 2", code)
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			if len(lines) != 1 {
				t.Fatalf("output has %d lines, want one JSON error line: %q", len(lines), out.String())
			}
			var rec struct{ Level, Msg, Error string }
			if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil || rec.Level != "ERROR" || rec.Error == "" {
				t.Fatalf("output %q is no JSON error line: %v", lines[0], err)
			}
		})
	}
	routes, err := parseRoutes([]string{"8443=10.0.0.1:31443", "8445=10.0.0.1:31445"})
	if err != nil || len(routes) != 2 || routes[0].listen != 8443 || routes[1].upstream != "10.0.0.1:31445" {
		t.Fatalf("good routes: %+v, %v", routes, err)
	}
}

// waitLog waits until a log line holds want, and returns it.
func waitLog(t *testing.T, logs *syncBuffer, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for l := range strings.SplitSeq(logs.String(), "\n") {
			if strings.Contains(l, want) {
				return l
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no log line with %q in:\n%s", want, logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// echoUpstream echoes every byte back until the client closes.
func echoUpstream(t *testing.T) string {
	t.Helper()
	return upstreamServer(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
}

// TestRelayStreamOutlivesFirstByteDeadline sends one byte, waits longer than the first-byte
// deadline, and then exchanges bytes both ways. The deadline covers only the wait for the first
// byte, so a long stream stays open.
func TestRelayStreamOutlivesFirstByteDeadline(t *testing.T) {
	relayAddr, logs := startRelay(t, echoUpstream(t), func(r *relay) { r.firstByteTimeout = 200 * time.Millisecond })
	c, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	exchange := func(msg string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
			t.Fatalf("echo of %q: got %q, %v", msg, got, err)
		}
	}
	exchange("a")
	time.Sleep(700 * time.Millisecond)
	exchange("bc")
	time.Sleep(300 * time.Millisecond)
	exchange("def")
	_ = c.Close()
	line := waitLog(t, logs, "connection ended")
	if strings.Contains(line, "timeout") || strings.Contains(line, "client_error") || !strings.Contains(line, `"result":"closed"`) {
		t.Errorf("the stream ended with %s, want result closed", line)
	}
}

// TestRelayStopClosesConnections cancels the relay while one client waits for its first byte and
// another holds a live stream. Both clients see the close within a second, and serve returns.
func TestRelayStopClosesConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{upstream: echoUpstream(t), dialTimeout: dialTimeout, firstByteTimeout: firstByteTimeout,
		keepAlive: keepAlive, log: slog.New(slog.NewJSONHandler(&syncBuffer{}, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- r.serve(ctx, ln) }()
	silent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	live, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	_, _ = live.Write([]byte("x"))
	_ = live.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(live, make([]byte, 1)); err != nil {
		t.Fatalf("echo before the stop: %v", err)
	}
	cancel()
	for name, c := range map[string]net.Conn{"silent": silent, "live": live} {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("the %s client read %v after the stop, want the close within 1s", name, err)
		}
	}
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not return within 1s of the stop")
	}
}

// dialAndSend opens a connection to the relay, and sends one byte.
func dialAndSend(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_, _ = c.Write([]byte("x"))
	return c
}

// refused reports whether the relay closed the connection at once, with no echo. The client sent a
// byte that the relay did not read, so the close may arrive as a reset.
func refused(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func admitted(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, err := io.ReadFull(c, make([]byte, 1))
	return err == nil
}

// TestRelayLimitsOneSource opens connections from one address up to the limit. The next one is
// closed at once, dials no upstream and logs source_limit. A freed slot admits a new connection.
func TestRelayLimitsOneSource(t *testing.T) {
	counted := make(chan struct{}, 16)
	addr := upstreamServer(t, func(c net.Conn) { counted <- struct{}{}; _, _ = io.Copy(c, c) })
	relayAddr, logs := startRelay(t, addr, func(r *relay) { r.limits = newLimiter(100, 2) })
	a, b := dialAndSend(t, relayAddr), dialAndSend(t, relayAddr)
	if !admitted(a) || !admitted(b) {
		t.Fatal("the first two connections of one source were not admitted")
	}
	third := dialAndSend(t, relayAddr)
	if !refused(third) {
		t.Fatal("the third connection of one source was admitted, want it refused")
	}
	waitLog(t, logs, `"result":"source_limit"`)
	if len(counted) != 2 {
		t.Errorf("the upstream saw %d connections, want 2", len(counted))
	}
	_ = a.Close()
	waitFor(t, func() bool {
		c := dialAndSend(t, relayAddr)
		return admitted(c)
	})
}

// TestRelayLimitsAllConnections checks the global limit, with a per-source limit that is higher.
func TestRelayLimitsAllConnections(t *testing.T) {
	relayAddr, logs := startRelay(t, echoUpstream(t), func(r *relay) { r.limits = newLimiter(2, 100) })
	a, b := dialAndSend(t, relayAddr), dialAndSend(t, relayAddr)
	if !admitted(a) || !admitted(b) {
		t.Fatal("the first two connections were not admitted")
	}
	if !refused(dialAndSend(t, relayAddr)) {
		t.Fatal("a connection over the global limit was admitted")
	}
	waitLog(t, logs, `"result":"overloaded"`)
}

// TestLimiterCountsEachSource checks that sources do not share a slot count, that a release frees
// a slot, and that the map holds no entry for a source with no connection.
func TestLimiterCountsEachSource(t *testing.T) {
	l := newLimiter(3, 2)
	for _, src := range []string{"10.0.0.1", "10.0.0.1", "10.0.0.2"} {
		if r := l.acquire(src); r != "" {
			t.Fatalf("acquire %s: %q", src, r)
		}
	}
	if r := l.acquire("10.0.0.1"); r != "overloaded" {
		t.Errorf("a fourth connection gave %q, want overloaded", r)
	}
	l.release("10.0.0.2")
	if r := l.acquire("10.0.0.1"); r != "source_limit" {
		t.Errorf("a third connection of one source gave %q, want source_limit", r)
	}
	if r := l.acquire("10.0.0.3"); r != "" {
		t.Errorf("another source gave %q, want admission", r)
	}
	l.release("10.0.0.1")
	l.release("10.0.0.1")
	l.release("10.0.0.3")
	if len(l.perSource) != 0 || l.total != 0 {
		t.Errorf("after every release: total %d, sources %v, want none", l.total, l.perSource)
	}
}

func TestParseLimits(t *testing.T) {
	if cfg, err := parse([]string{"--route", "8443=127.0.0.1:1"}); err != nil || cfg.maxConns != defaultMaxConns || cfg.maxPerSource != defaultMaxPerSource {
		t.Errorf("defaults: %+v, %v", cfg, err)
	}
	if cfg, err := parse([]string{"--route", "8443=127.0.0.1:1", "--max-conns", "5", "--max-conns-per-source", "3"}); err != nil || cfg.maxConns != 5 || cfg.maxPerSource != 3 {
		t.Errorf("set: %+v, %v", cfg, err)
	}
	for _, bad := range []string{"--max-conns=0", "--max-conns-per-source=0", "--max-conns=-1"} {
		if _, err := parse([]string{"--route", "8443=127.0.0.1:1", bad}); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("the condition did not hold within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

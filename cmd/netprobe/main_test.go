package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestScanFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	got, err := scan(context.Background(), "127.0.0.1", port-2, port+2, 300*time.Millisecond, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int{port}) {
		t.Errorf("open = %v, want [%d]", got, port)
	}
}

func TestParsePorts(t *testing.T) {
	lo, hi, err := parsePorts("20-30")
	if err != nil || lo != 20 || hi != 30 {
		t.Errorf("range: %d %d %v", lo, hi, err)
	}
	lo, hi, err = parsePorts("443")
	if err != nil || lo != 443 || hi != 443 {
		t.Errorf("single: %d %d %v", lo, hi, err)
	}
	for _, bad := range []string{"", "0-5", "9-3", "1-70000", "a"} {
		if _, _, err := parsePorts(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestServeReportsRemote(t *testing.T) {
	srv := httptest.NewServer(handler())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	var local string
	ctx := context.Background()
	dialer := &net.Dialer{}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, n, a)
			if err == nil {
				local = c.LocalAddr().String()
			}
			return c, err
		},
	}}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Remote string `json:"remote"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Remote != local {
		t.Errorf("remote = %q, want %q", out.Remote, local)
	}
	if strings.Contains(out.Remote, "203.0.113.9") {
		t.Error("forwarded header must be ignored")
	}
}

func TestGetPrintsBodyAndFailsOnStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	var sb strings.Builder
	if err := get(context.Background(), srv.URL, &sb, time.Second); err != nil || sb.String() != "hello" {
		t.Errorf("body = %q err = %v", sb.String(), err)
	}
	if err := get(context.Background(), srv.URL+"/bad", &sb, time.Second); err == nil {
		t.Error("want error on 403")
	}
}

func TestScanPrintsOnlyJSON(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	var out strings.Builder
	args := []string{"scan", "--host", "127.0.0.1", "--ports", strconv.Itoa(port)}
	if err := run(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	var got []int
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("stdout is not pure JSON: %q: %v", out.String(), err)
	}
	if !slices.Equal(got, []int{port}) {
		t.Errorf("open = %v, want [%d]", got, port)
	}
}

func TestFailureIsOneJSONErrorLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer srv.Close()
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"scan"},
		{"scan", "--host", "not-an-ip"},
		{"get"},
		{"get", "--url", srv.URL},
		{"get", "--bogus"},
		{"get", "-h"},
		{"scan", "-h"},
		{"scan", "--bogus"},
		{"serve", "--bogus"},
	} {
		var out strings.Builder
		stderr := captureStderr(t)
		code := execute(context.Background(), args, &out)
		if got := stderr(); got != "" {
			t.Errorf("%v: wrote to stderr: %q", args, got)
		}
		if code == 0 {
			t.Errorf("%v: exit code 0, want non-zero", args)
		}
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		if len(lines) != 1 {
			t.Fatalf("%v: %d lines, want 1: %q", args, len(lines), out.String())
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
			t.Fatalf("%v: not JSON: %q: %v", args, lines[0], err)
		}
		if msg, _ := m["error"].(string); msg == "" {
			t.Errorf("%v: no error field: %v", args, m)
		}
	}
}

func TestSuccessPrintsOnlyData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	var out strings.Builder
	stderr := captureStderr(t)
	defer func() {
		if got := stderr(); got != "" {
			t.Errorf("wrote to stderr: %q", got)
		}
	}()
	if code := execute(context.Background(), []string{"get", "--url", srv.URL}, &out); code != 0 || out.String() != "hello" {
		t.Errorf("get: code %d, stdout %q", code, out.String())
	}
	out.Reset()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	if code := execute(context.Background(), []string{"scan", "--host", "127.0.0.1", "--ports", closed}, &out); code != 0 || out.String() != "[]\n" {
		t.Errorf("scan: code %d, stdout %q", code, out.String())
	}
}

func TestServeLogsAreJSON(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	done := make(chan int)
	go func() { done <- execute(ctx, []string{"serve", "--addr", "127.0.0.1:0"}, &out) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "\n") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("serve exit code %d, output %q", code, out.String())
	}
	for _, l := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Errorf("serve log is not JSON: %q: %v", l, err)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

// captureStderr redirects os.Stderr to a pipe and returns a function that restores it and
// returns what was written.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	return func() string {
		os.Stderr = orig
		_ = w.Close()
		b, _ := io.ReadAll(r)
		_ = r.Close()
		return string(b)
	}
}

func dialResult(t *testing.T, args ...string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if code := execute(t.Context(), append([]string{"dial"}, args...), &out); code != 0 {
		t.Fatalf("dial %v: exit %d: %s", args, code, out.String())
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("dial output is not one JSON line: %q", out.String())
	}
	return m
}

func TestDialReportsConnectedAndRefused(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	if r := dialResult(t, "--addr", lis.Addr().String()); r["result"] != "connected" {
		t.Fatalf("open port: %v", r)
	}
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := closed.Addr().String()
	_ = closed.Close()
	if r := dialResult(t, "--addr", addr, "--timeout", "1s"); r["result"] != "refused" || r["addr"] != addr {
		t.Fatalf("closed port: %v", r)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "dial tcp 10.0.0.1:1: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestDialClassifiesErrors(t *testing.T) {
	cases := map[string]error{
		"connected": nil,
		"refused":   &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
		"timeout":   &net.OpError{Op: "dial", Err: timeoutError{}},
		"error":     &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)},
	}
	for want, err := range cases {
		if got := dialClass(err); got != want {
			t.Errorf("dialClass(%v) = %q, want %q", err, got, want)
		}
	}
	if got := dialClass(context.DeadlineExceeded); got != "timeout" {
		t.Errorf("dialClass(context.DeadlineExceeded) = %q, want timeout", got)
	}
}

func TestDialRejectsHostName(t *testing.T) {
	var out bytes.Buffer
	if code := execute(t.Context(), []string{"dial", "--addr", "example.com:80"}, &out); code != 1 || !strings.Contains(out.String(), "IP address") {
		t.Fatalf("exit %d, output %q", code, out.String())
	}
}

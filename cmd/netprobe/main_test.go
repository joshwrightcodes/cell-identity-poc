package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
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

func TestNewLoggerWritesServeLogsToStdout(t *testing.T) {
	var out strings.Builder
	newLogger([]string{"serve"}, &out).Info("serving")
	if !strings.Contains(out.String(), "serving") {
		t.Errorf("serve log missing from stdout: %q", out.String())
	}
	out.Reset()
	newLogger([]string{"scan"}, &out).Info("scanning")
	if out.Len() != 0 {
		t.Errorf("scan log reached stdout: %q", out.String())
	}
}

// Command netprobe is the network probe for the harness tests. It scans TCP ports, reports the
// peer address of each request, and fetches URLs.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	slog.SetDefault(newLogger(os.Args[1:], os.Stdout))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("netprobe failed", "error", err)
		os.Exit(1)
	}
}

// newLogger sends the logs of the long-running serve mode to stdout. The data commands keep
// stdout for their data, so their logs go to stderr.
func newLogger(args []string, stdout io.Writer) *slog.Logger {
	if len(args) > 0 && args[0] == "serve" {
		return slog.New(slog.NewTextHandler(stdout, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: netprobe scan|serve|get")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "scan":
		host := fs.String("host", "", "IP address to scan")
		ports := fs.String("ports", "1-1024", "port or port range")
		timeout := fs.Duration("timeout", 300*time.Millisecond, "connect timeout per port")
		conc := fs.Int("concurrency", 256, "parallel connects")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *host == "" {
			return errors.New("scan needs --host")
		}
		lo, hi, err := parsePorts(*ports)
		if err != nil {
			return err
		}
		open, err := scan(ctx, *host, lo, hi, *timeout, *conc)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(open)
	case "serve":
		addr := fs.String("addr", ":8080", "listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		slog.Info("serving", "addr", *addr)
		srv := &http.Server{Addr: *addr, Handler: handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case "get":
		url := fs.String("url", "", "URL to fetch")
		timeout := fs.Duration("timeout", 10*time.Second, "request timeout")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *url == "" {
			return errors.New("get needs --url")
		}
		return get(ctx, *url, stdout, *timeout)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func parsePorts(s string) (int, int, error) {
	loS, hiS, isRange := strings.Cut(s, "-")
	if !isRange {
		hiS = loS
	}
	lo, err1 := strconv.Atoi(loS)
	hi, err2 := strconv.Atoi(hiS)
	if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	return lo, hi, nil
}

// scan connects to each port in [lo, hi] and returns the ports that accept, in order.
func scan(ctx context.Context, host string, lo, hi int, timeout time.Duration, concurrency int) ([]int, error) {
	if concurrency < 1 {
		return nil, errors.New("concurrency must be at least 1")
	}
	if net.ParseIP(host) == nil {
		return nil, fmt.Errorf("host %q is not an IP address", host)
	}
	open := []int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for p := lo; p <= hi; p++ {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			d := net.Dialer{Timeout: timeout}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				return
			}
			_ = c.Close()
			mu.Lock()
			open = append(open, port)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slices.Sort(open)
	return open, nil
}

// handler answers every request with the peer address of the TCP connection.
func handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"remote": r.RemoteAddr})
	})
}

func get(ctx context.Context, url string, out io.Writer, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return nil
}

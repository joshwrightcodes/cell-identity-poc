// Command netprobe is the network probe for the harness tests. It scans TCP ports, reports the
// peer address of each request, fetches URLs, makes HTTP requests, serves TLS, and reports the
// result of one TCP connect.
//
// get prints the body of one GET and fails on a status of 400 or more. http prints one JSON line
// {"status", "body"} with the first 4 KiB of the body for any status, so a test can check a 403.
// It sends the body from standard input with --body-stdin.
//
// tlsserve reads a PEM certificate chain and a PEM private key from standard input, and serves
// TLS 1.3 with ALPN h2 on --addr. It completes each handshake, asks for no client certificate,
// and then closes the connection when the client sends EOF or after 10 seconds.
//
// dial prints {"addr", "result", "error"} with result connected, refused, timeout or error. A
// NetworkPolicy that drops packets gives timeout. A host that answers with a reset gives refused.
package main

import (
	"context"
	"crypto/tls"
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
	"syscall"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
)

// stdin is the input of tlsserve and of http --body-stdin. Tests replace it.
var stdin io.Reader = os.Stdin

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := execute(ctx, os.Args[1:], os.Stdout)
	stop()
	os.Exit(code)
}

// execute runs one command and returns the exit code. Every log line is compact JSON on stdout.
// A failure is one JSON error line on stdout, so the data commands print only data on success.
func execute(ctx context.Context, args []string, stdout io.Writer) int {
	slog.SetDefault(slog.New(slog.NewJSONHandler(stdout, nil)))
	return cli.Run(stdout, "netprobe", func(out io.Writer) error { return run(ctx, args, out) })
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: netprobe scan|serve|get|http|tlsserve|dial|tlsdial|flipforward|watch")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
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
	case "http":
		method := fs.String("method", "", "HTTP method, for example GET or POST")
		url := fs.String("url", "", "URL of the request")
		bodyStdin := fs.Bool("body-stdin", false, "send standard input as the request body")
		timeout := fs.Duration("timeout", 10*time.Second, "request timeout")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *method == "" || *url == "" {
			return errors.New("http needs --method and --url")
		}
		var body io.Reader
		if *bodyStdin {
			body = stdin
		}
		return httpRequest(ctx, *method, *url, body, stdout, *timeout)
	case "tlsserve":
		addr := fs.String("addr", ":8443", "listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return tlsServe(ctx, *addr)
	case "dial":
		addr := fs.String("addr", "", "IP address and port")
		timeout := fs.Duration("timeout", 3*time.Second, "connect timeout")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		host, _, err := net.SplitHostPort(*addr)
		if err != nil || net.ParseIP(host) == nil {
			return fmt.Errorf("dial needs --addr <IP address>:<port>, got %q", *addr)
		}
		d := net.Dialer{Timeout: *timeout}
		c, err := d.DialContext(ctx, "tcp", *addr)
		if c != nil {
			_ = c.Close()
		}
		out := struct {
			Addr   string `json:"addr"`
			Result string `json:"result"`
			Error  string `json:"error,omitempty"`
		}{Addr: *addr, Result: dialClass(err)}
		if err != nil {
			out.Error = err.Error()
		}
		return json.NewEncoder(stdout).Encode(out)
	case "tlsdial":
		return runTLSDial(ctx, fs, args[1:], stdout)
	case "flipforward":
		return runFlipForward(ctx, fs, args[1:])
	case "watch":
		return runWatch(ctx, fs, args[1:], stdout)
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
	if resp.StatusCode >= 400 {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	_, err = io.Copy(out, resp.Body)
	return err
}

// bodyLimit is the most of a response body that http prints.
const bodyLimit = 4 << 10

// httpRequest sends one request and prints {"status", "body"} for any status.
func httpRequest(ctx context.Context, method, url string, body io.Reader, out io.Writer, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}{resp.StatusCode, string(b)})
}

// tlsServe serves TLS 1.3 with the chain and key from stdin until ctx ends.
func tlsServe(ctx context.Context, addr string) error {
	in, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return fmt.Errorf("read the chain and key from stdin: %w", err)
	}
	// X509KeyPair takes the CERTIFICATE blocks of its first input and the key of its second.
	cert, err := tls.X509KeyPair(in, in)
	clear(in)
	if err != nil {
		return fmt.Errorf("stdin holds no PEM certificate chain and key: %w", err)
	}
	ln, err := tls.Listen("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{cert}})
	if err != nil {
		return err
	}
	slog.Info("serving tls", "addr", ln.Addr().String(), "chain_length", len(cert.Certificate))
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			tc := c.(*tls.Conn)
			if err := tc.HandshakeContext(ctx); err != nil {
				slog.Info("handshake failed", "remote", c.RemoteAddr().String(), "error", err.Error())
				return
			}
			slog.Info("handshake done", "remote", c.RemoteAddr().String(), "alpn", tc.ConnectionState().NegotiatedProtocol)
			n, _ := io.Copy(io.Discard, c)
			slog.Info("connection closed", "remote", c.RemoteAddr().String(), "bytes_after_handshake", n)
		})
	}
}

// dialClass names the outcome of one TCP connect.
func dialClass(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return "connected"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	default:
		return "error"
	}
}

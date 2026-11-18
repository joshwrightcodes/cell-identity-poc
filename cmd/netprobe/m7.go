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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
)

// tlsDialResult is the one output line of tlsdial.
type tlsDialResult struct {
	Addr      string `json:"addr"`
	Handshake string `json:"handshake"`
	Verified  bool   `json:"verified"`
	PeerID    string `json:"peer_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
	After     string `json:"after,omitempty"`
	Error     string `json:"error,omitempty"`
}

// runTLSDial parses the flags of tlsdial and prints one result line.
func runTLSDial(ctx context.Context, fs *flag.FlagSet, args []string, stdout io.Writer) error {
	addr := fs.String("addr", "", "IP address and port")
	expect := fs.String("expect-id", "", "exact SPIFFE ID of the server; empty with --no-verify")
	bundle := fs.String("bundle", "", "PEM file of the roots that the client trusts")
	noVerify := fs.Bool("no-verify", false, "accept any server certificate")
	clientCert := fs.Bool("client-cert-stdin", false, "present the PEM chain and key from stdin")
	source := fs.String("source", "", "local IP address of the dial")
	timeout := fs.Duration("timeout", 5*time.Second, "dial and handshake timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" || (!*noVerify && (*expect == "" || *bundle == "")) {
		return errors.New("tlsdial needs --addr, and --expect-id with --bundle unless --no-verify")
	}
	cfg, err := tlsDialConfig(*expect, *bundle, *noVerify)
	if err != nil {
		return err
	}
	if *clientCert {
		in, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
		if err != nil {
			return fmt.Errorf("read the chain and key from stdin: %w", err)
		}
		cert, err := tls.X509KeyPair(in, in)
		clear(in)
		if err != nil {
			return fmt.Errorf("stdin holds no PEM certificate chain and key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	d := net.Dialer{Timeout: *timeout}
	if *source != "" {
		ip := net.ParseIP(*source)
		if ip == nil {
			return fmt.Errorf("--source needs an IP address, got %q", *source)
		}
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	return json.NewEncoder(stdout).Encode(tlsDial(ctx, &d, *addr, cfg, !*noVerify, *timeout))
}

// tlsDialConfig returns the client config: the cell-proxy pin for an exact ID, or no server check.
func tlsDialConfig(expect, bundlePath string, noVerify bool) (*tls.Config, error) {
	if noVerify {
		return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, InsecureSkipVerify: true}, nil //nolint:gosec // The probe observes what a server does with an unverified client.
	}
	id, err := spiffeid.FromString(expect)
	if err != nil {
		return nil, fmt.Errorf("--expect-id: %w", err)
	}
	b, err := x509bundle.Load(id.TrustDomain(), bundlePath)
	if err != nil {
		return nil, fmt.Errorf("--bundle: %w", err)
	}
	return cellproxy.ProbeTLS(b, id), nil
}

// tlsDial dials addr, runs the handshake and waits up to timeout for the first read. The read
// shows a refusal that a TLS 1.3 server sends after the client has finished its handshake.
func tlsDial(ctx context.Context, d *net.Dialer, addr string, cfg *tls.Config, verified bool, timeout time.Duration) tlsDialResult {
	out := tlsDialResult{Addr: addr}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		out.Handshake = "no_connection"
		out.Error = err.Error()
		return out
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		out.Handshake = "failed"
		out.Reason = string(cellproxy.HandshakeReason(err))
		out.Error = err.Error()
		return out
	}
	out.Handshake = "ok"
	st := c.ConnectionState()
	out.Verified = verified
	if len(st.PeerCertificates) > 0 && len(st.PeerCertificates[0].URIs) > 0 {
		out.PeerID = st.PeerCertificates[0].URIs[0].String()
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Read(make([]byte, 1))
	out.After = afterClass(err)
	return out
}

// afterClass names what the first read after the handshake saw.
func afterClass(err error) string {
	var alert tls.AlertError
	var ne net.Error
	switch {
	case err == nil:
		return "data"
	case errors.As(err, &alert):
		return "alert:" + alert.Error()
	case strings.Contains(err.Error(), "remote error: tls: "):
		// crypto/tls returns an alert from the peer as an OpError with an unexported type.
		_, text, _ := strings.Cut(err.Error(), "remote error: ")
		return "alert:" + text
	case errors.Is(err, io.EOF):
		return "closed"
	case errors.As(err, &ne) && ne.Timeout():
		return "open"
	default:
		return "error:" + err.Error()
	}
}

// runFlipForward parses the flags of flipforward and serves until ctx ends.
func runFlipForward(ctx context.Context, fs *flag.FlagSet, args []string) error {
	listen := fs.String("listen", ":9443", "listen address")
	upstream := fs.String("upstream", "", "address of the upstream")
	flipAt := fs.Int64("flip-at", -1, "offset in the chosen direction of the byte to flip; -1 flips none")
	dir := fs.String("dir", "up", "direction of the flip: up (client to upstream) or down")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *upstream == "" || (*dir != "up" && *dir != "down") {
		return errors.New("flipforward needs --upstream and --dir up|down")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	slog.Info("forwarding", "addr", ln.Addr().String(), "upstream", *upstream, "flip_at", *flipAt, "dir", *dir)
	return flipForward(ctx, ln, *upstream, *flipAt, *dir)
}

// flipForward copies each connection to upstream and back. It flips every bit of the byte at
// offset flipAt of direction dir, and logs the counts of each connection when it closes. It
// never logs the bytes.
func flipForward(ctx context.Context, ln net.Listener, upstream string, flipAt int64, dir string) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	var conns atomic.Int64
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		n := conns.Add(1)
		wg.Go(func() {
			defer c.Close()
			d := net.Dialer{Timeout: 5 * time.Second}
			u, err := d.DialContext(ctx, "tcp", upstream)
			if err != nil {
				slog.Info("upstream failed", "conn", n, "error", err.Error())
				return
			}
			defer u.Close()
			upFlip, downFlip := int64(-1), int64(-1)
			if dir == "up" {
				upFlip = flipAt
			} else {
				downFlip = flipAt
			}
			upScan := &recordScanner{}
			var up, down copyStats
			var inner sync.WaitGroup
			inner.Go(func() { up = copyFlip(u, c, upFlip, upScan) })
			inner.Go(func() { down = copyFlip(c, u, downFlip, nil) })
			inner.Wait()
			slog.Info("connection closed", "conn", n, "bytes_up", up.n, "bytes_down", down.n,
				"flipped", up.flipped || down.flipped, "max_printable_run_up", upScan.maxRun)
		})
	}
}

type copyStats struct {
	n       int64
	flipped bool
}

// copyFlip copies src to dst, flips the byte at offset flipAt, feeds scan, and closes both ends
// when either side ends.
func copyFlip(dst, src net.Conn, flipAt int64, scan *recordScanner) copyStats {
	var st copyStats
	buf := make([]byte, 32*1024)
	for {
		k, err := src.Read(buf)
		if k > 0 {
			chunk := buf[:k]
			if flipAt >= st.n && flipAt < st.n+int64(k) {
				chunk[flipAt-st.n] ^= 0xFF
				st.flipped = true
			}
			if scan != nil {
				scan.Write(chunk)
			}
			st.n += int64(k)
			if _, werr := dst.Write(chunk); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	_ = dst.Close()
	_ = src.Close()
	return st
}

// recordScanner reads a TLS record stream and keeps the longest run of printable ASCII bytes in
// the payloads of application data records (type 23). Plain handshake records, such as the
// ClientHello with its server name, are skipped. It scans at most the first 64 KiB.
type recordScanner struct {
	hdr     [5]byte
	hdrN    int
	left    int
	appData bool
	run     int
	maxRun  int
	seen    int
}

func (s *recordScanner) Write(p []byte) {
	for _, b := range p {
		if s.seen >= 64*1024 {
			return
		}
		s.seen++
		if s.left == 0 {
			s.hdr[s.hdrN] = b
			s.hdrN++
			if s.hdrN == 5 {
				s.hdrN = 0
				s.appData = s.hdr[0] == 23
				s.left = int(s.hdr[3])<<8 | int(s.hdr[4])
				s.run = 0
			}
			continue
		}
		s.left--
		if s.appData && b >= 0x20 && b < 0x7f {
			s.run++
			s.maxRun = max(s.maxRun, s.run)
		} else {
			s.run = 0
		}
	}
}

// runWatch dials addr every interval for a duration and prints one line for each dial.
func runWatch(ctx context.Context, fs *flag.FlagSet, args []string, stdout io.Writer) error {
	addr := fs.String("addr", "", "IP address and port")
	interval := fs.Duration("interval", 100*time.Millisecond, "time between dials")
	dur := fs.Duration("for", 15*time.Second, "how long to dial")
	timeout := fs.Duration("timeout", 300*time.Millisecond, "connect timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		return errors.New("watch needs --addr")
	}
	return watch(ctx, *addr, *interval, *dur, *timeout, stdout)
}

// watch prints {"ms":n,"result":...} for each dial, where ms counts from the start.
func watch(ctx context.Context, addr string, interval, dur, timeout time.Duration, stdout io.Writer) error {
	start := time.Now()
	enc := json.NewEncoder(stdout)
	t := time.NewTicker(interval)
	defer t.Stop()
	for time.Since(start) < dur {
		d := net.Dialer{Timeout: timeout}
		c, err := d.DialContext(ctx, "tcp", addr)
		if c != nil {
			_ = c.Close()
		}
		if err := enc.Encode(struct {
			MS     int64  `json:"ms"`
			Result string `json:"result"`
		}{time.Since(start).Milliseconds(), dialClass(err)}); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
	return nil
}

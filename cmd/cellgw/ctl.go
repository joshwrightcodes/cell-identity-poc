package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
)

const (
	defaultSocket  = "/run/cellgw/admin.sock"
	ctlTimeout     = 60 * time.Second
	maxCtlResponse = 16 << 20
	maxCtlInput    = 1 << 20
	ctlUsage       = "usage: cellgw ctl [--socket <path>] status | queue --cell <c> | enqueue --cell <c> [--replay] | inject | outbox"
)

// euid is replaced by tests.
var euid = os.Geteuid

// listenAdmin listens on the unix socket at path. The socket is made under a restrictive umask and
// then set to mode 0600, and a stale socket file is removed first.
func listenAdmin(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("admin socket directory: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("admin socket path %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale admin socket: %w", err)
		}
	}
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("admin socket mode: %w", err)
	}
	return ln, nil
}

// serveAdmin serves h on ln until ctx ends.
func serveAdmin(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{
		Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv.Shutdown(sctx) != nil {
			_ = srv.Close()
		}
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ctlCommand runs one command against the admin socket and prints its answer as one JSON line.
func ctlCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) int {
	fs := newFlags("ctl")
	socket := fs.String("socket", defaultSocket, "admin socket")
	if err := fs.Parse(args); err != nil {
		cli.Fail(stdout, name, fmt.Errorf("%w; %s", err, ctlUsage))
		return exitConfig
	}
	rest := fs.Args()
	if len(rest) == 0 {
		cli.Fail(stdout, name, errors.New(ctlUsage))
		return exitConfig
	}
	sub := newFlags("ctl " + rest[0])
	cell := sub.String("cell", "", "cell name")
	replay := sub.Bool("replay", false, "delete the row of the operation first")
	if err := parseFlags(sub, rest[1:]); err != nil {
		cli.Fail(stdout, name, fmt.Errorf("%w; %s", err, ctlUsage))
		return exitConfig
	}
	fail := func(msg string) int {
		cli.Fail(stdout, name, errors.New(msg))
		return exitConfig
	}
	if *replay && rest[0] != "enqueue" {
		return fail("--replay applies only to enqueue")
	}
	if *cell != "" && rest[0] != "queue" && rest[0] != "enqueue" {
		return fail("--cell applies only to queue and enqueue")
	}
	var method, path string
	var input bool
	switch rest[0] {
	case "status":
		method, path = http.MethodGet, "/status"
	case "outbox":
		method, path = http.MethodGet, "/outbox"
	case "queue":
		if *cell == "" {
			return fail("queue needs --cell")
		}
		method, path = http.MethodGet, "/queue?cell="+url.QueryEscape(*cell)
	case "enqueue":
		if *cell == "" {
			return fail("enqueue needs --cell")
		}
		method, path, input = http.MethodPost, "/enqueue?cell="+url.QueryEscape(*cell), true
		if *replay {
			path += "&replay=1"
		}
	case "inject":
		method, path, input = http.MethodPost, "/inject", true
	default:
		return fail(fmt.Sprintf("unknown ctl command %q; %s", rest[0], ctlUsage))
	}
	var body []byte
	if input {
		b, err := io.ReadAll(io.LimitReader(stdin, maxCtlInput+1))
		if err != nil {
			cli.Fail(stdout, name, fmt.Errorf("read standard input: %w", err))
			return 1
		}
		if len(b) > maxCtlInput {
			return fail("standard input is above 1 MiB")
		}
		body = b
	}
	return cli.Run(stdout, name, func(out io.Writer) error {
		return ctlRequest(ctx, *socket, method, path, body, out)
	})
}

func ctlRequest(ctx context.Context, socket, method, path string, body []byte, out io.Writer) error {
	if fi, err := os.Lstat(socket); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s is not a socket", socket)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != euid() && euid() != 0 {
			return fmt.Errorf("%s is owned by uid %d, not by this user (uid %d)", socket, st.Uid, euid())
		}
	}
	client := &http.Client{
		Timeout: ctlTimeout,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
	defer client.CloseIdleConnections()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://cellgw"+path, rd)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("admin socket %s: %w", socket, err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxCtlResponse))
	if err != nil {
		return fmt.Errorf("read the answer: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		var e adminFailure
		if json.Unmarshal(answer, &e) == nil && e.Message != "" {
			return &e
		}
		return fmt.Errorf("admin socket answered %s", resp.Status)
	}
	var line bytes.Buffer
	if err := json.Compact(&line, answer); err != nil {
		return fmt.Errorf("the answer is not JSON: %w", err)
	}
	line.WriteByte('\n')
	_, err = out.Write(line.Bytes())
	return err
}

// adminFailure is an error answer of the admin socket. LogAttrs puts the reason on the error
// line, so that a script matches a field and not the text.
type adminFailure struct {
	Message string `json:"error"`
	Reason  string `json:"reason"`
}

func (e *adminFailure) Error() string { return e.Message }

func (e *adminFailure) LogAttrs() []any {
	if e.Reason == "" {
		return nil
	}
	return []any{"reason", e.Reason}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
)

const (
	defaultSocket  = "/run/mgmtd/ctl/admin.sock"
	ctlTimeout     = 60 * time.Second
	maxCtlResponse = 16 << 20
	ctlUsage       = "usage: mgmtd ctl [--socket <path>] [--expect-seq <n>] status | records | pubkey | keys --cell <c> | keycheck --cell <c> | restore --revision <n|latest> | rotate-key"
)

// listenAdmin listens on the unix socket at path. The socket is made under a restrictive umask and
// then set to mode 0600, and a stale socket file is removed first.
func listenAdmin(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	switch info, err := os.Stat(dir); {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("admin socket directory: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("admin socket directory mode: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("admin socket directory: %w", err)
	case !info.IsDir():
		return nil, fmt.Errorf("admin socket directory %s is not a directory", dir)
	case info.Mode().Perm()&0o022 != 0:
		return nil, fmt.Errorf("admin socket directory %s is writable by group or others (mode %v); another container could replace the socket, so mgmtd creates its own directory under the shared volume", dir, info.Mode().Perm())
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
func ctlCommand(ctx context.Context, args []string, stdout io.Writer) int {
	fs := newFlags("ctl")
	socket := fs.String("socket", defaultSocket, "admin socket")
	expect := fs.String("expect-seq", "", "run a change only at this state version")
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
	revision := sub.String("revision", "", "revision counter or latest")
	if err := parseFlags(sub, rest[1:]); err != nil {
		cli.Fail(stdout, name, fmt.Errorf("%w; %s", err, ctlUsage))
		return exitConfig
	}
	query := ""
	if *expect != "" {
		if _, err := strconv.ParseUint(*expect, 10, 64); err != nil {
			cli.Fail(stdout, name, errors.New("--expect-seq must be a state version number"))
			return exitConfig
		}
		query = "?expect-seq=" + *expect
	}
	if query != "" && !slices.Contains([]string{"keycheck", "restore", "rotate-key"}, rest[0]) {
		cli.Fail(stdout, name, fmt.Errorf("--expect-seq applies only to keycheck, restore and rotate-key, not %s", rest[0]))
		return exitConfig
	}
	var method, path string
	switch rest[0] {
	case "status":
		method, path = http.MethodGet, "/status"
	case "records":
		method, path = http.MethodGet, "/records"
	case "pubkey":
		method, path = http.MethodGet, "/pubkey"
	case "keys":
		if *cell == "" {
			cli.Fail(stdout, name, errors.New("keys needs --cell"))
			return exitConfig
		}
		method, path = http.MethodGet, "/keys/"+url.PathEscape(*cell)
	case "keycheck":
		if *cell == "" {
			cli.Fail(stdout, name, errors.New("keycheck needs --cell"))
			return exitConfig
		}
		method, path = http.MethodPost, "/keycheck/"+url.PathEscape(*cell)+query
	case "restore":
		if *revision == "" {
			cli.Fail(stdout, name, errors.New("restore needs --revision"))
			return exitConfig
		}
		method, path = http.MethodPost, "/restore/"+url.PathEscape(*revision)+query
	case "rotate-key":
		method, path = http.MethodPost, "/rotate-key"+query
	default:
		cli.Fail(stdout, name, fmt.Errorf("unknown ctl command %q; %s", rest[0], ctlUsage))
		return exitConfig
	}
	return cli.Run(stdout, name, func(out io.Writer) error {
		return ctlRequest(ctx, *socket, method, path, out)
	})
}

func ctlRequest(ctx context.Context, socket, method, path string, out io.Writer) error {
	client := &http.Client{
		Timeout: ctlTimeout,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, "http://mgmtd"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("admin socket %s: %w", socket, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCtlResponse))
	if err != nil {
		return fmt.Errorf("read the answer: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		var e adminFailure
		if json.Unmarshal(body, &e) == nil && e.Message != "" {
			return &e
		}
		return fmt.Errorf("admin socket answered %s", resp.Status)
	}
	var line bytes.Buffer
	if err := json.Compact(&line, body); err != nil {
		return fmt.Errorf("the answer is not JSON: %w", err)
	}
	line.WriteByte('\n')
	_, err = out.Write(line.Bytes())
	return err
}

// adminFailure is an error answer of the admin socket. LogAttrs puts the reason and the rotated
// flag on the error line, so that a script matches a field and not the text.
type adminFailure struct {
	Message string `json:"error"`
	Reason  string `json:"reason"`
	Rotated bool   `json:"rotated"`
}

func (e *adminFailure) Error() string { return e.Message }

func (e *adminFailure) LogAttrs() []any {
	var a []any
	if e.Reason != "" {
		a = append(a, "reason", e.Reason)
	}
	if e.Rotated {
		a = append(a, "rotated", true)
	}
	return a
}

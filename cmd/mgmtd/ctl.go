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
	ctlUsage       = "usage: mgmtd ctl [--socket <path>] [--expect-seq <n>] status | records | pubkey | keys --cell <c> | keycheck --cell <c> | restore --revision <n|latest> | rotate-key --stage|--commit|--emergency | op create|sign --cell <c> --line <text> [--ttl <d>] | op get|close <id> | op list [--cell <c>]"
)

// Hooks that tests replace.
var (
	euid        = os.Geteuid
	afterListen func()
)

// checkAdminDir makes the directory of the admin socket when it is absent, with mode 0700. It
// refuses an existing directory that its own uid does not own, unless the directory has the sticky
// bit, and one that group or others can write, unless the sticky bit stops them from renaming it.
// It returns the directory as checked.
func checkAdminDir(dir string) (fs.FileInfo, error) {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("admin socket directory: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("admin socket directory mode: %w", err)
		}
		return os.Stat(dir)
	case err != nil:
		return nil, fmt.Errorf("admin socket directory: %w", err)
	case !info.IsDir():
		return nil, fmt.Errorf("admin socket directory %s is not a directory", dir)
	}
	sticky := info.Mode()&os.ModeSticky != 0
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != euid() && !sticky {
		return nil, fmt.Errorf("admin socket directory %s is owned by uid %d, not by this process (uid %d); another uid could replace it", dir, st.Uid, euid())
	}
	if info.Mode().Perm()&0o022 != 0 && !sticky {
		return nil, fmt.Errorf("admin socket directory %s is writable by group or others (mode %v); mgmtd creates its own directory under the shared volume, and the volume must be mounted in the mgmtd container only", dir, info.Mode().Perm())
	}
	return info, nil
}

// listenAdmin listens on the unix socket at path. The socket is made under a restrictive umask and
// then set to mode 0600, and a stale socket file is removed first.
func listenAdmin(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	before, err := checkAdminDir(dir)
	if err != nil {
		return nil, err
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
	if afterListen != nil {
		afterListen()
	}
	// The directory must be the one that passed the check. A rename of the directory between the
	// check and the bind leaves another inode at this path.
	if after, err := os.Stat(dir); err != nil || !os.SameFile(before, after) {
		_ = ln.Close()
		return nil, fmt.Errorf("admin socket directory %s changed while the socket was made", dir)
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
	stage := sub.Bool("stage", false, "rotate-key: make the next signing key")
	commit := sub.Bool("commit", false, "rotate-key: make the staged key the signing key")
	emergency := sub.Bool("emergency", false, "rotate-key: rotate to a new key at once")
	line := sub.String("line", "", "op create, op sign: the line of a demo.append operation")
	ttl := sub.String("ttl", "", "op create, op sign: the lifetime of the operation, for example 10m")
	kind := sub.String("kind", "demo.append", "op create, op sign: the kind of the operation")
	id := sub.String("id", "", "op get, op close: the operation ID")
	subArgs := rest[1:]
	opSub := ""
	if rest[0] == "op" {
		if len(subArgs) == 0 {
			cli.Fail(stdout, name, fmt.Errorf("op needs create, sign, get, list or close; %s", ctlUsage))
			return exitConfig
		}
		opSub, subArgs = subArgs[0], subArgs[1:]
	}
	if err := sub.Parse(subArgs); err != nil {
		cli.Fail(stdout, name, fmt.Errorf("%w; %s", err, ctlUsage))
		return exitConfig
	}
	if sub.NArg() > 0 {
		if opSub != "get" && opSub != "close" || sub.NArg() > 1 || *id != "" {
			cli.Fail(stdout, name, fmt.Errorf("unexpected argument %q; %s", sub.Arg(0), ctlUsage))
			return exitConfig
		}
		*id = sub.Arg(0)
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
	var body io.Reader
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
		modes := 0
		for _, set := range []bool{*stage, *commit, *emergency} {
			if set {
				modes++
			}
		}
		if modes != 1 {
			cli.Fail(stdout, name, errors.New("rotate-key needs exactly one of --stage, --commit and --emergency"))
			return exitConfig
		}
		mode := ""
		switch {
		case *stage:
			mode = "stage=1"
		case *commit:
			mode = "commit=1"
		}
		method, path = http.MethodPost, "/rotate-key"+joinQuery(query, mode)
	case "op":
		var err error
		if method, path, body, err = opRequest(opSub, *cell, *kind, *line, *ttl, *id); err != nil {
			cli.Fail(stdout, name, err)
			return exitConfig
		}
	default:
		cli.Fail(stdout, name, fmt.Errorf("unknown ctl command %q; %s", rest[0], ctlUsage))
		return exitConfig
	}
	return cli.Run(stdout, name, func(out io.Writer) error {
		return ctlRequest(ctx, *socket, method, path, body, out)
	})
}

func ctlRequest(ctx context.Context, socket, method, path string, body io.Reader, out io.Writer) error {
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
	req, err := http.NewRequestWithContext(ctx, method, "http://mgmtd"+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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
	var one bytes.Buffer
	if err := json.Compact(&one, answer); err != nil {
		return fmt.Errorf("the answer is not JSON: %w", err)
	}
	one.WriteByte('\n')
	_, err = out.Write(one.Bytes())
	return err
}

// joinQuery adds the query part extra to query, which is empty or starts with ?.
func joinQuery(query, extra string) string {
	switch {
	case extra == "":
		return query
	case query == "":
		return "?" + extra
	}
	return query + "&" + extra
}

// opRequest returns the admin request of `ctl op <sub>`. create and sign take --cell and --line, and
// sign records the operation and signs it without serving it.
func opRequest(sub, cell, kind, line, ttl, id string) (method, path string, body io.Reader, err error) {
	switch sub {
	case "create", "sign":
		if cell == "" || line == "" {
			return "", "", nil, fmt.Errorf("op %s needs --cell and --line", sub)
		}
		args, err := json.Marshal(map[string]string{"line": line})
		if err != nil {
			return "", "", nil, err
		}
		req, err := json.Marshal(struct {
			Cell string          `json:"cell"`
			Kind string          `json:"kind"`
			Args json.RawMessage `json:"args"`
			TTL  string          `json:"ttl,omitempty"`
		}{cell, kind, args, ttl})
		if err != nil {
			return "", "", nil, err
		}
		path = "/ops"
		if sub == "sign" {
			path += "?serve=0"
		}
		return http.MethodPost, path, bytes.NewReader(req), nil
	case "get", "close":
		if id == "" {
			return "", "", nil, fmt.Errorf("op %s needs an operation ID", sub)
		}
		if sub == "get" {
			return http.MethodGet, "/ops/" + url.PathEscape(id), nil, nil
		}
		return http.MethodPost, "/ops/" + url.PathEscape(id) + "/close", nil, nil
	case "list":
		path = "/ops"
		if cell != "" {
			path += "?cell=" + url.QueryEscape(cell)
		}
		return http.MethodGet, path, nil, nil
	}
	return "", "", nil, fmt.Errorf("unknown op command %q; %s", sub, ctlUsage)
}

// adminFailure is an error answer of the admin socket. LogAttrs puts the reason and the rotated
// flag on the error line, so that a script matches a field and not the text.
type adminFailure struct {
	Message string `json:"error"`
	Reason  string `json:"reason"`
	Rotated bool   `json:"rotated"`
	Staged  bool   `json:"staged"`
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
	if e.Staged {
		a = append(a, "staged", true)
	}
	return a
}

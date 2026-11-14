package hostsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// adminWriteDeadline is the deadline of each write of a followed log. Tests shorten it.
var adminWriteDeadline = 30 * time.Second

// adminFollowPoll is how often a followed log looks for new bytes. Tests shorten it.
var adminFollowPoll = 250 * time.Millisecond

var umaskMu sync.Mutex

// ListenAdmin listens on the Unix socket at path with mode 0600. It refuses a path that exists and
// is not a socket, and removes a stale socket.
func ListenAdmin(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("admin socket path %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale admin socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	umaskMu.Lock()
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	umaskMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// NewAdminServer returns the HTTP server for the admin socket. It has no fixed write timeout,
// because a followed log streams.
func NewAdminServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
}

type adminHandler struct {
	a *Actor
	j *Journal
}

// NewAdminHandler serves the admin socket: GET /steps, GET /log?step=<id>[&follow=1],
// POST /cancel?cell=<c> or ?step=<id>, and POST /reset-journal. The socket mode is the only access
// control.
func NewAdminHandler(a *Actor, j *Journal) http.Handler {
	h := &adminHandler{a: a, j: j}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /steps", h.steps)
	mux.HandleFunc("GET /log", h.log)
	mux.HandleFunc("POST /cancel", h.cancel)
	mux.HandleFunc("POST /reset-journal", h.reset)
	return mux
}

func adminError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *adminHandler) steps(w http.ResponseWriter, _ *http.Request) {
	list := h.j.List()
	out := make([]mgmtapi.StepStatus, 0, len(list))
	for _, e := range list {
		out = append(out, e.Status)
	}
	writeJSON(w, http.StatusOK, map[string]any{"steps": out, "corrupt": h.j.Corrupt()})
}

func (h *adminHandler) cancel(w http.ResponseWriter, r *http.Request) {
	sel := Selector{Cell: r.URL.Query().Get("cell"), ID: r.URL.Query().Get("step")}
	if (sel.Cell == "") == (sel.ID == "") {
		adminError(w, http.StatusBadRequest, "give exactly one of cell and step")
		return
	}
	if err := h.a.Cancel(sel); err != nil {
		adminError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"cancelled": true})
}

func (h *adminHandler) reset(w http.ResponseWriter, _ *http.Request) {
	if err := h.a.ResetJournal(); err != nil {
		adminError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"reset": true})
}

func (h *adminHandler) log(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("step")
	if !stepIDShape.MatchString(id) {
		adminError(w, http.StatusBadRequest, "step must be 32 lowercase hex characters")
		return
	}
	f, err := os.Open(h.j.LogPath(id))
	if err != nil {
		adminError(w, http.StatusNotFound, "no log for this step")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	follow := r.URL.Query().Get("follow") == "1"
	for {
		n, err := f.Read(buf)
		if n > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(adminWriteDeadline))
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return
		}
		if n > 0 {
			continue
		}
		if !follow || h.stepEnded(id) {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(adminFollowPoll):
		}
	}
}

func (h *adminHandler) stepEnded(id string) bool {
	e, ok := h.j.Get(id)
	return !ok || e.Final() || e.Status.State == mgmtapi.StepFailed
}

// AdminClient calls the admin socket.
type AdminClient struct {
	c *http.Client
}

// NewAdminClient returns a client for the socket at path.
func NewAdminClient(path string) *AdminClient {
	return &AdminClient{c: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		DisableKeepAlives: true,
	}}}
}

// Do makes one request and returns the body reader. A status other than 200 is an error that holds
// the message of the host service.
func (c *AdminClient) Do(ctx context.Context, method, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://admin"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		var e struct {
			Error string `json:"error"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if json.Unmarshal(b, &e) != nil || e.Error == "" {
			e.Error = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return nil, errors.New(e.Error)
	}
	return resp.Body, nil
}

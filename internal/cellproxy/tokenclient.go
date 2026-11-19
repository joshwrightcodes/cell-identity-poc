package cellproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxTokenFile bounds the size of the token file.
const maxTokenFile = 16 << 10

// TokenClientConfig configures a token client. Upstream is the host:port of the store proxy, the
// only host that the client sends requests to. TokenFile holds the bearer token, which the client
// reads again for every request, so a rotated token takes effect at once.
type TokenClientConfig struct {
	Upstream  string
	TokenFile string
	Log       *slog.Logger
	// UpstreamTimeout bounds the wait for the response header of the upstream. Zero selects 60 seconds.
	UpstreamTimeout time.Duration
}

// NewTokenClient returns a handler that sends each request to Upstream with the token of
// TokenFile as the Authorization header. It replaces any Authorization header of the caller. It
// serves plain HTTP, so the caller must bind it to a loopback address.
func NewTokenClient(cfg TokenClientConfig) (http.Handler, error) {
	if cfg.Upstream == "" || cfg.TokenFile == "" {
		return nil, errors.New("token client needs an upstream and a token file")
	}
	target := &url.URL{Scheme: "http", Host: cfg.Upstream}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	c := &tokenClient{file: cfg.TokenFile, log: log}
	c.proxy = &httputil.ReverseProxy{
		Transport: upstreamTransport(cfg.UpstreamTimeout),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("Authorization", "Bearer "+pr.Out.Context().Value(tokenKey{}).(string))
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			refuse(w, r, log, UpstreamUnavailable, err.Error())
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return c, nil
}

type tokenKey struct{}

type tokenClient struct {
	file  string
	log   *slog.Logger
	proxy *httputil.ReverseProxy
}

func (c *tokenClient) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, err := readTokenFile(c.file)
	if err != nil {
		refuse(w, r, c.log, UpstreamUnavailable, err.Error())
		return
	}
	c.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenKey{}, token)))
}

// readTokenFile returns the trimmed token in path. It never returns the token in an error.
func readTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("token file cannot be opened")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	if err != nil {
		return "", errors.New("token file cannot be read")
	}
	if len(b) > maxTokenFile {
		return "", fmt.Errorf("token file is larger than %d bytes", maxTokenFile)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", errors.New("token file is empty")
	}
	if strings.ContainsAny(token, "\r\n\x00 ") {
		return "", errors.New("token file holds more than one token")
	}
	return token, nil
}

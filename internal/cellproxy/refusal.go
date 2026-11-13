package cellproxy

import (
	"context"
	"log/slog"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
)

const (
	refusalWindow  = 10 * time.Second
	maxRefusalKeys = 256
)

// refusalLog writes refusal lines with a reason and the remote address. It writes at most one
// line for each message, reason and peer ID in refusalWindow, and the next line carries the
// number of lines that it held back as suppressed.
type refusalLog struct {
	log   *slog.Logger
	limit *lograte.Limiter
}

func newRefusalLog(log *slog.Logger) *refusalLog {
	return &refusalLog{log: log, limit: lograte.New(refusalWindow, maxRefusalKeys, time.Now)}
}

// write logs one refusal. An unverified ID goes in unverified_spiffe_id, so it never looks like a
// verified peer. A missing client certificate logs at Debug, because every probe causes one.
func (r *refusalLog) write(msg string, reason Reason, remote, id string, err error) {
	_, ok, suppressed, held := r.limit.Allow(msg + "|" + string(reason) + "|" + id)
	for _, h := range held {
		r.log.Warn("refusals suppressed", "key", h.Key, "suppressed", h.Suppressed)
	}
	if !ok {
		return
	}
	args := []any{"reason", string(reason), "remote", remote}
	if id != "" {
		key := "spiffe_id"
		if reason == PeerUntrusted {
			key = "unverified_spiffe_id"
		}
		args = append(args, key, id)
	}
	if err != nil {
		args = append(args, "error", err.Error())
	}
	if suppressed > 0 {
		args = append(args, "suppressed", suppressed)
	}
	level := slog.LevelWarn
	if reason == NoClientCert {
		level = slog.LevelDebug
	}
	r.log.Log(context.Background(), level, msg, args...)
}

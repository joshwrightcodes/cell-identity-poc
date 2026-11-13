package telemetry

import (
	"io"
	"log/slog"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
)

const (
	// errorWindow is the shortest time between two lines for one error message.
	errorWindow = 10 * time.Second
	// maxTrackedErrors bounds the number of distinct messages that the handler remembers. Further
	// messages share one limited key.
	maxTrackedErrors = 256
)

// errorHandler writes each SDK error as one JSON line to stdout, never to the OTLP bridge. It
// writes at most one line for each distinct message in errorWindow. The next line for that
// message carries the number of errors that it held back as suppressed. A message that the
// handler forgets with held-back errors gets a "telemetry errors suppressed" line.
type errorHandler struct {
	log   *slog.Logger
	limit *lograte.Limiter
}

func newErrorHandler(stdout io.Writer, now func() time.Time) *errorHandler {
	return &errorHandler{log: slog.New(slog.NewJSONHandler(stdout, nil)), limit: lograte.New(errorWindow, maxTrackedErrors, now)}
}

// Handle implements otel.ErrorHandler.
func (h *errorHandler) Handle(err error) {
	msg := err.Error()
	_, ok, suppressed, held := h.limit.Allow(msg)
	for _, x := range held {
		h.log.Warn("telemetry errors suppressed", "error", x.Key, "suppressed", x.Suppressed)
	}
	if ok {
		h.log.Warn("telemetry error", "error", msg, "suppressed", suppressed)
	}
}

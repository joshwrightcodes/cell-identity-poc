package telemetry

import (
	"io"
	"log/slog"
	"sync"
	"time"
)

const (
	// errorWindow is the shortest time between two lines for one error message.
	errorWindow = 10 * time.Second
	// maxTrackedErrors bounds the number of distinct messages that the handler remembers.
	maxTrackedErrors = 256
)

// errorHandler writes each SDK error as one JSON line to stdout, never to the OTLP bridge. It
// writes at most one line for each distinct message in errorWindow. The next line for that
// message carries the number of lines that it held back as suppressed.
type errorHandler struct {
	log *slog.Logger
	now func() time.Time

	mu   sync.Mutex
	seen map[string]*errorState
}

type errorState struct {
	last       time.Time
	suppressed int
}

func newErrorHandler(stdout io.Writer, now func() time.Time) *errorHandler {
	return &errorHandler{log: slog.New(slog.NewJSONHandler(stdout, nil)), now: now, seen: map[string]*errorState{}}
}

// Handle implements otel.ErrorHandler.
func (h *errorHandler) Handle(err error) {
	msg := err.Error()
	now := h.now()
	h.mu.Lock()
	st, ok := h.seen[msg]
	if ok && now.Sub(st.last) < errorWindow {
		st.suppressed++
		h.mu.Unlock()
		return
	}
	suppressed := 0
	if ok {
		suppressed = st.suppressed
	} else {
		h.prune(now)
	}
	if ok || len(h.seen) < maxTrackedErrors {
		h.seen[msg] = &errorState{last: now}
	}
	h.mu.Unlock()
	h.log.Warn("telemetry error", "error", msg, "suppressed", suppressed)
}

// prune forgets the messages whose window has passed, once the map is full.
func (h *errorHandler) prune(now time.Time) {
	if len(h.seen) < maxTrackedErrors {
		return
	}
	for msg, st := range h.seen {
		if now.Sub(st.last) >= errorWindow {
			delete(h.seen, msg)
		}
	}
}

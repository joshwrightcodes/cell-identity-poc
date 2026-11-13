// Package cli holds the output rule of the bespoke commands. A command whose standard output
// carries data prints only that data on success. On failure it prints one compact JSON error line
// on standard output instead, and exits with a non-zero status.
package cli

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
)

// Attrs is an error that adds its own key and value pairs to the error line. The keys time,
// level, msg and error belong to the line itself, so LogAttrs must not use them.
type Attrs interface {
	error
	LogAttrs() []any
}

// Fail writes the error line "<name> failed" with the text of err to w. When err or an error that
// it wraps is an Attrs, the line also carries its pairs.
func Fail(w io.Writer, name string, err error) {
	args := []any{"error", err.Error()}
	var a Attrs
	if errors.As(err, &a) {
		args = append(args, a.LogAttrs()...)
	}
	slog.New(slog.NewJSONHandler(w, nil)).Error(name+" failed", args...)
}

// Run runs fn with a buffer for its data. On success it copies the data to w and returns 0. On
// failure it drops the data, writes the error line and returns 1, so no partial data reaches w.
func Run(w io.Writer, name string, fn func(out io.Writer) error) int {
	var out bytes.Buffer
	if err := fn(&out); err != nil {
		Fail(w, name, err)
		return 1
	}
	if _, err := w.Write(out.Bytes()); err != nil {
		return 1
	}
	return 0
}

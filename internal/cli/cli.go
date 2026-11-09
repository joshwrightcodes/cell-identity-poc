// Package cli holds the output rule of the bespoke commands. A command whose standard output
// carries data prints only that data on success. On failure it prints one compact JSON error line
// on standard output instead, and exits with a non-zero status.
package cli

import (
	"bytes"
	"io"
	"log/slog"
)

// Fail writes the error line "<name> failed" with the text of err to w.
func Fail(w io.Writer, name string, err error) {
	slog.New(slog.NewJSONHandler(w, nil)).Error(name+" failed", "error", err.Error())
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

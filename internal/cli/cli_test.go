package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestRunPrintsTheDataOnSuccess(t *testing.T) {
	var w bytes.Buffer
	code := Run(&w, "probe", func(out io.Writer) error {
		_, err := io.WriteString(out, "data\n")
		return err
	})
	if code != 0 || w.String() != "data\n" {
		t.Fatalf("code %d, output %q; want 0 and the data only", code, w.String())
	}
}

// A command that fails after it wrote part of its data prints only the error line.
func TestRunPrintsOneErrorLineAndNoPartialData(t *testing.T) {
	var w bytes.Buffer
	code := Run(&w, "probe", func(out io.Writer) error {
		_, _ = io.WriteString(out, `{"partial":`)
		return errors.New("connection reset")
	})
	if code != 1 {
		t.Fatalf("code %d, want 1", code)
	}
	assertErrorLine(t, w.String(), "probe failed", "connection reset")
}

func TestFailWritesOneErrorLine(t *testing.T) {
	var w bytes.Buffer
	Fail(&w, "celld", errors.New("no socket"))
	assertErrorLine(t, w.String(), "celld failed", "no socket")
}

func assertErrorLine(t *testing.T, out, msg, text string) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one line, got %q", out)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("line %q is not JSON: %v", lines[0], err)
	}
	if rec["level"] != "ERROR" || rec["msg"] != msg || rec["error"] != text {
		t.Fatalf("line %v, want level ERROR, msg %q and error %q", rec, msg, text)
	}
}

type reasonError struct{ error }

func (e reasonError) LogAttrs() []any { return []any{"reason", "peer_not_allowed"} }

// An error with its own attributes adds them to the error line, also when it is wrapped.
func TestFailAddsTheAttributesOfTheError(t *testing.T) {
	var w bytes.Buffer
	code := Run(&w, "probe", func(io.Writer) error {
		return fmt.Errorf("handshake: %w", reasonError{errors.New("wrong server")})
	})
	if code != 1 {
		t.Fatalf("code %d, want 1", code)
	}
	assertErrorLine(t, w.String(), "probe failed", "handshake: wrong server")
	var rec map[string]any
	if err := json.Unmarshal(w.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["reason"] != "peer_not_allowed" {
		t.Fatalf("line %v has no reason", rec)
	}
}

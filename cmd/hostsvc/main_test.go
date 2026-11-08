package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// jsonLines parses every line of out as a JSON object and fails if any line is not one.
func jsonLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("line is not a JSON object: %q: %v", l, err)
		}
		lines = append(lines, m)
	}
	return lines
}

func TestFailureIsOneJSONErrorLine(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"facts"},
		{"facts", "--cluster", "nope", "--topology", "does-not-exist.yaml"},
	} {
		var out strings.Builder
		if code := execute(context.Background(), args, &out); code == 0 {
			t.Errorf("%v: exit code 0, want non-zero", args)
		}
		lines := jsonLines(t, out.String())
		if len(lines) != 1 {
			t.Fatalf("%v: %d lines, want 1: %q", args, len(lines), out.String())
		}
		if msg, _ := lines[0]["error"].(string); msg == "" {
			t.Errorf("%v: no error field: %v", args, lines[0])
		}
	}
}

func TestLogsAreCompactJSON(t *testing.T) {
	var out strings.Builder
	execute(context.Background(), []string{"bogus"}, &out)
	if strings.Contains(out.String(), "\n  ") {
		t.Errorf("log is not compact: %q", out.String())
	}
}

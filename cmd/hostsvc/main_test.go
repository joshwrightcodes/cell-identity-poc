package main

import (
	"strings"
	"testing"
)

func TestNewLoggerStreams(t *testing.T) {
	for cmd, wantStdout := range map[string]bool{"up": true, "down": true, "facts": false} {
		var out strings.Builder
		newLogger([]string{cmd}, &out).Info("progress")
		if got := out.Len() > 0; got != wantStdout {
			t.Errorf("%s: log on stdout = %v, want %v", cmd, got, wantStdout)
		}
	}
}

package cellproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"testing"
)

func TestTLSReason(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want Reason
	}{
		"peer error":    {fmt.Errorf("dial: %w", &PeerError{Reason: PeerNotAllowed, Err: errors.New("x")}), PeerNotAllowed},
		"alert":         {fmt.Errorf("dial: %w", tls.AlertError(42)), HandshakeFailed},
		"record header": {tls.RecordHeaderError{Msg: "bad"}, HandshakeFailed},
		"not tls":       {errors.New("connection refused"), ""},
	} {
		if got := TLSReason(tc.err); got != tc.want {
			t.Errorf("%s: TLSReason = %q, want %q", name, got, tc.want)
		}
	}
}

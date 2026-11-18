//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
)

const (
	// relayCell is the cell whose node the flipforward pod runs on, so the relay of dev-cp admits its source.
	relayCell = "dev-cell-1"
	// relayIdentityCell is the cell whose SVID and proof the client sends. The tests never call Authenticate, so the stream of the
	// real agent of this cell stays up.
	relayIdentityCell = "dev-cell-2"
	// printableRunLimit is the longest run of printable ASCII bytes that ciphertext may hold in the test. A request in the clear, with a
	// proof token, holds runs of hundreds of bytes.
	printableRunLimit = 16
)

func relayUpstream(t *testing.T) string {
	t.Helper()
	return net.JoinHostPort(clusterFacts(t, envCluster).NodeIP, fmt.Sprint(relayViewPort))
}

func relayClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	_, cert := svidFor(t, envCluster, "spiffe://"+envTrustDomain+"/cell/"+relayIdentityCell+"/argocd-agent")
	return cert
}

// principalAccepted counts the "peer accepted" lines for the identity of the test in the cell-proxy log of the principal pod since a time.
func principalAccepted(t *testing.T, since time.Time) int {
	t.Helper()
	pod, _, _ := principalPod(t)
	logs, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "logs", pod, "-c", viewCellProxy, "--since-time="+since.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	id := "spiffe://" + envTrustDomain + "/cell/" + relayIdentityCell + "/argocd-agent"
	return len(matching(logs, func(l logLine) bool { return l.str("msg") == "peer accepted" && l.str("spiffe_id") == id }))
}

// requireNoPrincipalAccept fails the test as soon as the principal logs a "peer accepted" line for the identity of the test since a
// time. It reads the log for 15 seconds, because the principal can log the line after the client has seen the connection end.
func requireNoPrincipalAccept(t *testing.T, since time.Time) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if n := principalAccepted(t, since); n != 0 {
			t.Errorf("the principal accepted %d connections of %s after the flip, want 0", n, relayIdentityCell)
			return
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Second)
	}
}

// TestM7RelayForwardsCiphertextOnly sends one mutual TLS connection with the SVID and the proof of a cell through flipforward, which
// flips nothing, to the relay of dev-cp. The principal answers the HTTP/2 preface. The upstream half of the connection holds no run of
// 16 printable bytes in its application data records, so the proof token and the request travel as ciphertext.
func TestM7RelayForwardsCiphertextOnly(t *testing.T) {
	ns := m7Namespace(t, relayCell, false)
	addr, conns := startFlipForward(t, relayCell, ns, relayUpstream(t), -1, "up")
	if err := viewDial(t, addr, relayIdentityCell, relayClientCert(t), streamProof(t, relayIdentityCell, "argocd-agent")); err != nil {
		t.Fatalf("the request through flipforward with no flip failed: %v", err)
	}
	got := waitConns(t, "the request with no flip", conns, 1)
	c := got[0]
	if c.Flipped || !c.TLS || c.BytesUp == 0 || c.BytesDown == 0 {
		t.Errorf("connection %+v, want no flip, TLS records only, and bytes in both directions", c)
	}
	if c.MaxRunUp >= printableRunLimit {
		t.Errorf("the upstream half holds a printable run of %d bytes, want fewer than %d", c.MaxRunUp, printableRunLimit)
	}
	t.Logf("flipforward relayed %d bytes up and %d bytes down, longest printable run %d", c.BytesUp, c.BytesDown, c.MaxRunUp)
}

// relayControl sends one clean request through a forwarder that flips nothing, in the namespace of the flip test, and requires that it
// succeeds and that the principal accepts exactly one connection of the identity of the test. A flip test that failed because the relay
// or the principal was down would pass its own checks, so the control comes first.
func relayControl(t *testing.T, ns string) {
	t.Helper()
	addr, conns := startFlipForward(t, relayCell, ns, relayUpstream(t), -1, "up")
	since := time.Now().Add(-2 * time.Second)
	if err := viewDial(t, addr, relayIdentityCell, relayClientCert(t), streamProof(t, relayIdentityCell, "argocd-agent")); err != nil {
		t.Fatalf("the control request through flipforward with no flip failed, so a flip test would prove nothing: %v", err)
	}
	waitConns(t, "the control request", conns, 1)
	waitFor(t, "the principal accepts the control connection", time.Minute, func() (bool, string) {
		n := principalAccepted(t, since)
		return n == 1, fmt.Sprintf("%d accepted connections", n)
	})
}

// TestM7RelayAlteredHandshakeFails flips one byte of the ClientHello (offset 100, upstream). The client handshake fails, and the
// principal logs no accepted peer for the identity of the test. The client reason is handshake_failed, and the server answered, so the
// failure comes from the altered bytes and not from a relay that was down. A clean control request goes first.
func TestM7RelayAlteredHandshakeFails(t *testing.T) {
	ns := m7Namespace(t, relayCell, false)
	relayControl(t, ns)
	addr, conns := startFlipForward(t, relayCell, ns, relayUpstream(t), 100, "up")
	cert, proofToken := relayClientCert(t), streamProof(t, relayIdentityCell, "argocd-agent")
	since := time.Now().Add(-2 * time.Second)
	err := viewDial(t, addr, relayIdentityCell, cert, proofToken)
	if err == nil {
		t.Fatal("the client finished a request through flipforward with a flipped byte in its ClientHello")
	}
	if reason := cellproxy.TLSReason(err); reason != cellproxy.HandshakeFailed {
		t.Errorf("the client failed with reason %q: %v, want %s", reason, err, cellproxy.HandshakeFailed)
	}
	if c := waitConns(t, "the altered handshake", conns, 1)[0]; !c.Flipped || c.BytesDown == 0 {
		t.Errorf("connection %+v, want a flipped byte and an answer from the server", c)
	}
	requireNoPrincipalAccept(t, since)
}

// handshakeUpBytes returns how many bytes the client sends upstream before its first application byte, from a connection that ends
// after its handshake. The client closes the TCP connection with no close_notify, so the count holds the handshake only.
func handshakeUpBytes(t *testing.T, cell string, ns, upstream string) int64 {
	t.Helper()
	addr, conns := startFlipForward(t, cell, ns, upstream, -1, "up")
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, streamClientConfig(t, "argocd-agent", relayClientCert(t)))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		t.Fatalf("the handshake through flipforward with no flip failed: %v", err)
	}
	_ = raw.Close()
	c := waitConns(t, "the handshake only", conns, 1)[0]
	if c.BytesUp == 0 {
		t.Fatalf("the handshake sent no bytes upstream: %+v", c)
	}
	return c.BytesUp
}

// TestM7RelayAlteredRecordFails flips one byte in the first application data record that the client sends, which is the proof frame.
// flipforward counts the handshake bytes of an unaltered connection first, and flips the byte 20 bytes after them, so the byte is in
// the payload of the first record. The TLS layer of the principal refuses the record, the connection closes, and the principal logs
// no accepted peer for the identity of the test, so its backend receives no request from the connection.
func TestM7RelayAlteredRecordFails(t *testing.T) {
	ns := m7Namespace(t, relayCell, false)
	relayControl(t, ns)
	hs := handshakeUpBytes(t, relayCell, ns, relayUpstream(t))
	flipAt := hs + 20
	t.Logf("the handshake sends %d bytes upstream, so the flip is at offset %d", hs, flipAt)
	addr, conns := startFlipForward(t, relayCell, ns, relayUpstream(t), flipAt, "up")
	cert, proofToken := relayClientCert(t), streamProof(t, relayIdentityCell, "argocd-agent")
	since := time.Now().Add(-2 * time.Second)
	err := viewDial(t, addr, relayIdentityCell, cert, proofToken)
	if err == nil {
		t.Fatal("the client finished a request through flipforward with a flipped byte in its proof record")
	}
	t.Logf("the client failed: %v", err)
	c := waitConns(t, "the altered record", conns, 1)[0]
	if !c.Flipped || c.BytesDown == 0 {
		t.Errorf("connection %+v, want a flipped byte and an answer from the server", c)
	}
	t.Logf("flipforward relayed %d bytes up and %d bytes down before the connection closed", c.BytesUp, c.BytesDown)
	requireNoPrincipalAccept(t, since)
}

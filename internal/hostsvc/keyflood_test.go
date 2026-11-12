package hostsvc

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

// floodAttacker opens a connection in the given mode, waits until the server drops it, and opens
// the next one when the shared rate allows. It stops when stop closes.
func floodAttacker(mode, addr string, stop <-chan struct{}, rate <-chan time.Time) {
	for {
		select {
		case <-stop:
			return
		case <-rate:
		}
		switch mode {
		case "nocert":
			// A full ClientHello and a finished handshake, with no client certificate.
			c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
			if err == nil {
				_ = c.SetReadDeadline(time.Now().Add(7 * time.Second))
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}
		default:
			c, err := net.Dial("tcp", addr)
			if err != nil {
				time.Sleep(time.Millisecond)
				continue
			}
			if mode == "onebyte" {
				_, _ = c.Write([]byte{0x16})
			}
			_ = c.SetReadDeadline(time.Now().Add(7 * time.Second))
			_, _ = io.Copy(io.Discard, c)
			c.Close()
		}
	}
}

// The attackers run in a second process, as a real attacker does. In the same process they would
// take the processors that the accept loop of the server needs.
func TestFloodHelperProcess(t *testing.T) {
	mode := os.Getenv("FLOOD_MODE")
	if mode == "" {
		t.Skip("helper process of TestKeyServerSurvivesFloods")
	}
	n, _ := strconv.Atoi(os.Getenv("FLOOD_N"))
	// The attacker takes at most a quarter of the processors, like one process on a shared host.
	runtime.GOMAXPROCS(max(1, runtime.NumCPU()/4))
	// A cap far above what the server can serve, so that a run cannot use up the local port range
	// (a closed connection holds its port for 30 s).
	tick := time.NewTicker(time.Second / 20000)
	stop := make(chan struct{})
	for range n {
		go floodAttacker(mode, os.Getenv("FLOOD_ADDR"), stop, tick.C)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func startFlood(t *testing.T, mode string, n int, addr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFloodHelperProcess$")
	cmd.Env = append(os.Environ(), "FLOOD_MODE="+mode, "FLOOD_N="+strconv.Itoa(n), "FLOOD_ADDR="+addr)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
}

// Floods of connections that never present a valid client certificate must not stop mgmtd from
// reading keys, whatever the mode and the size, below the cap of pending handshakes.
func TestKeyServerSurvivesFloods(t *testing.T) {
	rows := []struct {
		mode string
		n    int
	}{
		{"silent", 9}, {"silent", 16}, {"silent", 300}, {"silent", 1000},
		{"onebyte", 9}, {"onebyte", 16}, {"onebyte", 300},
		{"nocert", 16}, {"nocert", 300},
	}
	for _, row := range rows {
		t.Run(fmt.Sprintf("%s_%d", row.mode, row.n), func(t *testing.T) {
			ca := spiffetest.NewCA(t, "mgmt.poc.internal")
			addr, cert := keyServer(t, ca.Bundle(), &lookups{})
			sum := sha256.Sum256(cert.Leaf.Raw)
			c, err := NewKeyClient(KeyClientConfig{Addr: addr, ServerName: KeyServerHost, Pin: sum[:], SVIDs: ca.Source(t, mgmtdID), Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			startFlood(t, row.mode, row.n, addr)
			time.Sleep(400 * time.Millisecond)
			for i := 1; i <= 20; i++ {
				start := time.Now()
				if _, err := c.Keys(t.Context(), "dev-cell-1"); err != nil {
					t.Fatalf("key read %d of 20 failed during the flood after %v: %v", i, time.Since(start), err)
				}
			}
		})
	}
}

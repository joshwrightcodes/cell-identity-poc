package e2e

// The pure part of the gateway_refuses check of the M9 revoke tests: the decision on the gateway log lines. This file has no build tag
// and imports the standard library only.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// m9GwLine is one JSON line of the gateway log.
type m9GwLine map[string]any

func (l m9GwLine) str(k string) string {
	s, _ := l[k].(string)
	return s
}

func (l m9GwLine) at() time.Time {
	at, _ := time.Parse(time.RFC3339Nano, l.str("time"))
	return at
}

// m9GwParse returns the JSON lines of a gateway log, in log order.
func m9GwParse(logs string) []m9GwLine {
	var out []m9GwLine
	for line := range strings.SplitSeq(logs, "\n") {
		var l m9GwLine
		if json.Unmarshal([]byte(line), &l) == nil {
			out = append(out, l)
		}
	}
	return out
}

// m9GwOpenPod returns the pod of the last stream_open of the cell that was logged before a time, or "".
func m9GwOpenPod(lines []m9GwLine, cell string, before time.Time) string {
	var pod string
	var last time.Time
	for _, l := range lines {
		if l.str("msg") == "stream_open" && l.str("cell") == cell && l.at().Before(before) && !l.at().Before(last) {
			pod, last = l.str("pod"), l.at()
		}
	}
	return pod
}

// m9GwEnded decides whether the log proves that the gateway ended the open stream of the cell (the stream of pod) after since.
// Outcome one: stream_refused cell_revoked with the pod of the open stream. Outcome two: the stream of that pod closed, a later
// stream_refused cell_revoked has no pod field (the gateway refuses before it reads the hello), and the gateway logged no stream_open
// of the cell after the close. It returns the time of the first line of the proof and a description of what was found.
func m9GwEnded(lines []m9GwLine, cell, pod string, since time.Time) (time.Time, string, bool) {
	if pod == "" {
		return time.Time{}, "the pod of the open stream is not known", false
	}
	var refusedWithPod, closed, refusedNoPod time.Time
	for _, l := range lines {
		lt := l.at()
		if lt.Before(since) || l.str("cell") != cell {
			continue
		}
		_, withPod := l["pod"]
		switch {
		case l.str("msg") == "stream_refused" && l.str("reason") == "cell_revoked" && withPod && l.str("pod") == pod:
			if refusedWithPod.IsZero() || lt.Before(refusedWithPod) {
				refusedWithPod = lt
			}
		case l.str("msg") == "stream_closed" && l.str("pod") == pod:
			if closed.IsZero() || lt.Before(closed) {
				closed = lt
			}
		}
	}
	if !refusedWithPod.IsZero() {
		return refusedWithPod, "stream_refused cell_revoked with the pod " + pod, true
	}
	if closed.IsZero() {
		return time.Time{}, "no stream_refused with the pod " + pod + " and no stream_closed of that pod", false
	}
	for _, l := range lines {
		lt := l.at()
		if l.str("cell") != cell || lt.Before(closed) {
			continue
		}
		if _, withPod := l["pod"]; l.str("msg") == "stream_refused" && l.str("reason") == "cell_revoked" && !withPod {
			refusedNoPod = lt
			break
		}
	}
	if refusedNoPod.IsZero() {
		return time.Time{}, "the stream of the pod " + pod + " closed, and no stream_refused cell_revoked without a pod follows", false
	}
	for _, l := range lines {
		if l.str("msg") == "stream_open" && l.str("cell") == cell && l.at().After(closed) {
			return time.Time{}, "the gateway logged stream_open of " + cell + " at " + l.str("time") + ", after the close of the stream", false
		}
	}
	return closed, "the stream of the pod " + pod + " closed, then stream_refused cell_revoked without a pod, and no new stream_open", true
}

func gwJSON(t time.Time, fields string) string {
	return `{"time":"` + t.Format(time.RFC3339Nano) + `",` + fields + `}` + "\n"
}

func TestGatewayEndedDecision(t *testing.T) {
	base := time.Date(2026, 11, 22, 20, 30, 0, 0, time.UTC)
	at := func(s float64) time.Time { return base.Add(time.Duration(s * float64(time.Second))) }
	since := at(20)
	open := gwJSON(at(11), `"msg":"stream_open","cell":"c2","pod":"p1"`)
	refPod := func(s float64, pod string) string {
		return gwJSON(at(s), `"msg":"stream_refused","cell":"c2","reason":"cell_revoked","pod":"`+pod+`"`)
	}
	refNone := func(s float64) string {
		return gwJSON(at(s), `"msg":"stream_refused","cell":"c2","reason":"cell_revoked"`)
	}
	closedAt := func(s float64, pod string) string {
		return gwJSON(at(s), `"msg":"stream_closed","cell":"c2","pod":"`+pod+`"`)
	}
	reopen := func(s float64) string { return gwJSON(at(s), `"msg":"stream_open","cell":"c2","pod":"p2"`) }

	cases := []struct {
		name string
		logs string
		pod  string
		want bool
		when float64
	}{
		{"refused with the pod", open + refPod(30, "p1"), "p1", true, 30},
		{"closed then refused without a pod", open + closedAt(42.771, "p1") + refNone(42.776) + refNone(43.4), "p1", true, 42.771},
		{"refused with another pod", open + refPod(30, "p9"), "p1", false, 0},
		{"closed of another pod then refused without a pod", open + closedAt(42, "p9") + refNone(43), "p1", false, 0},
		{"new stream_open after the close", open + closedAt(42, "p1") + reopen(42.5) + refNone(43), "p1", false, 0},
		{"new stream_open after the refusal", open + closedAt(42, "p1") + refNone(43) + reopen(50), "p1", false, 0},
		{"closed and no refusal", open + closedAt(42, "p1"), "p1", false, 0},
		{"refusal without a pod and no close", open + refNone(43), "p1", false, 0},
		{"close before since", open + closedAt(15, "p1") + refNone(43), "p1", false, 0},
		{"pod not known", open + refPod(30, "p1"), "", false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why, ok := m9GwEnded(m9GwParse(c.logs), "c2", c.pod, since)
			if ok != c.want {
				t.Fatalf("got %v (%s), want %v", ok, why, c.want)
			}
			if ok && !got.Equal(at(c.when)) {
				t.Errorf("ended at %s, want %s", got, at(c.when))
			}
		})
	}
}

func TestGatewayOpenPod(t *testing.T) {
	base := time.Date(2026, 11, 22, 20, 30, 0, 0, time.UTC)
	logs := gwJSON(base, `"msg":"stream_open","cell":"c2","pod":"p1"`) +
		gwJSON(base.Add(5*time.Second), `"msg":"stream_open","cell":"c1","pod":"x"`) +
		gwJSON(base.Add(10*time.Second), `"msg":"stream_open","cell":"c2","pod":"p2"`) +
		gwJSON(base.Add(30*time.Second), `"msg":"stream_open","cell":"c2","pod":"p3"`)
	if got := m9GwOpenPod(m9GwParse(logs), "c2", base.Add(20*time.Second)); got != "p2" {
		t.Errorf("got %q, want p2", got)
	}
	if got := m9GwOpenPod(m9GwParse(logs), "c2", base); got != "" {
		t.Errorf("got %q, want none", got)
	}
}

package e2e

// The pure part of the revocation breadcrumb build/gate/m9-revoked. Each line holds a cell, and after the revoke the identity of the
// revocation that the test made. This file has no build tag and imports the standard library only.

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// m9Event is the part of a revocation event of mgmt -- status that identifies a revoke.
type m9Event struct {
	Cell, Kind, EntryID string
	Epoch, Counter      uint64
}

// m9EventToken names the revocation that an event records: entry:<id> for an adopted local entry, else rev:<epoch>.<counter>.
func m9EventToken(ev m9Event) string {
	if ev.EntryID != "" {
		return "entry:" + ev.EntryID
	}
	return fmt.Sprintf("rev:%d.%d", ev.Epoch, ev.Counter)
}

// m9NewestRevoke returns the identity of the newest revoke event of the cell, or "" when there is none.
func m9NewestRevoke(events []m9Event, cell string) string {
	var best m9Event
	found := false
	for _, ev := range events {
		if ev.Cell != cell || ev.Kind != "revoke" {
			continue
		}
		if !found || ev.Epoch > best.Epoch || (ev.Epoch == best.Epoch && ev.Counter > best.Counter) {
			best, found = ev, true
		}
	}
	if !found {
		return ""
	}
	return m9EventToken(best)
}

// m9RevocationIsOurs reports whether the current revocation of the cell is the one that the breadcrumb token names. A token that is
// empty never matches, and neither does a cell with no revoke event.
func m9RevocationIsOurs(events []m9Event, cell, token string) bool {
	return token != "" && m9NewestRevoke(events, cell) == token
}

// m9CrumbEntries parses the breadcrumb into cell and token pairs, in file order. A line with one field has an empty token.
func m9CrumbEntries(data string) [][2]string {
	var out [][2]string
	for _, l := range strings.Split(data, "\n") {
		f := strings.Fields(l)
		switch len(f) {
		case 1:
			out = append(out, [2]string{f[0], ""})
		case 2:
			out = append(out, [2]string{f[0], f[1]})
		}
	}
	return out
}

// m9CrumbToken returns whether the breadcrumb lists the cell, and the token of its line.
func m9CrumbToken(data, cell string) (bool, string) {
	for _, e := range m9CrumbEntries(data) {
		if e[0] == cell {
			return true, e[1]
		}
	}
	return false, ""
}

// m9CrumbWith returns the breadcrumb with the line of the cell set to the token. The line moves to the end when it exists.
func m9CrumbWith(data, cell, token string) string {
	var b strings.Builder
	for _, e := range m9CrumbEntries(data) {
		if e[0] != cell {
			b.WriteString(strings.TrimSpace(e[0]+" "+e[1]) + "\n")
		}
	}
	b.WriteString(strings.TrimSpace(cell+" "+token) + "\n")
	return b.String()
}

// m9CrumbWithout returns the breadcrumb with no line of the cell.
func m9CrumbWithout(data, cell string) string {
	var b strings.Builder
	for _, e := range m9CrumbEntries(data) {
		if e[0] != cell {
			b.WriteString(strings.TrimSpace(e[0]+" "+e[1]) + "\n")
		}
	}
	return b.String()
}

func TestM9RevocationIsOurs(t *testing.T) {
	mine := m9Event{Cell: "dev-cell-2", Kind: "revoke", Epoch: 1, Counter: 5}
	later := m9Event{Cell: "dev-cell-2", Kind: "revoke", Epoch: 1, Counter: 6}
	entry := m9Event{Cell: "dev-cell-2", Kind: "revoke", EntryID: "0123456789abcdef", Epoch: 1, Counter: 6}
	un := m9Event{Cell: "dev-cell-2", Kind: "unrevoke", Epoch: 1, Counter: 9}
	other := m9Event{Cell: "dev-cell-1", Kind: "revoke", Epoch: 1, Counter: 8}
	for _, tc := range []struct {
		name   string
		events []m9Event
		token  string
		want   bool
	}{
		{"the recorded revoke", []m9Event{mine}, "rev:1.5", true},
		{"a newer revoke by another", []m9Event{mine, later}, "rev:1.5", false},
		{"the recorded entry", []m9Event{mine, entry}, "entry:0123456789abcdef", true},
		{"another entry", []m9Event{mine, entry}, "entry:fedcba9876543210", false},
		{"no token", []m9Event{mine}, "", false},
		{"no event", nil, "rev:1.5", false},
		{"an event of another cell", []m9Event{other}, "rev:1.8", false},
		{"an unrevoke does not count", []m9Event{mine, un}, "rev:1.9", false},
	} {
		if got := m9RevocationIsOurs(tc.events, "dev-cell-2", tc.token); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestM9Crumb(t *testing.T) {
	data := m9CrumbWith("", "dev-cell-2", "")
	if data != "dev-cell-2\n" {
		t.Fatalf("a bare mark is %q", data)
	}
	data = m9CrumbWith(data, "dev-cell-2", "rev:1.5")
	if data != "dev-cell-2 rev:1.5\n" {
		t.Fatalf("a recorded revoke is %q", data)
	}
	data = m9CrumbWith(data, "dev-cell-1", "entry:0123456789abcdef")
	if ok, tok := m9CrumbToken(data, "dev-cell-2"); !ok || tok != "rev:1.5" {
		t.Errorf("token of dev-cell-2: %v %q", ok, tok)
	}
	if ok, _ := m9CrumbToken(data, "dev-cell-3"); ok {
		t.Error("a cell that is not listed is marked")
	}
	rest := m9CrumbWithout(data, "dev-cell-2")
	if !slices.Equal(strings.Fields(rest), []string{"dev-cell-1", "entry:0123456789abcdef"}) {
		t.Errorf("after the removal: %q", rest)
	}
}

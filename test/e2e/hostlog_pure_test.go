package e2e

import (
	"fmt"
	"time"
)

// reasonsSince returns the reason of each log record whose time is at or after since. A record with no valid time never counts, because a
// test cannot tell when it happened. A zero since counts every record that has a reason.
func reasonsSince(recs []map[string]any, since time.Time) []string {
	var reasons []string
	for _, rec := range recs {
		r, _ := rec["reason"].(string)
		if r == "" {
			continue
		}
		if !since.IsZero() {
			at, err := time.Parse(time.RFC3339Nano, fmt.Sprint(rec["time"]))
			if err != nil || at.Before(since) {
				continue
			}
		}
		reasons = append(reasons, r)
	}
	return reasons
}

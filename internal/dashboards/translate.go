package dashboards

import "strings"

// Kind values of an instrument.
const (
	KindCounter       = "counter"
	KindUpDownCounter = "updowncounter"
	KindGauge         = "gauge"
	KindHistogram     = "histogram"
)

// unitSuffix gives the suffix that the Prometheus OTLP translation adds for a unit.
// A unit in braces adds nothing.
var unitSuffix = map[string]string{
	"s": "_seconds", "ms": "_milliseconds", "us": "_microseconds", "ns": "_nanoseconds",
	"min": "_minutes", "h": "_hours", "d": "_days", "By": "_bytes", "KiBy": "_kibibytes",
	"MiBy": "_mebibytes", "GiBy": "_gibibytes", "1": "_ratio", "%": "_percent",
}

// PromName gives the Prometheus names of an OTel instrument, as Prometheus 3.15 translates them.
// Dots become underscores, a known unit adds a suffix, and a monotonic counter adds _total.
// A histogram gives _bucket, _sum and _count.
func PromName(instrument, kind, unit string) []string {
	base := strings.NewReplacer(".", "_", "-", "_", "/", "_").Replace(instrument)
	if s, ok := unitSuffix[unit]; ok && !strings.HasSuffix(base, s) {
		if unit == "1" && kind != KindGauge {
			s = ""
		}
		base += s
	}
	switch kind {
	case KindCounter:
		if !strings.HasSuffix(base, "_total") {
			base += "_total"
		}
		return []string{base}
	case KindHistogram:
		return []string{base + "_bucket", base + "_sum", base + "_count"}
	default:
		return []string{base}
	}
}

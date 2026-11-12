package cellproxy

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Sides of the mesh-view tunnel, for the side attribute of each tunnel metric.
const (
	sideHub  = "hub"
	sideCell = "cell"
)

// Results of a dial of the cell side, for the result attribute of cell_proxy.tunnel.connects.
const (
	dialConnected     = "connected"
	dialRefusedByHub  = "refused_by_hub"
	dialServerRefused = "server_refused"
	dialFailed        = "failed"
)

// TunnelMetrics are the OTel instruments of the mesh-view tunnel:
//
//   - cell_proxy.tunnel.up: 1 while a tunnel is up, else 0. At the hub, one series for each
//     configured cell; at the cell, one series for its upstream.
//   - cell_proxy.tunnel.connects: tunnels that the hub accepted (with replaced) or refused (with
//     reason and role), and dials of the cell by result. A peer that the TLS handshake refuses
//     is only logged, as "peer refused".
//   - cell_proxy.tunnel.refused_requests: requests that the hub or the cell refused, by reason. A
//     503 of the hub has reason upstream_unavailable.
//   - cell_proxy.tunnel.responses: responses that came back through the tunnel to the hub, by
//     cell and HTTP status.
type TunnelMetrics struct {
	meter     metric.Meter
	up        metric.Int64ObservableGauge
	connects  metric.Int64Counter
	refused   metric.Int64Counter
	responses metric.Int64Counter
}

// NewTunnelMetrics creates the tunnel instruments on m.
func NewTunnelMetrics(m metric.Meter) (*TunnelMetrics, error) {
	up, err1 := m.Int64ObservableGauge("cell_proxy.tunnel.up", metric.WithUnit("{tunnel}"),
		metric.WithDescription("1 while the mesh-view tunnel is up, else 0"))
	connects, err2 := m.Int64Counter("cell_proxy.tunnel.connects", metric.WithUnit("{connection}"),
		metric.WithDescription("Tunnels that the hub accepted or refused, and dials of the cell side by result"))
	refused, err3 := m.Int64Counter("cell_proxy.tunnel.refused_requests", metric.WithUnit("{request}"),
		metric.WithDescription("Requests that the hub or the cell side refused, by reason"))
	responses, err4 := m.Int64Counter("cell_proxy.tunnel.responses", metric.WithUnit("{response}"),
		metric.WithDescription("Responses that came back through the tunnel to the hub, by cell and status"))
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, err
	}
	return &TunnelMetrics{meter: m, up: up, connects: connects, refused: refused, responses: responses}, nil
}

// TunnelOption configures a tunnel component.
type TunnelOption func(*tunnelOptions)

type tunnelOptions struct {
	metrics    *TunnelMetrics
	maxStreams int
}

// WithMetrics records the metrics of the component in m.
func WithMetrics(m *TunnelMetrics) TunnelOption {
	return func(o *tunnelOptions) { o.metrics = m }
}

// WithMaxStreams sets how many requests each cell listener of a hub passes into its tunnel at the
// same time. The default is hubMaxStreams. A request over the cap gets 503 with the reason
// overloaded.
func WithMaxStreams(n int) TunnelOption {
	return func(o *tunnelOptions) { o.maxStreams = n }
}

func applyOptions(opts []TunnelOption) tunnelOptions {
	var o tunnelOptions
	for _, f := range opts {
		f(&o)
	}
	return o
}

// observeUp registers a callback that reports the up state of each series that up returns.
func (m *TunnelMetrics) observeUp(up func() map[attribute.Set]bool) error {
	if m == nil {
		return nil
	}
	_, err := m.meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for set, isUp := range up() {
			var v int64
			if isUp {
				v = 1
			}
			o.ObserveInt64(m.up, v, metric.WithAttributeSet(set))
		}
		return nil
	}, m.up)
	return err
}

func (m *TunnelMetrics) connect(ctx context.Context, attrs ...attribute.KeyValue) {
	if m != nil {
		m.connects.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

func (m *TunnelMetrics) refusedRequest(ctx context.Context, attrs ...attribute.KeyValue) {
	if m != nil {
		m.refused.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

func (m *TunnelMetrics) response(ctx context.Context, attrs ...attribute.KeyValue) {
	if m != nil {
		m.responses.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

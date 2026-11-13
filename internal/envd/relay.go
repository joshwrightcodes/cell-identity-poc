package envd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

const (
	// MaxOpsBytes is the largest ops bundle that the puller reads.
	MaxOpsBytes = 1 << 20
	// MaxGatewayBody is the largest response body that the gateway client reads.
	MaxGatewayBody = 4 << 20
	// MaxReportItems and MaxReportBytes bound one report batch.
	MaxReportItems = 100
	MaxReportBytes = 1 << 20
)

// GatewayClient is the envd side of the gateway API.
type GatewayClient interface {
	// Sync gives the gateway the signed state and the open operations, and returns its outbox items.
	Sync(ctx context.Context, req gwapi.SyncRequest) (gwapi.SyncResponse, error)
	// Ack tells the gateway what the management plane decided for items that it handed out.
	Ack(ctx context.Context, req gwapi.AckRequest) error
}

type gatewayClient struct {
	c    *http.Client
	base string
}

// NewGatewayClient returns a GatewayClient that posts to baseURL with c. It reads at most 4 MiB of
// each response.
func NewGatewayClient(c *http.Client, baseURL string) GatewayClient {
	return &gatewayClient{c: c, base: baseURL}
}

// CloseIdleConnections ends the idle connections of the underlying client.
func (g *gatewayClient) CloseIdleConnections() { g.c.CloseIdleConnections() }

func (g *gatewayClient) Sync(ctx context.Context, req gwapi.SyncRequest) (gwapi.SyncResponse, error) {
	var out gwapi.SyncResponse
	body, err := g.post(ctx, gwapi.SyncPath, req)
	if err != nil {
		return out, fmt.Errorf("gateway sync: %w", err)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return gwapi.SyncResponse{}, fmt.Errorf("decode gateway sync: %w", err)
	}
	return out, nil
}

func (g *gatewayClient) Ack(ctx context.Context, req gwapi.AckRequest) error {
	if _, err := g.post(ctx, gwapi.AckPath, req); err != nil {
		return fmt.Errorf("gateway ack: %w", err)
	}
	return nil
}

func (g *gatewayClient) post(ctx context.Context, path string, v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.base+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxGatewayBody+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(body) > MaxGatewayBody {
		return nil, fmt.Errorf("response is larger than %d bytes", MaxGatewayBody)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

// leg runs f under its own deadline and its own span.
func (p *Puller) leg(ctx context.Context, name string, f func(ctx context.Context) error) error {
	ctx, span := p.cfg.Tracer.Start(ctx, name)
	defer span.End()
	lctx, cancel := context.WithTimeout(ctx, p.cfg.RoundTimeout)
	defer cancel()
	err := f(lctx)
	if err != nil {
		fail(span, err)
	}
	return err
}

// relay runs the legs after the spec leg: ops, gateway sync, reports and gateway ack. A failed leg
// stops only the legs that need its output. It returns the status of the gateway, or nil when the
// sync failed or did not run.
func (p *Puller) relay(ctx context.Context) *mgmtapi.GatewayStatus {
	var ops mgmtapi.OpsBundle
	opsErr := p.leg(ctx, "envd.ops", func(lctx context.Context) error {
		var err error
		ops, err = p.getOps(lctx)
		return err
	})
	if opsErr != nil {
		ops = mgmtapi.OpsBundle{}
		p.logLimited(ctx, "ops pull failed", "ops", "error", clip(opsErr.Error()))
	}
	if len(p.state.SpecEnvelope) == 0 {
		return nil
	}
	req := gwapi.SyncRequest{
		SpecEnvelope: p.state.SpecEnvelope,
		Records:      make(map[string]json.RawMessage, len(p.state.Records)),
		Ops:          ops.Ops,
		Cells:        ops.Cells,
	}
	for k, v := range p.state.Records {
		req.Records[k] = v
	}
	if req.Ops == nil {
		req.Ops = []json.RawMessage{}
	}
	if req.Cells == nil {
		req.Cells = []mgmtapi.CellInfo{}
	}
	var resp gwapi.SyncResponse
	if err := p.leg(ctx, "envd.gateway.sync", func(lctx context.Context) error {
		var err error
		resp, err = p.cfg.Gateway.Sync(lctx, req)
		return err
	}); err != nil {
		p.logLimited(ctx, "gateway sync failed", "gateway-sync", "error", clip(err.Error()))
		return nil
	}
	p.outbox.Record(ctx, int64(resp.Status.OutboxItems))
	if len(resp.Items) > 0 && opsErr == nil {
		p.relayItems(ctx, resp.Items)
	}
	return &resp.Status
}

func (p *Puller) getOps(ctx context.Context) (mgmtapi.OpsBundle, error) {
	var b mgmtapi.OpsBundle
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.BaseURL+mgmtapi.OpsPath(p.cfg.Env), nil)
	if err != nil {
		return b, err
	}
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		return b, fmt.Errorf("get ops: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return b, fmt.Errorf("get ops: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxOpsBytes+1))
	if err != nil {
		return b, fmt.Errorf("read ops: %w", err)
	}
	if len(body) > MaxOpsBytes {
		return b, fmt.Errorf("ops body is larger than %d bytes", MaxOpsBytes)
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return mgmtapi.OpsBundle{}, fmt.Errorf("decode ops bundle: %w", err)
	}
	return b, nil
}

// batch turns outbox items into one report batch of at most MaxReportItems items and MaxReportBytes
// bytes. The bytes of each item body stay as the gateway gave them.
func batch(items []gwapi.OutItem) mgmtapi.ReportBatch {
	var b mgmtapi.ReportBatch
	size := len(`{"items":[]}`)
	for _, it := range items {
		if len(b.Items) == MaxReportItems {
			break
		}
		ri := mgmtapi.ReportItem{ID: string(it.ID), Cell: it.Cell, Kind: it.Kind, OpID: it.OpID, Body: it.Body, Token: it.Token}
		raw, err := json.Marshal(ri)
		if err != nil || size+len(raw)+1 > MaxReportBytes {
			break
		}
		size += len(raw) + 1
		b.Items = append(b.Items, ri)
	}
	return b
}

// relayItems posts the items to the management plane and, only when it answers, acknowledges each
// outcome at the gateway.
func (p *Puller) relayItems(ctx context.Context, items []gwapi.OutItem) {
	b := batch(items)
	if len(b.Items) == 0 {
		return
	}
	var res mgmtapi.ReportResult
	if err := p.leg(ctx, "envd.reports", func(lctx context.Context) error {
		var err error
		res, err = p.postReports(lctx, b)
		return err
	}); err != nil {
		p.logLimited(ctx, "report post failed", "reports", "error", clip(err.Error()))
		return
	}
	sent := make(map[string]bool, len(b.Items))
	for _, it := range b.Items {
		sent[it.ID] = true
	}
	ack := gwapi.AckRequest{Outcomes: make([]mgmtapi.ItemOutcome, 0, len(res.Outcomes))}
	for _, o := range res.Outcomes {
		if !sent[o.ID] {
			continue
		}
		delete(sent, o.ID)
		ack.Outcomes = append(ack.Outcomes, o)
		p.relayCount.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", o.Outcome)))
	}
	if len(ack.Outcomes) == 0 {
		return
	}
	if err := p.leg(ctx, "envd.gateway.ack", func(lctx context.Context) error {
		return p.cfg.Gateway.Ack(lctx, ack)
	}); err != nil {
		p.logLimited(ctx, "gateway ack failed", "gateway-ack", "error", clip(err.Error()))
	}
}

func (p *Puller) postReports(ctx context.Context, b mgmtapi.ReportBatch) (mgmtapi.ReportResult, error) {
	var res mgmtapi.ReportResult
	// json.Marshal of the batch is the form that the proof inputs depend on. A body from celld is
	// already the compact Marshal output, and Marshal leaves such bytes unchanged.
	raw, err := json.Marshal(b)
	if err != nil {
		return res, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.BaseURL+mgmtapi.ReportsPath(p.cfg.Env), bytes.NewReader(raw))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		return res, fmt.Errorf("post reports: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return res, fmt.Errorf("post reports: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxOpsBytes+1))
	if err != nil {
		return res, fmt.Errorf("read report result: %w", err)
	}
	if len(body) > MaxOpsBytes {
		return res, errors.New("report result is too large")
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return mgmtapi.ReportResult{}, fmt.Errorf("decode report result: %w", err)
	}
	return res, nil
}

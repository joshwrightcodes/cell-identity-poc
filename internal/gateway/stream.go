package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/connlimit"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

// Real-time limits of the stream. Tests shorten the variables before they start a server.
var (
	writeTimeout    = 10 * time.Second
	workEvery       = 5 * time.Second
	sendPingTimeout = 30 * time.Second
	pingTimeout     = 10 * time.Second
)

// CelldRole is the last path segment of the SPIFFE ID of a celld stream peer.
const CelldRole = "celld"

// Limits and defaults of the stream listener.
const (
	DefaultReplicaCap   = 2
	DefaultHelloTimeout = 5 * time.Second
	DefaultMaxLife      = time.Hour
	// DefaultFrameIdle is how long a stream may send no frame before the gateway ends it. The cell
	// pings every 10 s.
	DefaultFrameIdle = 30 * time.Second

	streamConns       = 32
	streamPerSource   = 4
	streamConcurrent  = 4
	noRequestTimeout  = 5 * time.Second
	streamIdleTimeout = 30 * time.Second
	streamHeaderLimit = 5 * time.Second
	pollEvery         = time.Second
	hintGap           = 60 * time.Second
	// maxFenceAhead is how far above the current time in seconds a hello may report an epoch. The
	// epoch starts at the Unix time of the file and rises by one for each raise.
	maxFenceAhead = 24 * 60 * 60
)

// StreamConfig holds the settings of the stream handler. A zero value gets the default of its
// field, except Subject, Notifier and Meter, which stay as given. A nil Notifier means the
// handler never sends work on a signal, and a nil Meter means no metrics.
//
// FrameIdle is the time without any frame after which a stream ends. The lease length is
// LeaseTTL of the store.
type StreamConfig struct {
	ReplicaCap   int
	HelloTimeout time.Duration
	FrameIdle    time.Duration
	MaxLife      time.Duration
	Subject      record.Subject
	Notifier     *gwapi.Notifier
	Now          func() time.Time
	Log          *slog.Logger
	Meter        metric.Meter
}

// instruments are the counters that the servers share.
type instruments struct {
	refusals metric.Int64Counter
	claims   metric.Int64Counter
}

func newInstruments(m metric.Meter) *instruments {
	if m == nil {
		m = noop.NewMeterProvider().Meter("cellgw")
	}
	refusals, _ := m.Int64Counter("cellgw.refusals", metric.WithDescription("Refusals by reason"))
	claims, _ := m.Int64Counter("cellgw.claims", metric.WithDescription("Claims that gave a lease, by cell"))
	return &instruments{refusals: refusals, claims: claims}
}

// cellAttr is the cell attribute of the gauges and counters.
func cellAttr(cell string) attribute.KeyValue { return attribute.String("cell", cell) }

func (i *instruments) refused(ctx context.Context, reason string) {
	i.refusals.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

// StreamHandler serves the celld streams.
type StreamHandler struct {
	st    *Store
	cfg   StreamConfig
	log   *slog.Logger
	ins   *instruments
	mux   *http.ServeMux
	hints hintBook

	// beforeClaim runs between the record check and the claim. Tests use it.
	beforeClaim func()

	mu      sync.Mutex
	streams map[string]map[string]*stream
}

// stream is one admitted stream. The handler of the stream is the only writer.
type stream struct {
	pod    string
	kicked chan struct{}
	once   sync.Once
	reason atomic.Value
}

func (s *stream) kick(reason string) {
	s.once.Do(func() {
		s.reason.Store(reason)
		close(s.kicked)
	})
}

// NewStreamHandler returns the handler of the route StreamPath(cell). The peer must be
// cell/<cell>/celld, the cell must have an unrevoked record, and a hello with a valid proof must
// come first. It returns the concrete type, so that the envd handler can read Streams and TakeHints.
func NewStreamHandler(st *Store, cfg StreamConfig) *StreamHandler {
	if cfg.ReplicaCap <= 0 {
		cfg.ReplicaCap = DefaultReplicaCap
	}
	if cfg.HelloTimeout <= 0 {
		cfg.HelloTimeout = DefaultHelloTimeout
	}
	if cfg.FrameIdle <= 0 {
		cfg.FrameIdle = DefaultFrameIdle
	}
	if cfg.MaxLife <= 0 {
		cfg.MaxLife = DefaultMaxLife
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	h := &StreamHandler{st: st, cfg: cfg, log: cfg.Log, ins: newInstruments(cfg.Meter), mux: http.NewServeMux(),
		hints: hintBook{last: map[string]time.Time{}, pending: map[string]time.Time{}}, streams: map[string]map[string]*stream{}}
	h.mux.HandleFunc(gwapi.StreamPattern, h.serve)
	h.mux.HandleFunc("/", http.NotFound)
	return h
}

func (h *StreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p := r.URL.Path; p == "" || p != path.Clean(p) {
		http.NotFound(w, r)
		return
	}
	h.mux.ServeHTTP(w, r)
}

// Streams returns the number of open streams of each cell.
func (h *StreamHandler) Streams() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]int, len(h.streams))
	for cell, m := range h.streams {
		out[cell] = len(m)
	}
	return out
}

// TakeHints returns the key hints that refused hellos made since the last call, and forgets them.
func (h *StreamHandler) TakeHints() []mgmtapi.KeyHint { return h.hints.take() }

// hintBook keeps the hints of refused hellos, at most one for each cell in hintGap.
type hintBook struct {
	mu      sync.Mutex
	last    map[string]time.Time
	pending map[string]time.Time
}

func (b *hintBook) note(cell string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.last[cell]; ok && now.Sub(t) < hintGap {
		return
	}
	b.last[cell] = now
	b.pending[cell] = now
}

func (b *hintBook) take() []mgmtapi.KeyHint {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]mgmtapi.KeyHint, 0, len(b.pending))
	for cell, at := range b.pending {
		out = append(out, mgmtapi.KeyHint{Cell: cell, At: at.UTC()})
	}
	clear(b.pending)
	slices.SortFunc(out, func(a, b mgmtapi.KeyHint) int {
		switch {
		case a.Cell < b.Cell:
			return -1
		case a.Cell > b.Cell:
			return 1
		}
		return 0
	})
	return out
}

// admit registers pod for cell. A pod that already streams supersedes its older stream. A new pod
// beyond the cap is refused with replica_cap.
func (h *StreamHandler) admit(cell, pod string) (*stream, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.streams[cell]
	if m == nil {
		m = map[string]*stream{}
		h.streams[cell] = m
	}
	if old, ok := m[pod]; ok {
		old.kick(gwapi.ReasonSuperseded)
	} else if len(m) >= h.cfg.ReplicaCap {
		return nil, gwapi.ReasonReplicaCap
	}
	s := &stream{pod: pod, kicked: make(chan struct{})}
	m[pod] = s
	return s, ""
}

func (h *StreamHandler) release(cell string, s *stream) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.streams[cell]
	if m[s.pod] == s {
		delete(m, s.pod)
	}
	if len(m) == 0 {
		delete(h.streams, cell)
	}
}

type frameResult struct {
	f   gwapi.Frame
	err error
}

// out writes frames with a deadline on each write.
type out struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (o out) send(f gwapi.Frame) error {
	// The deadline covers this write only. A deadline that stays set would end the stream when it
	// passes, also when nothing is written.
	_ = o.rc.SetWriteDeadline(time.Now().Add(writeTimeout))
	defer func() { _ = o.rc.SetWriteDeadline(time.Time{}) }()
	if err := gwapi.Encode(o.w, f); err != nil {
		return err
	}
	// Encode flushes and drops the error. The controller returns the flush error of the HTTP/2
	// layer, which forward needs before it forgets a retry.
	return o.rc.Flush()
}

func (h *StreamHandler) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	cell := r.PathValue("cell")
	notAfter, ok := h.peer(r, cell)
	if !ok {
		h.ins.refused(ctx, "peer_mismatch")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rec, found, err := h.st.Cell(ctx, cell)
	if err != nil {
		h.log.ErrorContext(ctx, "stream_store_failed", "cell", cell, "error", err.Error())
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	binding, err := proof.Binding(*r.TLS)
	if err != nil {
		h.log.WarnContext(ctx, "stream_binding_failed", "cell", cell, "error", err.Error())
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	o := out{w: w, rc: rc}
	refuse := func(reason string, attrs ...any) {
		h.ins.refused(ctx, reason)
		h.log.InfoContext(ctx, "stream_refused", append([]any{"cell", cell, "reason", reason}, attrs...)...)
		_ = o.send(gwapi.Frame{Type: gwapi.TypeRefused, Reason: reason})
	}
	switch {
	case !found:
		refuse(gwapi.ReasonCellUnknown)
		return
	case rec.Revoked:
		refuse(gwapi.ReasonCellRevoked)
		return
	}

	frames := make(chan frameResult, 1)
	go func() {
		dec := gwapi.NewDecoder(r.Body)
		for {
			f, err := dec.Decode()
			select {
			case frames <- frameResult{f, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	hello, reason := h.readHello(ctx, frames)
	if reason != "" {
		if reason != "gone" {
			refuse(reason)
		}
		return
	}
	claims, err := proof.Verify(rec, hello.Token, proof.HelloAudience(cell, binding), h.cfg.Subject, h.cfg.Now())
	if err != nil {
		var pe *proof.Error
		reason, detail := gwapi.ReasonProofInvalid, ""
		if errors.As(err, &pe) {
			reason, detail = pe.Reason, pe.Detail
		}
		if detail == string(clusterjwt.UnknownKID) {
			h.hints.note(cell, h.cfg.Now())
		}
		refuse(reason, "detail", detail)
		return
	}
	if hello.LastFence.Epoch > uint64(h.cfg.Now().Unix())+maxFenceAhead {
		refuse(mgmtapi.ReasonPayloadInvalid, "what", "fence_epoch", "pod", claims.PodUID, "epoch", hello.LastFence.Epoch)
		return
	}
	if err := h.st.RaiseEpoch(ctx, hello.LastFence); err != nil {
		if errors.Is(err, ErrEpochOutOfRange) {
			refuse(mgmtapi.ReasonPayloadInvalid, "what", "fence_epoch", "pod", claims.PodUID)
			return
		}
		h.log.ErrorContext(ctx, "stream_store_failed", "cell", cell, "error", err.Error())
		return
	}
	me, reason := h.admit(cell, claims.PodUID)
	if reason != "" {
		refuse(reason, "pod", claims.PodUID)
		return
	}
	defer h.release(cell, me)
	if err := o.send(gwapi.Frame{Type: gwapi.TypeWelcome, Pod: claims.PodUID, Cap: h.cfg.ReplicaCap, Fence: op.Fence{Epoch: h.st.Epoch()}}); err != nil {
		return
	}
	h.log.InfoContext(ctx, "stream_open", "cell", cell, "pod", claims.PodUID)
	defer h.log.InfoContext(ctx, "stream_closed", "cell", cell, "pod", claims.PodUID)

	deadline := time.Now().Add(h.cfg.MaxLife)
	if notAfter.Before(deadline) {
		deadline = notAfter
	}
	h.loop(ctx, cell, me, o, frames, deadline, refuse)
}

// peer returns the end of the client certificate when it names cell/<cell>/celld for the cell of
// the path and has not expired.
func (h *StreamHandler) peer(r *http.Request, cell string) (notAfter time.Time, ok bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return time.Time{}, false
	}
	c := r.TLS.PeerCertificates[0]
	id, err := x509svid.IDFromCert(c)
	if err != nil {
		return time.Time{}, false
	}
	src, err := cellproxy.ParseSource(id)
	if err != nil || src.Plane != cellproxy.PlaneCell || src.Cell != cell || src.Role != CelldRole {
		return time.Time{}, false
	}
	if h.cfg.Now().After(c.NotAfter) {
		return time.Time{}, false
	}
	return c.NotAfter, true
}

// readHello waits for the first frame. The reason is empty when the frame is a hello.
func (h *StreamHandler) readHello(ctx context.Context, frames <-chan frameResult) (gwapi.Frame, string) {
	t := time.NewTimer(h.cfg.HelloTimeout)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return gwapi.Frame{}, "gone"
	case <-t.C:
		return gwapi.Frame{}, gwapi.ReasonHelloTimeout
	case fr := <-frames:
		switch {
		case fr.err != nil && errors.Is(fr.err, io.EOF), errors.Is(fr.err, context.Canceled):
			return gwapi.Frame{}, "gone"
		case fr.err != nil, fr.f.Type != gwapi.TypeHello:
			return gwapi.Frame{}, gwapi.ReasonProofMissing
		}
		return fr.f, ""
	}
}

func (h *StreamHandler) loop(ctx context.Context, cell string, me *stream, o out, frames <-chan frameResult, deadline time.Time, refuse func(string, ...any)) {
	var notified <-chan struct{}
	if h.cfg.Notifier != nil {
		ch, unsub := h.cfg.Notifier.Subscribe(cell)
		defer unsub()
		notified = ch
	}
	poll := time.NewTicker(pollEvery)
	defer poll.Stop()
	idle := time.NewTimer(h.cfg.FrameIdle)
	defer idle.Stop()
	life := time.NewTimer(time.Until(deadline))
	defer life.Stop()
	var cursor int64
	var lastWork time.Time

	work := func() error {
		n, err := h.st.Depth(ctx, cell)
		if err != nil || n == 0 {
			return err
		}
		lastWork = time.Now()
		return o.send(gwapi.Frame{Type: gwapi.TypeWork, Queued: n})
	}
	fail := func(what string, err error) {
		if ctx.Err() == nil {
			h.log.WarnContext(ctx, "stream_failed", "cell", cell, "pod", me.pod, "what", what, "error", err.Error())
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-me.kicked:
			refuse(me.reason.Load().(string), "pod", me.pod)
			return
		case <-life.C:
			refuse(gwapi.ReasonReauth, "pod", me.pod)
			return
		case <-idle.C:
			h.log.InfoContext(ctx, "stream_idle", "cell", cell, "pod", me.pod)
			return
		case <-notified:
			if err := work(); err != nil {
				fail("work", err)
				return
			}
		case <-poll.C:
			if h.cellGone(ctx, cell) {
				refuse(gwapi.ReasonCellRevoked, "pod", me.pod)
				return
			}
			next, err := h.forward(ctx, cell, cursor, o.send)
			if err != nil {
				fail("outcomes", err)
				return
			}
			cursor = next
			if time.Since(lastWork) >= workEvery {
				if err := work(); err != nil {
					fail("work", err)
					return
				}
			}
		case fr := <-frames:
			if fr.err != nil {
				if !errors.Is(fr.err, io.EOF) && !errors.Is(fr.err, context.Canceled) {
					h.log.InfoContext(ctx, "stream_frame_refused", "cell", cell, "pod", me.pod, "error", fr.err.Error())
				}
				return
			}
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(h.cfg.FrameIdle)
			if err := h.handle(ctx, cell, me, o, fr.f, refuse); err != nil {
				if !errors.Is(err, errEndStream) {
					fail("frame", err)
				}
				return
			}
		}
	}
}

var errEndStream = errors.New("stream ends")

func (h *StreamHandler) handle(ctx context.Context, cell string, me *stream, o out, f gwapi.Frame, refuse func(string, ...any)) error {
	switch f.Type {
	case gwapi.TypePing:
		return o.send(gwapi.Frame{Type: gwapi.TypePong})
	case gwapi.TypeClaim:
		if h.cellGone(ctx, cell) {
			refuse(gwapi.ReasonCellRevoked, "pod", me.pod)
			return errEndStream
		}
		if h.beforeClaim != nil {
			h.beforeClaim()
		}
		l, err := h.st.ClaimLive(ctx, cell, me.pod)
		if errors.Is(err, ErrCellNotLive) {
			refuse(gwapi.ReasonCellRevoked, "pod", me.pod)
			return errEndStream
		}
		if err != nil {
			return err
		}
		if l == nil {
			return o.send(gwapi.Frame{Type: gwapi.TypeNone})
		}
		h.ins.claims.Add(ctx, 1, metric.WithAttributes(cellAttr(cell)))
		return o.send(gwapi.Frame{Type: gwapi.TypeLease, LeaseID: l.ID, OpID: l.OpID, Envelope: json.RawMessage(l.Envelope), Fence: l.Fence, Until: l.Until})
	case gwapi.TypeResult:
		if f.Item == nil || f.Item.Kind != gwapi.KindResult || f.Item.Cell != cell {
			refuse(gwapi.ReasonProofInvalid, "pod", me.pod, "what", "result_item")
			return errEndStream
		}
		_, err := h.st.CompleteWithItem(ctx, cell, f.LeaseID, *f.Item, f.Fence)
		ack := gwapi.Frame{Type: gwapi.TypeAck, LeaseID: f.LeaseID, OpID: f.Item.OpID}
		switch {
		case err == nil:
		case gwapi.ReasonOf(err) != "":
			ack.Reason = gwapi.ReasonOf(err)
		default:
			return err
		}
		return o.send(ack)
	case gwapi.TypeStatus:
		if f.Item == nil || f.Item.Kind != gwapi.KindStatus || f.Item.Cell != cell {
			refuse(gwapi.ReasonProofInvalid, "pod", me.pod, "what", "status_item")
			return errEndStream
		}
		_, err := h.st.Append(ctx, *f.Item)
		switch {
		case err == nil:
			return o.send(gwapi.Frame{Type: gwapi.TypeAck})
		case errors.Is(err, gwapi.ErrOverloaded):
			h.ins.refused(ctx, gwapi.ReasonOverloaded)
			return o.send(gwapi.Frame{Type: gwapi.TypeRefused, Reason: gwapi.ReasonOverloaded})
		}
		return err
	}
	h.log.InfoContext(ctx, "stream_frame_unexpected", "cell", cell, "pod", me.pod, "type", f.Type)
	return errEndStream
}

// cellGone reports whether the record of cell is revoked or missing now. A store failure is not an
// answer, so the stream goes on.
func (h *StreamHandler) cellGone(ctx context.Context, cell string) bool {
	rec, found, err := h.st.Cell(ctx, cell)
	if err != nil {
		h.log.WarnContext(ctx, "stream_cell_check_failed", "cell", cell, "error", err.Error())
		return false
	}
	return !found || rec.Revoked
}

// forward sends final or retry for each outcome after cursor, then forgets the retry outcomes that
// the stream wrote. It returns the new cursor. After a failed write it returns the old cursor and
// forgets nothing, so no retry is lost.
func (h *StreamHandler) forward(ctx context.Context, cell string, cursor int64, send func(gwapi.Frame) error) (int64, error) {
	outs, next, err := h.st.FinalOutcomes(ctx, cell, cursor)
	if err != nil {
		return cursor, err
	}
	for _, o := range outs {
		f := gwapi.Frame{Type: gwapi.TypeFinal, OpID: o.OpID, Outcome: o.Outcome}
		if o.Outcome == mgmtapi.OutcomeRetry {
			f = gwapi.Frame{Type: gwapi.TypeRetry, OpID: o.OpID}
		}
		if err := send(f); err != nil {
			return cursor, err
		}
	}
	if next > cursor {
		if err := h.st.ForgetRetries(ctx, cell, next); err != nil {
			return cursor, err
		}
	}
	return next, nil
}

// StreamServerTLS returns the TLS settings of the stream listener: TLS 1.3 and ALPN h2 only, and
// a client certificate from a member of td. The handler checks the exact peer for each request.
func StreamServerTLS(svids x509svid.Source, bundles x509bundle.Source, td spiffeid.TrustDomain) *tls.Config {
	return pinTLS13(tlsconfig.MTLSServerConfig(svids, bundles, tlsconfig.AuthorizeMemberOf(td)))
}

func pinTLS13(cfg *tls.Config) *tls.Config {
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.NextProtos = []string{"h2"}
	cfg.SessionTicketsDisabled = true
	return cfg
}

// ListenStream wraps ln for the stream server: at most 32 connections and 4 for each source
// address, with no maximum age. A connection above the per-source cap closes at once.
func ListenStream(ln net.Listener, cfg *tls.Config) net.Listener {
	return tls.NewListener(connlimit.ListenPerSource(ln, streamConns, streamPerSource, 0, 0, nil), cfg)
}

// NewStreamServer returns the HTTP/2 server of the stream listener. A connection with no request
// 5 s after accept closes, and so does one with no open stream for 30 s. A silent peer fails the
// HTTP/2 ping within 40 s. tracer may be nil.
func NewStreamServer(h http.Handler, cfg *tls.Config, tracer trace.Tracer) *http.Server {
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	srv := &http.Server{
		Handler: telemetry.Handler(orNoop(tracer), "cellgw.stream", h), TLSConfig: cfg, Protocols: protos,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: streamConcurrent, SendPingTimeout: sendPingTimeout, PingTimeout: pingTimeout,
		},
		ReadHeaderTimeout: streamHeaderLimit, IdleTimeout: streamIdleTimeout, MaxHeaderBytes: 16 << 10,
	}
	guard := &noRequestGuard{d: noRequestTimeout}
	srv.ConnState, srv.ConnContext = guard.connState, guard.connContext
	srv.Handler = guard.handler(srv.Handler)
	return srv
}

// noRequestGuard closes a connection that has opened no request within d of its accept. The timer
// stops at the first request, whatever the HTTP/2 preface did before it.
type noRequestGuard struct {
	d      time.Duration
	timers sync.Map
}

type guardKey struct{}

func (g *noRequestGuard) connState(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateClosed, http.StateHijacked:
		if t, ok := g.timers.LoadAndDelete(c); ok {
			t.(*time.Timer).Stop()
		}
	}
}

func (g *noRequestGuard) connContext(ctx context.Context, c net.Conn) context.Context {
	// The server calls ConnContext before it reports StateNew, so the timer starts here.
	t, _ := g.timers.LoadOrStore(c, time.AfterFunc(g.d, func() { _ = c.Close() }))
	return context.WithValue(ctx, guardKey{}, t.(*time.Timer))
}

func (g *noRequestGuard) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if t, ok := r.Context().Value(guardKey{}).(*time.Timer); ok {
			t.Stop()
		}
		next.ServeHTTP(w, r)
	})
}

func orNoop(t trace.Tracer) trace.Tracer {
	if t == nil {
		return tracenoop.NewTracerProvider().Tracer("cellgw")
	}
	return t
}

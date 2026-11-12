package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// Nonce returns a stateless bind nonce for a cell of the intent.
func (p *Plane) Nonce(cell string) (mgmtapi.NonceResponse, error) {
	if _, ok := p.intent[cell]; !ok {
		return mgmtapi.NonceResponse{}, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	nonce, exp := p.nonces.Issue(cell)
	return mgmtapi.NonceResponse{
		Nonce: nonce, Audience: mgmtapi.BindAudience(cell, nonce), ExpiresAt: exp,
		Bound: p.snap.Load().st.Cells[cell] != nil,
	}, nil
}

// Bind checks a bind request and binds the cell, updates its keys, or answers already_bound. A
// refused bind writes no file and consumes no nonce.
func (p *Plane) Bind(ctx context.Context, cell string, req mgmtapi.BindRequest) (resp mgmtapi.BindResponse, err error) {
	defer func() { p.countBind(ctx, cell, resp, err) }()
	if _, ok := p.intent[cell]; !ok {
		return resp, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	if err := p.nonces.Check(cell, req.Nonce); err != nil {
		return resp, err
	}
	now := p.cfg.Now()
	pre := p.snap.Load().st
	cs := pre.Cells[cell]
	issuer := ""
	if cs != nil {
		issuer = cs.Issuer
	}
	aud := mgmtapi.BindAudience(cell, req.Nonce)
	if err := clusterjwt.Precheck(req.Token, issuer, aud, p.cfg.Intent.BindSubject, now); err != nil {
		return resp, tokenError(err)
	}
	if cs != nil {
		_, verr := clusterjwt.ValidateFor(p.cellRecord(cell, cs.Issuer, cs.JWKS), req.Token, aud, now)
		switch {
		case verr == nil:
			return p.alreadyBound(cell, req.Nonce, cs.Record)
		case clusterjwt.ReasonOf(verr) != clusterjwt.UnknownKID:
			return resp, tokenError(verr)
		}
	}

	prepare := func(keys mgmtapi.ClusterKeys) ([]keyInfo, json.RawMessage, error) {
		if keys.Issuer == "" || (issuer != "" && keys.Issuer != issuer) {
			return nil, nil, refuse(mgmtapi.ReasonIssuerUntrusted, "issuer_changed")
		}
		fresh := parseKeys(keys.JWKS)
		jwks, err := encodeKeys(fresh)
		if err != nil {
			return nil, nil, refuse(mgmtapi.ReasonKeysUntrusted, "unreadable_set")
		}
		if _, verr := clusterjwt.ValidateFor(p.cellRecord(cell, keys.Issuer, jwks), req.Token, aud, now); verr != nil {
			return nil, nil, tokenError(verr)
		}
		if len(fresh) > maxKeys {
			return nil, nil, refuse(mgmtapi.ReasonKeysUntrusted, "too_many_keys")
		}
		return fresh, jwks, nil
	}
	keys, _, cached, err := p.cachedKeys(ctx, cell, fetchCached)
	if err != nil {
		return resp, err
	}
	fresh, jwks, err := prepare(keys)
	if err != nil && cached && isUnknownKID(err) {
		// The cached set may predate a rotation. One refetch per refetchGap is allowed.
		if again, _, cachedAgain, ferr := p.cachedKeys(ctx, cell, fetchRefetch); ferr == nil && !cachedAgain {
			keys = again
			fresh, jwks, err = prepare(keys)
		}
	}
	if err != nil {
		return resp, err
	}

	err = p.commit(func(t *txn) error {
		if p.nonces.Used(req.Nonce) {
			return refuse(mgmtapi.ReasonNonceInvalid, "consumed")
		}
		cur := t.st.Cells[cell]
		if cur != nil {
			_, verr := clusterjwt.ValidateFor(p.cellRecord(cell, cur.Issuer, cur.JWKS), req.Token, aud, now)
			switch {
			case verr == nil:
				if err := p.nonces.Consume(cell, req.Nonce); err != nil {
					return err
				}
				resp = mgmtapi.BindResponse{Status: mgmtapi.StatusAlreadyBound, Record: cur.Record}
				return nil
			case clusterjwt.ReasonOf(verr) != clusterjwt.UnknownKID:
				return tokenError(verr)
			}
			if keys.Issuer != cur.Issuer {
				return refuse(mgmtapi.ReasonIssuerUntrusted, "issuer_changed")
			}
		}
		if err := t.revise(); err != nil {
			return err
		}
		status := mgmtapi.StatusBound
		if cur != nil {
			status = mgmtapi.StatusKeysUpdated
			if diffKeys(parseKeys(cur.JWKS), fresh).added > maxNewKeys {
				return refuse(mgmtapi.ReasonKeysUntrusted, "too_many_new_keys")
			}
			if p.gapActive(cur, t.now) {
				return refuse(mgmtapi.ReasonRateLimited, "key_update_gap")
			}
		} else {
			cur = &CellState{BoundAt: t.now}
			t.st.Cells[cell] = cur
			delete(t.st.Retired, cell)
		}
		cur.Issuer, cur.JWKS = keys.Issuer, jwks
		cur.KeysUpdatedAt, cur.CheckedAt, cur.LastCheck = t.now, t.now, ""
		if err := t.signCell(cell); err != nil {
			return err
		}
		resp = mgmtapi.BindResponse{Status: status, Record: t.rev}
		t.after = append(t.after, func() {
			if err := p.nonces.Consume(cell, req.Nonce); err != nil {
				p.logLimited(ctx, slog.LevelError, "consume_failed/"+cell, "nonce_consume_failed", "cell", cell, "error", err.Error())
			}
		})
		return nil
	})
	if err != nil {
		return mgmtapi.BindResponse{}, err
	}
	return resp, nil
}

func isUnknownKID(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Reason == mgmtapi.ReasonTokenInvalid && e.Detail == string(clusterjwt.UnknownKID)
}

// alreadyBound consumes the nonce under the mutex, so two requests with one nonce get one answer.
func (p *Plane) alreadyBound(cell, nonce string, rev spec.Revision) (mgmtapi.BindResponse, error) {
	if err := p.commit(func(*txn) error { return p.nonces.Consume(cell, nonce) }); err != nil {
		return mgmtapi.BindResponse{}, err
	}
	return mgmtapi.BindResponse{Status: mgmtapi.StatusAlreadyBound, Record: rev}, nil
}

func (p *Plane) countBind(ctx context.Context, cell string, resp mgmtapi.BindResponse, err error) {
	result := resp.Status
	if err != nil {
		result = ReasonOf(err)
		if result == "" {
			result = "error"
		}
		key := "bind_refused/" + cell + "/" + result
		if result == mgmtapi.ReasonCellUnknown {
			key = "bind_refused/unknown_cell" // one key, so invented names cannot fill the limiter
		}
		p.logLimited(ctx, slog.LevelInfo, key, "bind_refused", "cell", cell, "reason", result, "error", err.Error())
	} else if resp.Status != mgmtapi.StatusAlreadyBound {
		p.cfg.Log.InfoContext(ctx, "bind", "cell", cell, "result", result, "record_epoch", resp.Record.Epoch, "record_counter", resp.Record.Counter)
	}
	p.bindResults.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

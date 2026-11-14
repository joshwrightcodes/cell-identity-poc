package hostsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

// maxStepAnswer is the largest answer that the step client reads.
const maxStepAnswer = 64 << 10

var requestIDShape = regexp.MustCompile(`^[0-9a-f]{16}$`)

// StepClient sends signed steps to the host service and reads their status. It trusts the pinned
// server certificate only and presents the SVID of this process.
type StepClient struct{ kc *KeyClient }

// NewStepClient checks cfg and returns a client.
func NewStepClient(cfg KeyClientConfig) (*StepClient, error) {
	kc, err := NewKeyClient(cfg)
	if err != nil {
		return nil, err
	}
	return &StepClient{kc: kc}, nil
}

// Put sends a step envelope and returns the status that the host service reports. The error is a
// *mgmtapi.HostError.
func (c *StepClient) Put(ctx context.Context, envelope []byte) (mgmtapi.StepStatus, error) {
	id, _, _, err := step.Peek(envelope)
	if err != nil {
		return mgmtapi.StepStatus{}, fmt.Errorf("step envelope: %w", err)
	}
	return c.status(ctx, http.MethodPut, mgmtapi.StepPath(id), envelope)
}

// Get returns the status of step id. The error is a *mgmtapi.HostError. A host service that does
// not know the step answers 404, which is hostsvc_denied with Status 404.
func (c *StepClient) Get(ctx context.Context, id string) (mgmtapi.StepStatus, error) {
	return c.status(ctx, http.MethodGet, mgmtapi.StepPath(id), nil)
}

func (c *StepClient) status(ctx context.Context, method, path string, body []byte) (mgmtapi.StepStatus, error) {
	answer, err := c.kc.call(ctx, method, path, body)
	if err != nil {
		return mgmtapi.StepStatus{}, err
	}
	var st mgmtapi.StepStatus
	if err := json.Unmarshal(answer, &st); err != nil || !mgmtapi.ValidStepStatus(st) {
		return mgmtapi.StepStatus{}, &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable, Status: http.StatusOK}
	}
	return st, nil
}

// PutSpec sends a spec envelope to the host service. Any 2xx answer is success. The error is a
// *mgmtapi.HostError.
func (c *KeyClient) PutSpec(ctx context.Context, envelope []byte) error {
	_, err := c.call(ctx, http.MethodPut, mgmtapi.HostSpecPath, envelope)
	return err
}

// call makes one request and maps every failure to a *mgmtapi.HostError: a pin mismatch is
// hostsvc_untrusted, 403 and 404 are hostsvc_denied with the request ID of the answer, 503 with a
// Retry-After header is hostsvc_busy, and every other failure is hostsvc_unavailable.
func (c *KeyClient) call(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+c.addr+path, rd)
	if err != nil {
		return nil, &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, errPinMismatch) {
			return nil, &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUntrusted}
		}
		return nil, &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable}
	}
	defer resp.Body.Close()
	answer, rerr := io.ReadAll(io.LimitReader(resp.Body, maxStepAnswer+1))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if rerr != nil || len(answer) > maxStepAnswer {
			return nil, &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable, Status: resp.StatusCode}
		}
		return answer, nil
	}
	he := &mgmtapi.HostError{Status: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		he.Reason = mgmtapi.ReasonHostsvcDenied
		var d mgmtapi.Denied
		if json.Unmarshal(answer, &d) == nil && requestIDShape.MatchString(d.RequestID) {
			he.RequestID = d.RequestID
		}
	case resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "":
		he.Reason = mgmtapi.ReasonHostsvcBusy
		if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n >= 0 {
			he.RetryAfter = time.Duration(n) * time.Second
		}
	default:
		he.Reason = mgmtapi.ReasonHostsvcUnavailable
	}
	return nil, he
}

package mgmtapi

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

// HostSpecPath is the path where the management plane sends the signed spec to the host service.
const HostSpecPath = "/v1/spec"

// The states of a step. StepRefused exists at the cell controller only.
const (
	StepQueued        = "queued"
	StepCreating      = "creating"
	StepAdmitting     = "admitting"
	StepBootstrapping = "bootstrapping"
	StepDone          = "done"
	StepFailed        = "failed"
	StepFailedFinal   = "failed_final"
	StepCancelled     = "cancelled"
	StepRefused       = "refused"
)

// The stages of a step. A StepStatus holds the running stage, or the stage that failed.
const (
	StageCreating      = "creating"
	StageAdmitting     = "admitting"
	StageBootstrapping = "bootstrapping"
)

// StepStatus is what the host service and the cell controller report for one step. Reason is empty,
// step.Code or a host error reason. Detail is empty or one of step.Details.
type StepStatus struct {
	ID            string         `json:"id"`
	Cell          string         `json:"cell"`
	State         string         `json:"state"`
	Stage         string         `json:"stage"`
	Reason        string         `json:"reason"`
	Detail        string         `json:"detail"`
	RequestID     string         `json:"requestId"`
	NodeIP        string         `json:"nodeIP"`
	Attempts      int            `json:"attempts"`
	UpdatedAt     time.Time      `json:"updatedAt,omitzero"`
	RetryAt       time.Time      `json:"retryAt,omitzero"`
	LastHostError *HostErrorInfo `json:"lastHostError,omitempty"`
}

// HostErrorInfo is the last failed call of the cell controller to the host service.
type HostErrorInfo struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// PortalRequest asks the management plane to request steps for cells.
type PortalRequest struct {
	Cells           []string `json:"cells"`
	BootstrapSHA256 string   `json:"bootstrapSHA256"`
}

// PortalResult answers a portal request: the revision of the commit, one step for each new cell,
// and the cells that were already requested.
type PortalResult struct {
	RequestID        string        `json:"requestId"`
	Revision         spec.Revision `json:"revision"`
	Steps            []PortalStep  `json:"steps"`
	AlreadyRequested []string      `json:"alreadyRequested"`
}

// MarshalJSON encodes empty Steps and AlreadyRequested as [], never null.
func (r PortalResult) MarshalJSON() ([]byte, error) {
	type plain PortalResult
	if r.Steps == nil {
		r.Steps = []PortalStep{}
	}
	if r.AlreadyRequested == nil {
		r.AlreadyRequested = []string{}
	}
	return json.Marshal(plain(r))
}

// PortalStep names the step that a portal request signed for a cell.
type PortalStep struct {
	Cell   string `json:"cell"`
	StepID string `json:"stepID"`
}

// HostError is a failed call to the host service. Reason is one of the hostsvc reasons.
type HostError struct {
	Reason     string
	RequestID  string
	Status     int
	RetryAfter time.Duration
}

func (e *HostError) Error() string {
	return fmt.Sprintf("host service: %s (status %d, request %s)", e.Reason, e.Status, e.RequestID)
}

// Retry reports whether the caller may try the call again: after hostsvc_busy and
// hostsvc_unavailable. A pin or a denial does not change by waiting.
func (e *HostError) Retry() bool {
	return e.Reason == ReasonHostsvcBusy || e.Reason == ReasonHostsvcUnavailable
}

var (
	stepIDRE    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	requestIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

var stepStates = []string{
	StepQueued, StepCreating, StepAdmitting, StepBootstrapping, StepDone, StepFailed, StepFailedFinal,
	StepCancelled, StepRefused,
}

// ValidStepStatus reports whether s has the shape that the host service, the cell controller and
// the management plane accept: a known state, an empty or known stage, reason and detail, a known
// reason in LastHostError, a request ID of
// 16 lowercase hex characters or none, an IPv4 node address or none, 0 to 3 attempts, a step ID of
// 32 lowercase hex characters and a cell that is a DNS label.
func ValidStepStatus(s StepStatus) bool {
	if !stepIDRE.MatchString(s.ID) || !spec.ValidName(s.Cell) || !slices.Contains(stepStates, s.State) {
		return false
	}
	switch s.Stage {
	case "", StageCreating, StageAdmitting, StageBootstrapping:
	default:
		return false
	}
	if s.Reason != "" && s.Reason != step.Code && !isHostReason(s.Reason) {
		return false
	}
	if s.LastHostError != nil && !isHostReason(s.LastHostError.Reason) {
		return false
	}
	if s.Detail != "" && !slices.Contains(step.Details(), s.Detail) {
		return false
	}
	if s.RequestID != "" && !requestIDRE.MatchString(s.RequestID) {
		return false
	}
	if s.NodeIP != "" {
		ip, err := netip.ParseAddr(s.NodeIP)
		if err != nil || !ip.Is4() || ip.String() != s.NodeIP {
			return false
		}
	}
	return s.Attempts >= 0 && s.Attempts <= 3
}

func isHostReason(r string) bool {
	switch r {
	case ReasonHostsvcUntrusted, ReasonHostsvcUnavailable, ReasonHostsvcDenied, ReasonHostsvcBusy:
		return true
	}
	return false
}

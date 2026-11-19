// Package agentban bans the SPIRE agents of cells that the cluster_jwt plugin refuses. The plugin
// refuses a revoked or retired cell at attestation, and an agent that attested before keeps its SVID
// until it expires. A ban makes the server refuse the agent at its next sync.
package agentban

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
)

// Agent is one attested agent in the SPIRE server.
type Agent struct {
	ID     string
	Banned bool
}

// API is the part of the SPIRE Agent API that the ban loop uses.
type API interface {
	// List returns the agents that the cluster_jwt plugin attested.
	List(ctx context.Context) ([]Agent, error)
	// Ban bans one agent. An agent that the server no longer holds counts as banned.
	Ban(ctx context.Context, id string) error
}

// Config is the setting of the ban loop.
type Config struct {
	TrustDomain string
	// Read returns the cells that the plugin refuses. An error means that the set is unknown.
	Read  func() (clusterjwt.RevokedSet, error)
	API   API
	Every time.Duration
	Log   *slog.Logger
	Meter metric.Meter
}

const (
	pageSize  = 200
	callLimit = 10 * time.Second
)

// NewAgentAPI connects to the SPIRE server API on the unix socket. The list covers only agents that
// the cluster_jwt plugin attested. The returned function closes the connection.
func NewAgentAPI(socket string) (API, func() error, error) {
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", socket, err)
	}
	return &agentAPI{c: agentv1.NewAgentClient(conn)}, conn.Close, nil
}

type agentAPI struct{ c agentv1.AgentClient }

func (a *agentAPI) List(ctx context.Context) ([]Agent, error) {
	var out []Agent
	token := ""
	for {
		cctx, cancel := context.WithTimeout(ctx, callLimit)
		resp, err := a.c.ListAgents(cctx, &agentv1.ListAgentsRequest{
			Filter:    &agentv1.ListAgentsRequest_Filter{ByAttestationType: clusterjwt.PluginName},
			PageSize:  pageSize,
			PageToken: token,
		})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("list agents: %w", err)
		}
		for _, ag := range resp.GetAgents() {
			out = append(out, Agent{
				ID:     "spiffe://" + ag.GetId().GetTrustDomain() + ag.GetId().GetPath(),
				Banned: ag.GetBanned(),
			})
		}
		if token = resp.GetNextPageToken(); token == "" {
			return out, nil
		}
	}
}

func (a *agentAPI) Ban(ctx context.Context, id string) error {
	rest, ok := strings.CutPrefix(id, "spiffe://")
	if !ok {
		return fmt.Errorf("agent ID %q is not a SPIFFE ID", id)
	}
	td, path, _ := strings.Cut(rest, "/")
	cctx, cancel := context.WithTimeout(ctx, callLimit)
	defer cancel()
	_, err := a.c.BanAgent(cctx, &agentv1.BanAgentRequest{Id: &types.SPIFFEID{TrustDomain: td, Path: "/" + path}})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

// cellOf returns the cell in the ID of a cluster_jwt agent of the trust domain:
// spiffe://<td>/spire/agent/cluster_jwt/<cell>/<pod uid>/<nonce hash>. The match is on whole path
// segments, so a cell name never matches as a prefix of another.
func cellOf(trustDomain, id string) (string, bool) {
	rest, ok := strings.CutPrefix(id, "spiffe://"+trustDomain+"/spire/agent/"+clusterjwt.PluginName+"/")
	if !ok {
		return "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	return parts[0], true
}

// Once reads the refused cells and bans every agent of those cells that is not yet banned. It returns
// the number of agents that it banned. A failed read bans nothing.
func Once(ctx context.Context, cfg Config) (int, error) {
	set, err := cfg.Read()
	if err != nil {
		return 0, fmt.Errorf("read revoked cells: %w", err)
	}
	if len(set.Cells) == 0 {
		return 0, nil
	}
	agents, err := cfg.API.List(ctx)
	if err != nil {
		return 0, err
	}
	counter, err := cfg.Meter.Int64Counter("agentban.bans", metric.WithDescription("Agents banned because their cell is revoked or retired"))
	if err != nil {
		return 0, fmt.Errorf("counter: %w", err)
	}
	banned := 0
	var errs []error
	for _, ag := range agents {
		cell, ok := cellOf(cfg.TrustDomain, ag.ID)
		if !ok || ag.Banned {
			continue
		}
		source, refused := set.Cells[cell]
		if !refused {
			continue
		}
		if err := cfg.API.Ban(ctx, ag.ID); err != nil {
			errs = append(errs, fmt.Errorf("ban %s: %w", ag.ID, err))
			continue
		}
		banned++
		counter.Add(ctx, 1, metric.WithAttributes(attribute.String("cell", cell), attribute.String("source", source)))
		cfg.Log.InfoContext(ctx, "agent_banned", "cell", cell, "source", source, "agent_id", ag.ID)
	}
	return banned, errors.Join(errs...)
}

// Run calls Once at once and then every cfg.Every, until ctx ends. A failed pass is logged and
// tried again at the next tick.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Every <= 0 {
		return errors.New("agentban: Every must be positive")
	}
	tick := time.NewTicker(cfg.Every)
	defer tick.Stop()
	for {
		if _, err := Once(ctx, cfg); err != nil && ctx.Err() == nil {
			cfg.Log.ErrorContext(ctx, "agent_ban_failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

package agentban

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const testDomain = "dev-cp.test"

type fakeAgent struct {
	id     string
	attest string
	banned bool
}

// spireFake serves the Agent API of a SPIRE server on a unix socket. A banned ID stays banned. An
// ID that evict names answers NotFound to BanAgent.
type spireFake struct {
	agentv1.UnimplementedAgentServer
	mu       sync.Mutex
	agents   []*fakeAgent
	evicted  map[string]bool
	bans     []string
	pageSize int
	filters  []*agentv1.ListAgentsRequest_Filter
}

func newSpireFake(t *testing.T) (*spireFake, string) {
	t.Helper()
	f := &spireFake{evicted: map[string]bool{}, pageSize: 2}
	dir, err := os.MkdirTemp("", "ab")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	agentv1.RegisterAgentServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return f, sock
}

func agentID(cell, uid string) string {
	return "spiffe://" + testDomain + "/spire/agent/cluster_jwt/" + cell + "/" + uid + "/h1"
}

func (f *spireFake) add(attest, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents = append(f.agents, &fakeAgent{id: id, attest: attest})
}

func (f *spireFake) addBanned(attest, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents = append(f.agents, &fakeAgent{id: id, attest: attest, banned: true})
}

func (f *spireFake) evict(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evicted[id] = true
}

func (f *spireFake) banned() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.agents {
		if a.banned {
			out = append(out, a.id)
		}
	}
	return out
}

func (f *spireFake) banCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bans)
}

func splitID(id string) (string, string) {
	rest := id[len("spiffe://"):]
	for i := range rest {
		if rest[i] == '/' {
			return rest[:i], rest[i:]
		}
	}
	return rest, ""
}

func (f *spireFake) ListAgents(_ context.Context, req *agentv1.ListAgentsRequest) (*agentv1.ListAgentsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filters = append(f.filters, req.GetFilter())
	var match []*fakeAgent
	for _, a := range f.agents {
		if t := req.GetFilter().GetByAttestationType(); t != "" && t != a.attest {
			continue
		}
		if b := req.GetFilter().GetByBanned(); b != nil && b.GetValue() != a.banned {
			continue
		}
		match = append(match, a)
	}
	start := 0
	if tok := req.GetPageToken(); tok != "" {
		for i, a := range match {
			if a.id == tok {
				start = i + 1
			}
		}
	}
	end := min(start+f.pageSize, len(match))
	resp := &agentv1.ListAgentsResponse{}
	for _, a := range match[start:end] {
		td, path := splitID(a.id)
		resp.Agents = append(resp.Agents, &types.Agent{
			Id:              &types.SPIFFEID{TrustDomain: td, Path: path},
			AttestationType: a.attest,
			Banned:          a.banned,
		})
	}
	if end < len(match) {
		resp.NextPageToken = match[end-1].id
	}
	return resp, nil
}

func (f *spireFake) BanAgent(_ context.Context, req *agentv1.BanAgentRequest) (*emptypb.Empty, error) {
	id := "spiffe://" + req.GetId().GetTrustDomain() + req.GetId().GetPath()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bans = append(f.bans, id)
	if f.evicted[id] {
		return nil, status.Error(codes.NotFound, "agent not found")
	}
	for _, a := range f.agents {
		if a.id == id {
			a.banned = true
			return &emptypb.Empty{}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "agent not found")
}

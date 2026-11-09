package cellproxy

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var updateGolden = flag.Bool("update", false, "write testdata/principal-access-token.jwt again")

const goldenPath = "testdata/principal-access-token.jwt"

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func signingKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKey = k
	})
	return rsaKey
}

// tokenClaims mirrors jwt.RegisteredClaims of golang-jwt v5.3.1, in its field order. A one-value
// audience is an array, because MarshalSingleStringAsArray is true by default.
type tokenClaims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`
}

// issueToken mirrors IssueAccessToken and IssueRefreshToken of Argo CD Agent v0.10.0
// (internal/issuer/jwt.go lines 157 to 187, commit 78a3788f): RS512, jti from a random UUID,
// iss, sub, aud, nbf, iat and exp. The principal names the issuer "argocd-agent-server"
// (principal/server.go line 310). The audience is that name with "-access" or "-refresh"
// (internal/issuer/jwt.go lines 115 and 116). The subject is the JSON of auth.AuthSubject
// (principal/apis/auth/auth.go lines 97 to 102 and internal/auth/interface.go lines 19 to 22).
func issueToken(t *testing.T, audience, clientID, mode string, now time.Time) string {
	t.Helper()
	sub, err := json.Marshal(struct {
		ClientID string `json:"clientID"`
		Mode     string `json:"mode"`
	}{clientID, mode})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(tokenClaims{
		Issuer: "argocd-agent-server", Subject: string(sub), Audience: []string{"argocd-agent-server-" + audience},
		ExpiresAt: now.Add(5 * time.Minute).Unix(), NotBefore: now.Unix(), IssuedAt: now.Unix(), ID: uuid(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return signToken(t, `{"alg":"RS512","typ":"JWT"}`, string(claims))
}

func uuid(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// signToken builds a compact JWS from a header and claims, signed with RS512.
func signToken(t *testing.T, header, claims string) string {
	t.Helper()
	enc := base64.RawURLEncoding
	input := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(claims))
	sum := sha512.Sum512([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey(t), crypto.SHA512, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + enc.EncodeToString(sig)
}

func accessToken(t *testing.T, clientID, mode string) string {
	return issueToken(t, "access", clientID, mode, time.Now())
}

func refreshToken(t *testing.T, clientID string) string {
	return issueToken(t, "refresh", clientID, "autonomous", time.Now())
}

// tokenShape returns the raw header and the claim names of a token in their order.
func tokenShape(t *testing.T, token string) (string, []string, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	var names []string
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, k.(string))
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return string(header), names, claims
}

// TestGoldenAccessToken checks that the golden token has the shape that the helper builds.
// Run go test -run TestGoldenAccessToken -update to write the file again.
func TestGoldenAccessToken(t *testing.T) {
	if *updateGolden {
		tok := issueToken(t, "access", "dev-dev-cell-1", "autonomous", time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC))
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	golden := goldenToken(t)
	gh, gn, gc := tokenShape(t, golden)
	fh, fn, _ := tokenShape(t, accessToken(t, "dev-dev-cell-1", "autonomous"))
	if gh != `{"alg":"RS512","typ":"JWT"}` || gh != fh {
		t.Fatalf("golden header %s, helper header %s", gh, fh)
	}
	if want := []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}; !slices.Equal(gn, want) || !slices.Equal(fn, want) {
		t.Fatalf("golden claims %v, helper claims %v, want %v", gn, fn, want)
	}
	if gc["iss"] != "argocd-agent-server" || gc["sub"] != `{"clientID":"dev-dev-cell-1","mode":"autonomous"}` {
		t.Fatalf("golden claims are %v", gc)
	}
	if aud, ok := gc["aud"].([]any); !ok || len(aud) != 1 || aud[0] != "argocd-agent-server-access" {
		t.Fatalf("golden audience is %v", gc["aud"])
	}
}

func goldenToken(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// denied checks that err is PermissionDenied with message denied, and that the server logged
// the reason with the request ID that the client got in trailer.
func denied(t *testing.T, h *harness, err error, trailer metadata.MD, reason Reason) {
	t.Helper()
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied || st.Message() != "denied" {
		t.Fatalf("got %v, want PermissionDenied with message denied", err)
	}
	ids := trailer.Get("x-request-id")
	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("trailer %v has no single request ID", trailer)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, l := range logLines(t, h.serverLog) {
			if l["msg"] == "request denied" && l["request_id"] == ids[0] {
				if l["reason"] != string(reason) {
					t.Fatalf("request %s was denied with %v, want %s", ids[0], l["reason"], reason)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no log line for request %s:\n%s", ids[0], h.serverLog.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// invoke makes a unary call and returns its trailer.
func invoke(ctx context.Context, conn *grpc.ClientConn, method, msg string, opts ...grpc.CallOption) (metadata.MD, error) {
	var trailer metadata.MD
	err := conn.Invoke(ctx, method, wrapperspb.String(msg), &wrapperspb.StringValue{}, append(opts, grpc.Trailer(&trailer))...)
	return trailer, err
}

func TestServerRequiresOneAuthorization(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	conn := h.dial(t)
	good := accessToken(t, "dev-dev-cell-1", "autonomous")
	_, _, claims := tokenShape(t, good)
	claimsWith := func(sub string) string {
		c := map[string]any{}
		for k, v := range claims {
			c[k] = v
		}
		c["sub"] = sub
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	enc := base64.RawURLEncoding
	goodSub := `{"clientID":"dev-dev-cell-1","mode":"autonomous"}`
	dupSub, err := json.Marshal(goodSub)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"no authorization": nil,
		"two values":       {good, good},
		"Bearer prefix":    {"Bearer " + good},
		"alg none": {enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
			enc.EncodeToString([]byte(claimsWith(goodSub))) + "."},
		"malformed":       {"not-a-jwt"},
		"sub is not JSON": {signToken(t, `{"alg":"RS512","typ":"JWT"}`, claimsWith("dev-dev-cell-1"))},
		"duplicate sub key": {signToken(t, `{"alg":"RS512","typ":"JWT"}`,
			strings.TrimSuffix(claimsWith(goodSub), "}")+`,"sub":`+string(dupSub)+"}")},
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			for _, v := range values {
				ctx = metadata.AppendToOutgoingContext(ctx, "authorization", v)
			}
			s, err := conn.NewStream(ctx, bidiDesc(), "/test.Echo/Bidi")
			if err != nil {
				t.Fatal(err)
			}
			_ = s.SendMsg(wrapperspb.String("x"))
			err = s.RecvMsg(&wrapperspb.StringValue{})
			denied(t, h, err, s.Trailer(), SubjectMismatch)
		})
	}
	if n := h.up.hits.Load(); n != 0 {
		t.Fatalf("upstream hits %d, want 0", n)
	}
	t.Run("one good value passes", func(t *testing.T) {
		ctx := metadata.AppendToOutgoingContext(t.Context(), "authorization", good)
		if err := unaryCall(ctx, conn, "/test.Echo/Unary"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestServerChecksJWTSubject(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	conn := h.dial(t)
	call := func(ctx context.Context, token, method string) (metadata.MD, error) {
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", token)
		}
		return invoke(ctx, conn, method, "hello")
	}
	t.Run("golden token for dev-dev-cell-1", func(t *testing.T) {
		if _, err := call(t.Context(), goldenToken(t), "/test.Echo/Unary"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("token for dev-dev-cell-2", func(t *testing.T) {
		md, err := call(t.Context(), accessToken(t, "dev-dev-cell-2", "autonomous"), "/test.Echo/Unary")
		denied(t, h, err, md, SubjectMismatch)
	})
	t.Run("mode managed", func(t *testing.T) {
		md, err := call(t.Context(), accessToken(t, "dev-dev-cell-1", "managed"), "/test.Echo/Unary")
		denied(t, h, err, md, SubjectMismatch)
	})
	t.Run("Authenticate without a token", func(t *testing.T) {
		if _, err := call(t.Context(), "", "/authapi.Authentication/Authenticate"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Version without a token", func(t *testing.T) {
		md, err := call(t.Context(), "", "/versionapi.Version/Version")
		denied(t, h, err, md, SubjectMismatch)
	})
}

func TestServerChecksRefreshTokenSubject(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	conn := h.dial(t)
	refresh := func(ctx context.Context, token string, opts ...grpc.CallOption) (metadata.MD, error) {
		return invoke(ctx, conn, "/authapi.Authentication/RefreshToken", token, opts...)
	}
	t.Run("token for dev-dev-cell-2", func(t *testing.T) {
		md, err := refresh(t.Context(), refreshToken(t, "dev-dev-cell-2"))
		denied(t, h, err, md, SubjectMismatch)
	})
	t.Run("token for dev-dev-cell-1", func(t *testing.T) {
		if _, err := refresh(t.Context(), refreshToken(t, "dev-dev-cell-1")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("with an authorization value", func(t *testing.T) {
		ctx := metadata.AppendToOutgoingContext(t.Context(), "authorization", accessToken(t, "dev-dev-cell-1", "autonomous"))
		md, err := refresh(ctx, refreshToken(t, "dev-dev-cell-1"))
		denied(t, h, err, md, SubjectMismatch)
	})
	t.Run("compressed frame", func(t *testing.T) {
		md, err := refresh(t.Context(), refreshToken(t, "dev-dev-cell-1"), grpc.UseCompressor(gzip.Name))
		denied(t, h, err, md, SubjectMismatch)
	})
	t.Run("two frames", func(t *testing.T) {
		s, err := conn.NewStream(t.Context(), bidiDesc(), "/authapi.Authentication/RefreshToken")
		if err != nil {
			t.Fatal(err)
		}
		tok := refreshToken(t, "dev-dev-cell-1")
		send(t, s, tok)
		send(t, s, tok)
		if err := s.CloseSend(); err != nil {
			t.Fatal(err)
		}
		err = s.RecvMsg(&wrapperspb.StringValue{})
		denied(t, h, err, s.Trailer(), SubjectMismatch)
	})
}

package cellproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// tokenAlg is the algorithm of the tokens that the Argo CD Agent principal issues.
	tokenAlg = "RS512"
	// agentMode is the only agent mode that the central view serves.
	agentMode = "autonomous"
	// maxRefreshFrame bounds the one gRPC message of a RefreshToken call.
	maxRefreshFrame = 16 << 10
)

// checkSubject checks the unverified subject of a principal token: a compact JWS with header alg
// RS512, whose sub claim is a JSON string that decodes to exactly clientID and mode. clientID
// must be agent and mode must be autonomous. JSON objects with a duplicate key fail. The
// principal checks the signature.
func checkSubject(token, agent string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("token is not a compact JWS")
	}
	var raw [3][]byte
	for i, p := range parts {
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil || len(b) == 0 {
			return fmt.Errorf("token part %d is not base64url", i+1)
		}
		raw[i] = b
	}
	header, err := strictObject(raw[0])
	if err != nil {
		return fmt.Errorf("token header: %w", err)
	}
	var alg string
	if err := json.Unmarshal(header["alg"], &alg); err != nil || alg != tokenAlg {
		return fmt.Errorf("token alg is not %s", tokenAlg)
	}
	claims, err := strictObject(raw[1])
	if err != nil {
		return fmt.Errorf("token claims: %w", err)
	}
	var sub string
	if err := json.Unmarshal(claims["sub"], &sub); err != nil {
		return errors.New("token sub is not a JSON string")
	}
	subject, err := strictObject([]byte(sub))
	if err != nil {
		return fmt.Errorf("token sub: %w", err)
	}
	var clientID, mode string
	if len(subject) != 2 || json.Unmarshal(subject["clientID"], &clientID) != nil || json.Unmarshal(subject["mode"], &mode) != nil {
		return errors.New("token sub must hold exactly the strings clientID and mode")
	}
	if clientID != agent {
		return fmt.Errorf("token names agent %q, not %q", clientID, agent)
	}
	if mode != agentMode {
		return fmt.Errorf("token mode is %q, not %s", mode, agentMode)
	}
	return nil
}

// strictObject decodes one JSON object into its raw values. A duplicate key or trailing data
// fails.
func strictObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := tok.(string)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the object")
	}
	return out, nil
}

// readRefreshFrame reads the one uncompressed gRPC message of a RefreshToken request from body
// and returns the whole frame and the token in field 1. A compressed frame, a frame above
// maxRefreshFrame, a second frame or a parse error fails.
func readRefreshFrame(body io.Reader) ([]byte, string, error) {
	var head [5]byte
	if _, err := io.ReadFull(body, head[:]); err != nil {
		return nil, "", fmt.Errorf("read frame header: %w", err)
	}
	if head[0] != 0 {
		return nil, "", errors.New("frame is compressed")
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > maxRefreshFrame {
		return nil, "", fmt.Errorf("frame of %d bytes is above %d", n, maxRefreshFrame)
	}
	frame := make([]byte, 5+n)
	copy(frame, head[:])
	if _, err := io.ReadFull(body, frame[5:]); err != nil {
		return nil, "", fmt.Errorf("read frame: %w", err)
	}
	if _, err := io.ReadFull(body, make([]byte, 1)); !errors.Is(err, io.EOF) {
		return nil, "", errors.New("request has more than one frame")
	}
	token, err := refreshTokenField(frame[5:])
	return frame, token, err
}

// refreshTokenField returns field 1 of a RefreshTokenRequest, its only field.
func refreshTokenField(msg []byte) (string, error) {
	var token []byte
	found := false
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return "", protowire.ParseError(n)
		}
		msg = msg[n:]
		if num != 1 || typ != protowire.BytesType || found {
			return "", fmt.Errorf("unexpected field %d of type %d", num, typ)
		}
		v, n := protowire.ConsumeBytes(msg)
		if n < 0 {
			return "", protowire.ParseError(n)
		}
		token, msg, found = v, msg[n:], true
	}
	if !found {
		return "", errors.New("request has no refresh token")
	}
	return string(token), nil
}

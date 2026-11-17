package executor

import (
	"encoding/json"
)

func decodeEnv(b []byte) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return m
}

// spliceSignature returns the payload of other under the signatures of env.
func spliceSignature(env, other []byte) []byte {
	a, b := decodeEnv(env), decodeEnv(other)
	a["payload"] = b["payload"]
	out, _ := json.Marshal(a)
	return out
}

func stripSignatures(env []byte) []byte {
	a := decodeEnv(env)
	delete(a, "signatures")
	out, _ := json.Marshal(a)
	return out
}

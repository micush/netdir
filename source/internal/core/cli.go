package core

import (
	"encoding/json"
	"time"
)

// op runs a management command over the socket and returns the decoded data.
func Op(sock, cmd string, args any) json.RawMessage {
	res, err := StatusRequestTimeout(sock, map[string]any{"cmd": cmd, "args": args}, 140*time.Second)
	if err != nil {
		Fatal(err)
	}
	if ok, _ := res["ok"].(bool); !ok {
		Fatalf("%v", res["error"])
	}
	b, _ := json.Marshal(res["data"])
	return b
}

func Decode(b json.RawMessage, v any) {
	if err := json.Unmarshal(b, v); err != nil {
		Fatalf("unexpected reply from the daemon: %v", err)
	}
}

package core

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testMCPKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "netdir_" + base64.RawURLEncoding.EncodeToString(b)
}

func TestNormMCPKeys(t *testing.T) {
	k := testMCPKey()
	out, err := NormMCPKeys([]MCPKey{{Name: "laptop", Key: k}, {Name: "ops-1", Access: "RW", Hash: strings.ToUpper(McpKeyHash(testMCPKey()))}})
	if err != nil || len(out) != 2 {
		t.Fatal(err, out)
	}
	if out[0].Key != k || out[0].Hash != McpKeyHash(k) || out[0].Access != "ro" || out[0].Created == 0 {
		t.Fatalf("new key: %+v", out[0])
	}
	if out[1].Access != "rw" || !strings.HasPrefix(out[1].Hash, "sha256:") || out[1].Hash != strings.ToLower(out[1].Hash) || out[1].Created != 0 {
		t.Fatalf("kept key: %+v", out[1])
	}
	if l, err := NormMCPKeys(nil); l != nil || err != nil {
		t.Fatal("empty")
	}
	for name, bad := range map[string][]MCPKey{
		"no name":      {{Key: k}},
		"bad name":     {{Name: "my laptop", Key: k}},
		"same name":    {{Name: "a", Key: k}, {Name: "A", Key: testMCPKey()}},
		"same key":     {{Name: "a", Key: k}, {Name: "b", Key: k}},
		"short key":    {{Name: "a", Key: "short"}},
		"spaces":       {{Name: "a", Key: " " + k}},
		"no key, hash": {{Name: "a"}},
		"bad hash":     {{Name: "a", Hash: "sha256:abcd"}},
		"bad access":   {{Name: "a", Key: k, Access: "admin"}},
	} {
		if _, err := NormMCPKeys(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

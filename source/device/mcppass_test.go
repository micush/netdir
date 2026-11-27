package device

import (
	"context"
	"strings"
	"testing"
)

func passTools() map[string]any {
	m := filedirTools()
	m["__list"] = []any{
		J{"name": "files_list", "description": "list", "annotations": J{"readOnlyHint": true},
			"inputSchema": J{"properties": J{"folder": J{"type": "string"}, "limit": J{"type": "integer"}, "mode": J{"type": "string", "enum": []any{"a", "b"}}}, "required": []any{"folder"}}},
		J{"name": "files_delete", "description": "delete", "annotations": J{"readOnlyHint": false, "destructiveHint": true},
			"inputSchema": J{"properties": J{"folder": J{"type": "string"}, "path": J{"type": "string"}}, "required": []any{"folder", "path"}}},
		J{"name": "files_new_thing", "description": "a tool this program has never heard of", "annotations": J{"readOnlyHint": true},
			"inputSchema": J{"properties": J{"x": J{"type": "boolean"}}}},
		J{"name": "files_unmarked", "description": "says nothing about itself", "inputSchema": J{"properties": J{}}},
	}
	m["files_new_thing"] = J{"hello": "from a new tool", "password": "hunter2"}
	m["files_unmarked"] = "plain words, not JSON"
	return m
}

// Any tool of a device is reachable by its name, checked against the schema the device gave, with no code here for it.
func TestMCPPassthrough(t *testing.T) {
	ctx := context.Background()
	for _, plat := range []string{"filedir", "logdir", "flowdir", "dnsdir", "ntpdir", "netdir"} {
		d, st := dirStub(t, passTools())
		d.Platform = plat
		drv := open(t, d, Credential{Token: "RWKEY"})
		mp, ok := bareDriver(drv).(MCPPassthrough)
		if !ok {
			t.Fatalf("%s has no MCP passthrough", plat)
		}
		tools, err := mp.MCPTools(ctx)
		if err != nil || len(tools) != 4 || tools[0].Name != "files_delete" || tools[0].ReadOnly || !tools[0].Destructive || !tools[2].ReadOnly {
			t.Fatalf("%s tools: %v %+v", plat, err, tools)
		}
		if tools[3].ReadOnly {
			t.Errorf("a tool that says nothing about itself was taken for a read")
		}
		// a tool this program has no code for, answered with secrets hidden
		v, err := mp.MCPCall(ctx, "files_new_thing", map[string]any{"x": true}, false)
		if err != nil {
			t.Fatalf("%s: %v", plat, err)
		}
		if j := strings.TrimSpace(toJSON(v)); !strings.Contains(j, "from a new tool") || strings.Contains(j, "hunter2") {
			t.Errorf("%s: answer %s", plat, j)
		}
		// a text answer is handed on as text
		if v, err := mp.MCPCall(ctx, "files_unmarked", nil, true); err != nil || v != "plain words, not JSON" {
			t.Errorf("text answer: %v %v", v, err)
		}
		// what the schema forbids never reaches the device
		n := len(st.calls)
		for name, c := range map[string]struct {
			tool string
			args map[string]any
		}{
			"unknown tool":    {"files_nothing", nil},
			"missing":         {"files_list", map[string]any{}},
			"unknown arg":     {"files_list", map[string]any{"folder": "docs", "bogus": 1}},
			"wrong type":      {"files_list", map[string]any{"folder": 5}},
			"wrong number":    {"files_list", map[string]any{"folder": "docs", "limit": "x"}},
			"not in the enum": {"files_list", map[string]any{"folder": "docs", "mode": "c"}},
			"bad name":        {"../x", nil},
		} {
			if _, err := mp.MCPCall(ctx, c.tool, c.args, true); err == nil {
				t.Errorf("%s was accepted", name)
			}
		}
		// a tool that changes things is a change, not a read
		if _, err := mp.MCPCall(ctx, "files_delete", map[string]any{"folder": "docs", "path": "a"}, false); err == nil || !strings.Contains(err.Error(), "device_mcp_write") {
			t.Errorf("a change was run as a read: %v", err)
		}
		if _, err := mp.MCPCall(ctx, "files_unmarked", nil, false); err == nil {
			t.Error("an unmarked tool was run as a read")
		}
		for _, c := range st.calls[n:] {
			if !strings.HasPrefix(c, "") || strings.HasPrefix(c, "files_nothing") || strings.HasPrefix(c, "files_delete") {
				t.Errorf("a refused call reached the device: %s", c)
			}
		}
		if _, err := mp.MCPCall(ctx, "files_delete", map[string]any{"folder": "docs", "path": "a"}, true); err != nil && !strings.Contains(err.Error(), "unknown tool") {
			t.Errorf("an allowed change: %v", err)
		}
	}
}

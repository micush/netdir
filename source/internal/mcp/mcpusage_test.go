package mcp

import (
	"testing"
	"time"

	"netdir/internal/core"
)

func TestMCPUsageCapAndNil(t *testing.T) {
	u := core.NewMCPUsage("")
	now := time.Now()
	for i := 0; i < core.McpUsageRows+50; i++ {
		u.Record(core.McpUseCall{Time: now, Caller: "k", Addr: "a", Tool: "t", Target: "d" + string(rune('a'+i%26)) + time.Duration(i).String(), Result: "ok"})
	}
	if n := len(u.Hours[now.Truncate(time.Hour).Unix()]); n > core.McpUsageRows+1 {
		t.Errorf("%d rows in a bucket", n)
	}
	if u.Report(time.Hour)["totals"].(core.McpUseSum).Calls != int64(core.McpUsageRows+50) {
		t.Error("a call was lost over the cap")
	}
	var nilU *core.McpUsage
	nilU.Record(core.McpUseCall{})
	nilU.Flush()
	if got := mcpCallerOf("k@1.2.3.4", "1.2.3.4"); got != "k" {
		t.Errorf("caller %q", got)
	}
	if got := mcpCallerOf("1.2.3.4", "1.2.3.4"); got != "(address list)" {
		t.Errorf("caller %q", got)
	}
	if got := mcpTarget(map[string]any{"target": " tag:site=dc1 "}); got != "tag:site=dc1" {
		t.Errorf("target %q", got)
	}
}

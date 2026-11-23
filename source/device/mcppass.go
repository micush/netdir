package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Whatever the sibling products and other Network Directors offer over their own MCP endpoint is reachable here without a release of this
// program for each new tool: the driver asks the device for its tool list (tools/list) and calls a tool by its name.  The device's own
// description of the tool decides what is checked: its input schema (required arguments, types, enums, no argument it does not know) and
// its annotations (readOnlyHint false means the call changes something, which a caller must ask for as a change).  What the tool
// answers passes Redact as every answer does.  This is the whole of the connection to dnsdir, ntpdir, netdir, logdir, flowdir and filedir;
// the "show NAME" words and the change methods of their drivers are shortcuts on top of it.

// MCPTool is one tool of a device's MCP endpoint.
type MCPTool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	ReadOnly    bool           `json:"read_only"`
	Destructive bool           `json:"destructive,omitempty"`
	Required    []string       `json:"required,omitempty"`
	Args        map[string]any `json:"args,omitempty"` // each argument's schema: type, description, enum
}

// MCPPassthrough is implemented by the drivers of the products that speak MCP.
type MCPPassthrough interface {
	// MCPTools is the device's tool list, by name.
	MCPTools(ctx context.Context) ([]MCPTool, error)
	// MCPCall runs one tool with these arguments after checking them against the tool's schema, and returns its answer.  A tool that is not
	// read only needs allowWrite; the caller has decided that it may change things.
	MCPCall(ctx context.Context, tool string, args map[string]any, allowWrite bool) (any, error)
}

var mcpToolNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

func (m *director) MCPTools(ctx context.Context) ([]MCPTool, error) {
	req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": map[string]any{}}
	b, err := m.api.do(ctx, http.MethodPost, "/mcp", req, http.Header{"Accept": {"application/json, text/event-stream"}})
	if err != nil {
		return nil, err
	}
	var r struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Title       string `json:"title"`
				Description string `json:"description"`
				InputSchema struct {
					Properties map[string]any `json:"properties"`
					Required   []string       `json:"required"`
				} `json:"inputSchema"`
				Annotations struct {
					ReadOnly    *bool `json:"readOnlyHint"`
					Destructive *bool `json:"destructiveHint"`
				} `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("tools/list: the answer is not MCP JSON: %v", err)
	}
	if r.Error != nil {
		return nil, &statusError{Code: http.StatusBadRequest, Body: r.Error.Message}
	}
	out := make([]MCPTool, 0, len(r.Result.Tools))
	for _, t := range r.Result.Tools {
		mt := MCPTool{Name: t.Name, Title: t.Title, Description: t.Description, Required: t.InputSchema.Required, Args: t.InputSchema.Properties,
			ReadOnly:    t.Annotations.ReadOnly != nil && *t.Annotations.ReadOnly, // not said: it may change things
			Destructive: t.Annotations.Destructive != nil && *t.Annotations.Destructive}
		out = append(out, mt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// checkMCPArgs checks args against a tool's schema: every required one is there, none is unknown, and each has the type and, where the
// schema lists them, one of the values it names.
// CheckMCPArgs is the check the passthrough makes before a call.
func CheckMCPArgs(t MCPTool, args map[string]any) error { return checkMCPArgs(t, args) }

func checkMCPArgs(t MCPTool, args map[string]any) error {
	for _, k := range t.Required {
		if v, ok := args[k]; !ok || v == nil {
			return fmt.Errorf("%s: the argument %q is required", t.Name, k)
		}
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		spec, ok := t.Args[k].(map[string]any)
		if !ok {
			names := make([]string, 0, len(t.Args))
			for n := range t.Args {
				names = append(names, n)
			}
			sort.Strings(names)
			return fmt.Errorf("%s: no argument %q (it takes: %s)", t.Name, k, strings.Join(names, ", "))
		}
		v := args[k]
		switch spec["type"] {
		case "string":
			if _, ok := v.(string); !ok {
				return fmt.Errorf("%s: %s is a string", t.Name, k)
			}
		case "integer", "number":
			if _, ok := v.(float64); !ok {
				return fmt.Errorf("%s: %s is a number", t.Name, k)
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("%s: %s is true or false", t.Name, k)
			}
		case "object":
			if _, ok := v.(map[string]any); !ok {
				return fmt.Errorf("%s: %s is a JSON object", t.Name, k)
			}
		case "array":
			if _, ok := v.([]any); !ok {
				return fmt.Errorf("%s: %s is a JSON array", t.Name, k)
			}
		}
		if enum, ok := spec["enum"].([]any); ok && len(enum) > 0 {
			found := false
			for _, e := range enum {
				if e == v {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("%s: %s is one of %v", t.Name, k, enum)
			}
		}
	}
	return nil
}

func (m *director) MCPCall(ctx context.Context, tool string, args map[string]any, allowWrite bool) (any, error) {
	if !mcpToolNameRE.MatchString(tool) {
		return nil, fmt.Errorf("tool %q is not a tool name", tool)
	}
	tools, err := m.MCPTools(ctx)
	if err != nil {
		return nil, err
	}
	var t *MCPTool
	for i := range tools {
		if tools[i].Name == tool {
			t = &tools[i]
		}
	}
	if t == nil {
		names := make([]string, len(tools))
		for i := range tools {
			names[i] = tools[i].Name
		}
		return nil, fmt.Errorf("the device has no tool %q (it has: %s)", tool, strings.Join(names, ", "))
	}
	if args == nil {
		args = map[string]any{}
	}
	if err := checkMCPArgs(*t, args); err != nil {
		return nil, err
	}
	if !t.ReadOnly && !allowWrite {
		return nil, fmt.Errorf("%s changes things on the device: it is called as a change (device_mcp_write), not as a read", tool)
	}
	if _, takes := t.Args["node"]; takes && m.node != "" {
		if _, ok := args["node"]; !ok {
			args["node"] = m.node
		}
	}
	v, err := m.callAny(ctx, tool, args)
	if err != nil {
		return nil, err
	}
	return Redact(v), nil
}

// callAny is callPlain for any tool: an answer that is not JSON comes back as its text.
func (m *director) callAny(ctx context.Context, tool string, args map[string]any) (any, error) {
	v, err := m.callPlain(ctx, tool, args)
	var pe *plainTextError
	if errors.As(err, &pe) {
		return pe.text, nil
	}
	return v, err
}

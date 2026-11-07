package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every field the GUI labels must have an entry in the help panel of the screen or tab it is on
// (webui/help.js, a ["fields", [["Label", "..."]]] block). Labels come from the `l: "…"` specs in
// app.js; the controls that are labelled another way are listed below.
func TestHelpCoversEveryField(t *testing.T) {
	appB, err := os.ReadFile("webui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(appB)
	topics := helpTopics(t)
	has := func(tp, label string) bool {
		body, ok := topics[tp]
		if !ok {
			t.Fatalf("help.js has no panel %q", tp)
		}
		return strings.Contains(body, `["`+strings.ReplaceAll(label, `"`, `\"`)+`",`)
	}

	cfgAt := strings.Index(app, "const LB = [")
	if cfgAt < 0 {
		t.Fatal("cannot find the Settings schema in app.js")
	}
	// the arrays of the Settings schema and the panel their fields belong to
	arrays := []struct{ name, topic string }{
		{"GROUP_FIELDS", "config_groups"},
		{"WEB_FIELDS", "config_web"},
		{"SSO_FIELDS", ""}, // by tab, below
		{"LDAP_FIELDS", "users_ldap"},
		{"SNMP_FIELDS", "config_snmp"},
		{"PROM_FIELDS", "config_metrics"},
		{"MCP_FIELDS", "config_mcp"},
		{"LLDP_FIELDS", "config_general"},
		{"DEVICE_FIELDS", "config_devices"},
		{"DEVCRED_FIELDS", "config_devices"},
		{"DEVCHECK_FIELDS", "config_devices"},
		{"CLUSTER_FIELDS", "config_cluster"},
		{"LOG_FIELDS", "config_logs"},
		{"SYSLOG_FIELDS", "config_logs"},
	}
	type span struct {
		from, to int
		topic    string
		name     string
	}
	var spans []span
	for _, a := range arrays {
		i := strings.Index(app, "const "+a.name+" = [")
		if i < 0 {
			t.Fatalf("cannot find %s in app.js", a.name)
		}
		end := strings.Index(app[i:], "\n  ];")
		if eol := strings.Index(app[i:], "\n"); strings.HasSuffix(app[i:i+eol], "];") {
			end = eol // an array on one line
		}
		spans = append(spans, span{i, i + end, a.topic, a.name})
	}
	// single sign-on: the tab each field is on
	ssoTab := map[string]string{}
	for i, m := range regexp.MustCompile(`\["(?:General|Google|Microsoft|OpenID Connect)", \[([^\]]*)\]\]`).FindAllStringSubmatch(app, -1) {
		for _, k := range regexp.MustCompile(`"([a-z_]+)"`).FindAllStringSubmatch(m[1], -1) {
			ssoTab[k[1]] = "users_sso" + string(rune('0'+i))
		}
	}
	if len(ssoTab) < 10 {
		t.Fatalf("cannot read SSO_TABS: %v", ssoTab)
	}

	found := 0
	for _, m := range regexp.MustCompile(`\bl: "([^"]+)"`).FindAllStringSubmatchIndex(app, -1) {
		label := app[m[2]:m[3]]
		tp := "topology"
		if m[0] > cfgAt {
			tp = ""
			for _, sp := range spans {
				if m[0] > sp.from && m[0] < sp.to {
					tp = sp.topic
					switch sp.name {
					case "SSO_FIELDS":
						line := app[strings.LastIndex(app[:m[0]], "\n"):m[1]]
						k := regexp.MustCompile(`\bk: "([a-z_]+)"`).FindStringSubmatch(line)
						if k != nil {
							tp = ssoTab[k[1]]
						}
					}
				}
			}
			if tp == "" {
				t.Errorf("field %q: cannot tell which help panel it belongs to (new array or section in app.js?)", label)
				continue
			}
		}
		found++
		if !has(tp, label) {
			t.Errorf("field %q (panel %s) has no entry in the help's Fields list", label, tp)
		}
	}
	if found < 55 {
		t.Errorf("found only %d labelled fields in app.js; the label pattern probably changed", found)
	}

	extra := map[string][]string{
		"config_upgrades": {"Update every node automatically when a newer release is staged (one node at a time)", "Online repository"},
		"config_web":      {"Username", "Password", "Certificate", "Private key", "Main name", "Other names (one per line)", "IP addresses (one per line, optional)", "Pending CSR"},
		"cluster":         {"Node", "Join code"},
		"updates":         {"Release archive", "Fetch from online"},
		"anycast_bgp":     {"Local AS number", "Router ID", "New neighbor address", "New neighbor AS", "New neighbor description", "New neighbor password"},
		"anycast_ospf":    {"Router ID", "Hello interval", "Dead interval", "Metric", "New interface name", "New interface area", "New interface link type", "New interface key"},
		"history":         {"Compare version", "Configuration file"},
		"devices":         {"Target", "Ask for", "Command", "Address"},
		"host":            {"Time range", "From", "To"},
		"capture":         {"Interface", "Filter"},
		"log":             {"Filter text", "Level", "Time range", "Lines", "Live"},
		"node":            {"Action", "When", "Minutes", "Time of day"},
		"users_local":     {"Name", "Password", "Expires"},
	}
	for tp, ls := range extra {
		for _, l := range ls {
			if !has(tp, l) {
				t.Errorf("control %q (panel %s) has no entry in the help's Fields list", l, tp)
			}
		}
	}
}

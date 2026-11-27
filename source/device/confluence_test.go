package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type cfState struct {
	mu       sync.Mutex
	calls    []string
	auths    []string
	root     string // /rest/api or /wiki/rest/api
	version  int
	text     string
	puts     []map[string]any
	failRead bool // /space answers 500 (the read after a change)
}

const cfStorage = `<h1>VPN&nbsp;runbook</h1><p>Connect to <strong>vpn.example.com</strong> &amp; sign in.</p><ul><li>one</li><li>two</li></ul>` +
	`<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[password: hunter2]]></ac:plain-text-body></ac:structured-macro><!-- hidden comment --><script>alert(1)</script>`

func cfStub(t *testing.T, st *cfState, opts map[string]string, c Credential) Driver {
	t.Helper()
	if st.root == "" {
		st.root = "/rest/api"
	}
	st.version, st.text = 4, cfStorage
	d := tlsDevice(t, "wiki", "confluence", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		st.calls = append(st.calls, r.Method+" "+r.URL.RequestURI())
		st.auths = append(st.auths, r.Header.Get("Authorization"))
		if !strings.HasPrefix(r.URL.Path, st.root+"/") {
			jout(w, 404, map[string]any{"message": "no such path"})
			return
		}
		p := strings.TrimPrefix(r.URL.Path, st.root)
		page := func() map[string]any {
			return map[string]any{"id": "123456", "type": "page", "status": "current", "title": "VPN runbook",
				"space":    map[string]any{"key": "KB", "name": "Knowledge base"},
				"version":  map[string]any{"number": st.version, "when": "2026-11-20T10:00:00.000Z", "by": map[string]any{"displayName": "Joe Smith"}},
				"body":     map[string]any{"storage": map[string]any{"value": st.text, "representation": "storage"}},
				"metadata": map[string]any{"labels": map[string]any{"results": []any{map[string]any{"name": "vpn"}, map[string]any{"name": "runbook"}}}},
				"_links":   map[string]any{"webui": "/spaces/KB/pages/123456/VPN+runbook"}}
		}
		switch {
		case r.Method == http.MethodGet && p == "/space":
			if st.failRead {
				jout(w, 500, map[string]any{"message": "boom"})
				return
			}
			jout(w, 200, map[string]any{"results": []any{map[string]any{"key": "KB", "name": "Knowledge base", "type": "global", "status": "current"}}, "size": 1,
				"_links": map[string]any{"next": "/rest/api/space?start=1"}})
		case r.Method == http.MethodGet && p == "/content/search":
			jout(w, 200, map[string]any{"results": []any{page()}, "size": 1, "_links": map[string]any{"base": "https://wiki.example.com/wiki"}})
		case r.Method == http.MethodGet && p == "/content/123456":
			jout(w, 200, page())
		case r.Method == http.MethodGet && p == "/content/123456/child/page":
			jout(w, 200, map[string]any{"results": []any{}, "size": 0})
		case r.Method == http.MethodPost && p == "/content":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if r.Header.Get("X-Atlassian-Token") != "no-check" {
				jout(w, 403, map[string]any{"message": "XSRF check failed"})
				return
			}
			jout(w, 200, map[string]any{"id": "777", "type": b["type"], "title": b["title"]})
		case r.Method == http.MethodPut && p == "/content/123456":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			st.puts = append(st.puts, b)
			n, _ := b["version"].(map[string]any)["number"].(float64)
			if int(n) != st.version+1 {
				jout(w, 409, map[string]any{"message": "version conflict"})
				return
			}
			st.version = int(n)
			st.text = b["body"].(map[string]any)["storage"].(map[string]any)["value"].(string)
			jout(w, 200, page())
		default:
			io.Copy(io.Discard, r.Body)
			jout(w, 404, map[string]any{"message": "not found"})
		}
	}))
	d.Options = opts
	drv, err := Open(d, c)
	if err != nil {
		t.Fatal(err)
	}
	return drv
}

func TestConfluenceCloudAndDataCenterSignIn(t *testing.T) {
	ctx := context.Background()
	// Data Center with a personal access token: Bearer, below /rest/api, and the context path when there is one
	st := &cfState{root: "/confluence/rest/api"}
	drv := cfStub(t, st, map[string]string{"context": "/confluence"}, Credential{Token: "PAT123"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "Atlassian" || f.Model != "Confluence Data Center" {
		t.Fatalf("%+v %v", f, err)
	}
	if st.auths[0] != "Bearer PAT123" {
		t.Errorf("a personal access token is sent as a Bearer token: %q", st.auths[0])
	}
	// Cloud: Basic with the e-mail address and the API token, below /wiki/rest/api; no secret in a URL
	st = &cfState{root: "/wiki/rest/api"}
	drv = cfStub(t, st, map[string]string{"flavor": "cloud"}, Credential{Username: "joe@contoso.com", Password: "APITOKEN"})
	f, err = drv.Facts(ctx)
	if err != nil || f.Model != "Confluence Cloud" {
		t.Fatalf("%+v %v", f, err)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("joe@contoso.com:APITOKEN")); st.auths[0] != want {
		t.Errorf("Cloud signs in with the e-mail address and the API token: %q", st.auths[0])
	}
	for _, c := range st.calls {
		if strings.Contains(c, "APITOKEN") || strings.Contains(c, "joe@") {
			t.Errorf("a secret or an account in a URL: %s", c)
		}
	}
	// a Data Center with a user name and a password: Basic too
	st = &cfState{}
	drv = cfStub(t, st, nil, Credential{Username: "svc", Password: "pw"})
	if _, err := drv.Facts(ctx); err != nil || !strings.HasPrefix(st.auths[0], "Basic ") {
		t.Errorf("user name and password on Data Center: %v %q", err, st.auths)
	}
	// refused when the device is opened
	d := tlsDevice(t, "wiki", "confluence", http.NotFoundHandler())
	for name, tc := range map[string]struct {
		o map[string]string
		c Credential
	}{
		"cloud with a token only":   {map[string]string{"flavor": "cloud"}, Credential{Token: "x"}},
		"no secret":                 {nil, Credential{}},
		"unknown flavor":            {map[string]string{"flavor": "wiki"}, Credential{Token: "x"}},
		"a context with a host":     {map[string]string{"context": "//evil.example/x"}, Credential{Token: "x"}},
		"a context with a space":    {map[string]string{"context": "/a b"}, Credential{Token: "x"}},
		"user without a password":   {nil, Credential{Username: "u"}},
		"password without a user":   {nil, Credential{Password: "p"}},
		"cloud by the address, but": {map[string]string{"flavor": "cloud"}, Credential{}},
	} {
		d.Options = tc.o
		if _, err := Open(d, tc.c); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// an address that ends in .atlassian.net is Cloud without the option
	d.Address, d.Options = "acme.atlassian.net", nil
	if drv, err := Open(d, Credential{Username: "a@b.c", Password: "t"}); err != nil || !bareDriver(drv).(*confluence).cloud || bareDriver(drv).(*confluence).root != "/wiki/rest/api" {
		t.Errorf("acme.atlassian.net is Cloud: %v", err)
	}
}

func TestConfluenceShow(t *testing.T) {
	ctx := context.Background()
	st := &cfState{}
	drv := cfStub(t, st, nil, Credential{Token: "PAT"})
	out, err := drv.Show(ctx, "show spaces")
	if err != nil || !strings.Contains(out, "Knowledge base") || !strings.Contains(out, "there are more spaces") {
		t.Fatalf("spaces: %s %v", out, err)
	}
	out, err = drv.Show(ctx, "show pages space=KB search=vpn+runbook label=runbook limit=5")
	if err != nil || !strings.Contains(out, "VPN runbook") || !strings.Contains(out, "Joe Smith") || !strings.Contains(out, "https://wiki.example.com/wiki/spaces/KB/pages/123456") {
		t.Fatalf("pages: %s %v", out, err)
	}
	var cql string
	for _, c := range st.calls {
		if strings.Contains(c, "/content/search") {
			cql = c
		}
	}
	for _, want := range []string{"cql=type+%3D+page+and+space+%3D+%22KB%22+and+label+%3D+%22runbook%22+and+text+~+%22vpn+runbook%22+order+by+lastmodified+desc", "limit=5", "expand=space%2Cversion"} {
		if !strings.Contains(cql, want) {
			t.Errorf("the search is %s, want %s", cql, want)
		}
	}
	out, err = drv.Show(ctx, "show page 123456")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"VPN runbook", "vpn.example.com", "sign in.", `"labels"`, "runbook", "one", "two"} {
		if !strings.Contains(out, want) {
			t.Errorf("page lacks %q: %s", want, out)
		}
	}
	if !strings.Contains(out, "password: (hidden)") && !strings.Contains(out, "(hidden)") {
		t.Errorf("the code macro's text is missing or a secret in it is not hidden: %s", out)
	}
	for _, bad := range []string{"hunter2", "<strong>", "alert(1)", "hidden comment", "&amp;", "&nbsp;"} {
		if strings.Contains(out, bad) {
			t.Errorf("page holds %q: %s", bad, out)
		}
	}
	for _, bad := range []string{"show", "show pages | rm", "show page abc", "show page 12 34", "show pages space=a/b", `show pages search=a"b`, "show pages limit=0", "show pages foo=bar", "show users", "show pages space=K B"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestConfluenceText(t *testing.T) {
	got := cfText(`<p>a&nbsp;b</p><p>c</p><br/><ac:rich-text-body><p>d</p></ac:rich-text-body><style>x{}</style>`)
	if got != "a b\nc\n\nd" && got != "a b\nc\nd" {
		t.Errorf("%q", got)
	}
	if cfText("") != "" {
		t.Error("empty")
	}
}

func TestConfluenceAPIGet(t *testing.T) {
	ctx := context.Background()
	st := &cfState{}
	drv := cfStub(t, st, nil, Credential{Token: "PAT"})
	g := drv.(APIer)
	for _, ok := range []string{"/content/search?cql=type%3Dpage&limit=3", "/content/123456?expand=body.storage,version", "/content/123456/child/page", "/rest/api/content/123456", "/space?limit=5", "/space/KB", "/search?cql=text+~+%22vpn%22"} {
		if _, _, err := g.APIGet(ctx, ok); err != nil && !strings.Contains(err.Error(), "HTTP 404") { // a path the stub does not serve is a 404 from the stub, not a refusal
			t.Errorf("%s: %v", ok, err)
		}
	}
	v, _, err := g.APIGet(ctx, "/content/123456?expand=body.storage")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(v); strings.Contains(string(b), "hunter2") || !strings.Contains(string(b), "VPN") {
		t.Errorf("a secret in a page was not hidden: %s", b)
	}
	for _, bad := range []string{"/user/current", "/group", "/content/123456/restriction", "/content/123456/restriction/byOperation", "/space/KB/permission", "/space/KB/settings", "/audit", "/longtask",
		"/content/abc", "/content/123456/child/foo", "/content/123456/child/page/9", "/content/123456?foo=bar", "/content/123456?expand=a b", "/content?limit=0", "/content?limit=101",
		"/content?start=x", "//evil.example/x", "/content/123456/../../user", "/", "/space/KB/content/9"} {
		if _, _, err := g.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if _, err := drv.(APIer).APICatalog(ctx); err != nil {
		t.Error(err)
	}
	for _, c := range st.calls {
		if strings.Contains(c, "evil") || strings.Contains(c, "/user") || strings.Contains(c, "restriction") {
			t.Errorf("a refused path was sent: %s", c)
		}
	}
}

func TestConfluenceChange(t *testing.T) {
	ctx := context.Background()
	st := &cfState{}
	drv := cfStub(t, st, nil, Credential{Token: "PAT"})
	rc := drv.(RawChanger)
	// a new page: the XSRF header is sent
	create := `{"type":"page","title":"New","space":{"key":"KB"},"body":{"storage":{"value":"<p>hi</p>","representation":"storage"}}}`
	res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/content", Body: create}, false)
	if err != nil || !res.Applied || !strings.Contains(res.Answer, "777") {
		t.Fatalf("%+v %v", res, err)
	}
	// a dry run changes nothing and shows the page as it is
	n := len(st.puts)
	res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/content/123456", Body: `{"id":"123456","type":"page","title":"VPN runbook","version":{"number":5},"body":{"storage":{"value":"<p>new</p>","representation":"storage"}}}`}, true)
	if err != nil || res.Applied || !res.DryRun || len(st.puts) != n || res.Before == "" || st.version != 4 {
		t.Fatalf("dry run: %+v %v puts=%d version=%d", res, err, len(st.puts), st.version)
	}
	// a write: the version is the next one
	upd := `{"id":"123456","type":"page","title":"VPN runbook","version":{"number":5},"body":{"storage":{"value":"<p>new text</p>","representation":"storage"}}}`
	if res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/content/123456", Body: upd}, false); err != nil || !res.Applied || st.version != 5 || st.text != "<p>new text</p>" {
		t.Fatalf("%+v %v version=%d", res, err, st.version)
	}
	// a write after which the site does not answer a read: the page as it was comes back as the next version
	st.failRead = false
	st.version, st.text = 5, "<p>new text</p>"
	st.puts = nil
	bad := strings.Replace(upd, `"number":5`, `"number":6`, 1)
	bad = strings.Replace(bad, "new text", "worse text", 1)
	st.mu.Lock()
	st.failRead = true // from the moment of the PUT on: the check that follows it fails
	st.mu.Unlock()
	res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/content/123456", Body: bad}, false)
	if err == nil || !res.RolledBack {
		t.Fatalf("the change was not put back: %+v %v", res, err)
	}
	if st.text != "<p>new text</p>" || st.version != 7 {
		t.Errorf("after the put-back: version %d, text %q", st.version, st.text)
	}
	if last := st.puts[len(st.puts)-1]; last["version"].(map[string]any)["number"].(float64) != 7 || !strings.Contains(last["body"].(map[string]any)["storage"].(map[string]any)["value"].(string), "new text") {
		t.Errorf("the put-back is the old page as the next version: %v", last)
	}
	// a page that is not there: the copy cannot be read, and nothing is sent
	st.puts = nil
	st.failRead = false
	res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/content/999", Body: upd}, false)
	if err == nil && res.Applied || len(st.puts) != 0 {
		t.Errorf("a PUT to a page that is not there: %+v %v", res, err)
	}
}

func TestConfluenceWriteCheck(t *testing.T) {
	ok := func(m, p, b string) {
		t.Helper()
		if err := cfWriteCheck(m, p, b); err != nil {
			t.Errorf("%s %s refused: %v", m, p, err)
		}
	}
	no := func(m, p, b string) {
		t.Helper()
		if err := cfWriteCheck(m, p, b); err == nil {
			t.Errorf("%s %s %s was accepted", m, p, b)
		}
	}
	ok("POST", "/content", `{"type":"page"}`)
	ok("POST", "/content", `{"type":"blogpost"}`)
	ok("POST", "/content", `{"type":"comment"}`)
	ok("PUT", "/content/12?expand=version", `{"type":"page","version":{"number":3}}`)
	ok("POST", "/content/12/label", `[{"prefix":"global","name":"x"}]`)
	no("POST", "/content", `{"type":"attachment"}`)
	no("POST", "/content", ``)
	no("PUT", "/content/12", `{"type":"page"}`) // no version
	no("PUT", "/content/12", `{"type":"space","version":{"number":3}}`)
	no("DELETE", "/content/12", ``)
	no("POST", "/space", `{"key":"X"}`)
	no("POST", "/user/current", ``)
	no("PUT", "/content/12/restriction", `{}`)
	no("PUT", "/content/abc", `{"type":"page","version":{"number":2}}`)
}

package device

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// cfCloud is a Confluence Cloud with both APIs.  v1Gone answers every v1 path with 410 (the endpoints Atlassian removes), v2Gone
// every v2 path with 404.
type cfCloud struct {
	mu       sync.Mutex
	calls    []string
	v1Gone   bool
	v2Gone   bool
	failRead bool // the v2 space list answers 500 (the read after a change)
	version  int
	text     string
	bodies   map[string]map[string]any // the last body received, by "METHOD path"
}

func (s *cfCloud) seen(sub string) int {
	n := 0
	for _, c := range s.calls {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func cfCloudStub(t *testing.T, st *cfCloud) Driver {
	t.Helper()
	st.version, st.text, st.bodies = 4, cfStorage, map[string]map[string]any{}
	d := tlsDevice(t, "wiki", "confluence", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		st.calls = append(st.calls, r.Method+" "+r.URL.RequestURI())
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		st.bodies[r.Method+" "+r.URL.Path] = body
		q := r.URL.Query()
		switch {
		case strings.HasPrefix(r.URL.Path, "/wiki/rest/api/"):
			if st.v1Gone {
				jout(w, 410, map[string]any{"message": "This API has been removed"})
				return
			}
			p := strings.TrimPrefix(r.URL.Path, "/wiki/rest/api")
			page := map[string]any{"id": "123456", "type": "page", "title": "VPN runbook", "space": map[string]any{"key": "KB"},
				"version": map[string]any{"number": st.version, "when": "2026-11-20T10:00:00.000Z", "by": map[string]any{"displayName": "Joe Smith"}},
				"body":    map[string]any{"storage": map[string]any{"value": st.text}}, "_links": map[string]any{"webui": "/spaces/KB/pages/123456"}}
			switch {
			case r.Method == "GET" && p == "/space":
				jout(w, 200, map[string]any{"results": []any{map[string]any{"key": "KB", "name": "Knowledge base", "type": "global", "status": "current"}}})
			case r.Method == "GET" && p == "/content/search":
				jout(w, 200, map[string]any{"results": []any{page}})
			case r.Method == "GET" && p == "/content/123456":
				jout(w, 200, page)
			case r.Method == "POST" && p == "/content":
				jout(w, 200, map[string]any{"id": "700"})
			default:
				jout(w, 404, map[string]any{})
			}
		case strings.HasPrefix(r.URL.Path, "/wiki/api/v2/"):
			if st.v2Gone {
				jout(w, 404, map[string]any{"message": "not found"})
				return
			}
			p := strings.TrimPrefix(r.URL.Path, "/wiki/api/v2")
			page := map[string]any{"id": "123456", "status": "current", "title": "VPN runbook", "spaceId": "98765",
				"version": map[string]any{"number": st.version, "createdAt": "2026-11-20T10:00:00.000Z", "authorId": "acc-1"},
				"_links":  map[string]any{"webui": "/spaces/KB/pages/123456", "base": "https://acme.atlassian.net/wiki"}}
			switch {
			case r.Method == "GET" && p == "/spaces":
				if st.failRead {
					jout(w, 500, map[string]any{"message": "boom"})
					return
				}
				rs := []any{map[string]any{"id": "98765", "key": "KB", "name": "Knowledge base", "type": "global", "status": "current"}}
				if k := q.Get("keys"); k != "" && k != "KB" {
					rs = nil
				}
				jout(w, 200, map[string]any{"results": rs, "_links": map[string]any{"next": "/wiki/api/v2/spaces?cursor=abc"}})
			case r.Method == "GET" && p == "/pages":
				jout(w, 200, map[string]any{"results": []any{page}, "_links": map[string]any{"base": "https://acme.atlassian.net/wiki"}})
			case r.Method == "GET" && p == "/pages/123456":
				if q.Get("body-format") == "storage" {
					page["body"] = map[string]any{"storage": map[string]any{"representation": "storage", "value": st.text}}
				}
				if q.Get("include-labels") == "true" {
					page["labels"] = map[string]any{"results": []any{map[string]any{"name": "vpn"}}}
				}
				jout(w, 200, page)
			case r.Method == "PUT" && p == "/pages/123456":
				n, _ := body["version"].(map[string]any)["number"].(float64)
				if int(n) != st.version+1 {
					jout(w, 409, map[string]any{"message": "version conflict"})
					return
				}
				st.version = int(n)
				st.text = body["body"].(map[string]any)["value"].(string)
				jout(w, 200, page)
			case r.Method == "POST" && p == "/pages":
				jout(w, 200, map[string]any{"id": "800"})
			default:
				jout(w, 404, map[string]any{})
			}
		default:
			jout(w, 404, map[string]any{})
		}
	}))
	d.Options = map[string]string{"flavor": "cloud"}
	drv, err := Open(d, Credential{Username: "joe@contoso.com", Password: "TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	return drv
}

func TestConfluenceCloudPrefersV2AndFallsBackToV1(t *testing.T) {
	ctx := context.Background()
	st := &cfCloud{}
	drv := cfCloudStub(t, st)
	if _, err := drv.Facts(ctx); err != nil {
		t.Fatal(err)
	}
	out, err := drv.Show(ctx, "show page 123456")
	if err != nil || !strings.Contains(out, `"space": "KB"`) || !strings.Contains(out, "vpn.example.com") || !strings.Contains(out, "acc-1") || !strings.Contains(out, `"vpn"`) {
		t.Fatalf("page through v2 (the space key and the labels resolved): %s %v", out, err)
	}
	if st.seen("/wiki/rest/api/") != 0 {
		t.Errorf("v2 answered, and v1 was asked: %v", st.calls)
	}
	// the api v2 goes away: v1 answers, and is asked first afterwards
	st.v2Gone = true
	st.calls = nil
	out, err = drv.Show(ctx, "show page 123456")
	if err != nil || !strings.Contains(out, "Joe Smith") {
		t.Fatalf("page through v1: %s %v", out, err)
	}
	if _, err = drv.Show(ctx, "show page 123456"); err != nil {
		t.Fatal(err)
	}
	if st.seen("/wiki/api/v2/pages/123456") != 1 || st.seen("/wiki/rest/api/content/123456") != 2 {
		t.Errorf("v2 was tried once, then v1 first: %v", st.calls)
	}
	// and the other way: v1 is gone, v2 is back
	st.v2Gone, st.v1Gone = false, true
	st.calls = nil
	for _, cmd := range []string{"show spaces", "show page 123456", "show pages space=KB limit=5", "show pages"} {
		if _, err := drv.Show(ctx, cmd); err != nil {
			t.Errorf("%s: %v", cmd, err)
		}
	}
	// the list of pages in a space needs its ID in v2: the key is looked up, and the list is the newest change first
	if st.seen("/wiki/api/v2/spaces?limit=1&keys=KB") != 1 || st.seen("space-id=98765") != 1 || st.seen("sort=-modified-date") != 2 {
		t.Errorf("the pages of a space through v2: %v", st.calls)
	}
	out, _ = drv.Show(ctx, "show pages")
	if !strings.Contains(out, "VPN runbook") || !strings.Contains(out, `"space": "KB"`) || !strings.Contains(out, "https://acme.atlassian.net/wiki/spaces/KB/pages/123456") {
		t.Errorf("the pages through v2: %s", out)
	}
	// a text search has no v2: with v1 gone, the error says so
	_, err = drv.Show(ctx, "show pages search=vpn")
	if err == nil || !strings.Contains(err.Error(), "410") || !strings.Contains(err.Error(), "no search") {
		t.Errorf("a search with v1 gone: %v", err)
	}
	// both gone: an error that names both
	st.v2Gone = true
	if _, err = drv.Show(ctx, "show spaces"); err == nil || !strings.Contains(err.Error(), "v1:") || !strings.Contains(err.Error(), "v2:") {
		t.Errorf("both APIs gone: %v", err)
	}
	// an answer that the other API would repeat is not retried: a server error is one
	st.v2Gone, st.v1Gone = false, false
	st.calls = nil
	st.failRead = true // v2 /spaces answers 500
	if _, err := drv.Show(ctx, "show spaces"); err == nil {
		t.Error("a server error was swallowed")
	}
	if st.seen("/wiki/rest/api/") != 0 {
		t.Errorf("a 500 from v2 was retried through v1: %v", st.calls)
	}
}

func TestConfluenceDataCenterNeverUsesV2(t *testing.T) {
	st := &cfState{}
	drv := cfStub(t, st, nil, Credential{Token: "PAT"})
	ctx := context.Background()
	for _, cmd := range []string{"show spaces", "show pages", "show page 123456"} {
		if _, err := drv.Show(ctx, cmd); err != nil {
			t.Errorf("%s: %v", cmd, err)
		}
	}
	if _, err := drv.Facts(ctx); err != nil {
		t.Error(err)
	}
	for _, p := range []string{"/pages", "/spaces", "/wiki/api/v2/pages", "/api/v2/pages/1"} {
		if _, _, err := drv.(APIer).APIGet(ctx, p); err == nil || !strings.Contains(err.Error(), "Cloud") {
			t.Errorf("%s on Data Center: %v", p, err)
		}
		if _, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "POST", Path: p, Body: `{}`}, true); err == nil {
			t.Errorf("a change through %s on Data Center", p)
		}
	}
	for _, c := range st.calls {
		if strings.Contains(c, "/api/v2") {
			t.Errorf("Data Center was asked for the API v2: %s", c)
		}
	}
}

func TestConfluenceV2PathsAndTranslatedReads(t *testing.T) {
	ctx := context.Background()
	st := &cfCloud{}
	drv := cfCloudStub(t, st)
	g := drv.(APIer)
	for _, p := range []string{"/pages?sort=-modified-date&limit=10", "/pages/123456?body-format=storage&include-labels=true", "/wiki/api/v2/pages/123456", "/api/v2/spaces?keys=KB", "/spaces?limit=250&cursor=abc123"} {
		if _, _, err := g.APIGet(ctx, p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, bad := range []string{"/pages/123456/properties", "/spaces/98765/permissions", "/spaces/98765/roles", "/users", "/admin-key", "/pages/abc", "/pages?limit=251", "/pages?limit=0",
		"/pages?expand=body", "/pages?cql=x", "/pages?cursor=a%20b", "/pages?foo=1", "/pages/123456/children/9", "/blogposts/1/children", "/classification-levels"} {
		if _, _, err := g.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	// a v1 read that v1 no longer has goes to the v2 path that does the same
	st.v1Gone = true
	st.calls = nil
	v, _, err := g.APIGet(ctx, "/content/123456?expand=body.storage,metadata.labels")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(v); !strings.Contains(string(b), "VPN runbook") || strings.Contains(string(b), "hunter2") {
		t.Errorf("the page through v2: %s", b)
	}
	if st.seen("/wiki/api/v2/pages/123456?body-format=storage&include-labels=true") != 1 {
		t.Errorf("the v1 read became a v2 read: %v", st.calls)
	}
	if _, _, err := g.APIGet(ctx, "/space"); err != nil || st.seen("/wiki/api/v2/spaces") == 0 {
		t.Errorf("/space through v2: %v %v", err, st.calls)
	}
	// a CQL search has no v2 path
	if _, _, err := g.APIGet(ctx, "/content/search?cql=type%3Dpage"); err == nil || !strings.Contains(err.Error(), "CQL") {
		t.Errorf("a CQL search with v1 gone: %v", err)
	}
}

func TestConfluenceChangesThroughV2(t *testing.T) {
	ctx := context.Background()
	st := &cfCloud{}
	drv := cfCloudStub(t, st)
	rc := drv.(RawChanger)
	// a v1 create of a page, with v1 gone: sent through v2 with the space's ID and the parent
	st.v1Gone = true
	create := `{"type":"page","title":"New page","space":{"key":"KB"},"ancestors":[{"id":"11"},{"id":"22"}],"body":{"storage":{"value":"<p>hi</p>","representation":"storage"}}}`
	res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/content", Body: create}, false)
	if err != nil || !res.Applied || !strings.Contains(res.Note, "through the API v2") || !strings.Contains(res.Answer, "800") {
		t.Fatalf("%+v %v", res, err)
	}
	b := st.bodies["POST /wiki/api/v2/pages"]
	if b["spaceId"] != "98765" || b["parentId"] != "22" || b["title"] != "New page" || b["status"] != "current" ||
		b["body"].(map[string]any)["representation"] != "storage" || b["body"].(map[string]any)["value"] != "<p>hi</p>" {
		t.Errorf("the page as v2 got it: %v", b)
	}
	// a dry run changes nothing
	n := st.seen("POST /wiki/api/v2/pages")
	if res, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/content", Body: create}, true); err != nil || res.Applied || st.seen("POST /wiki/api/v2/pages") != n {
		t.Errorf("dry run: %+v %v", res, err)
	}
	// a v1 update of a page, with v1 gone: the same page through v2, the version as given
	upd := `{"id":"123456","type":"page","title":"VPN runbook","version":{"number":5,"message":"edit"},"body":{"storage":{"value":"<p>new text</p>","representation":"storage"}}}`
	if res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/content/123456", Body: upd}, false); err != nil || !res.Applied || st.version != 5 || st.text != "<p>new text</p>" {
		t.Fatalf("%+v %v version %d", res, err, st.version)
	}
	// what v1 has not got and v2 has no counterpart for is an error that says so, and nothing was sent
	if _, err = rc.RawChange(ctx, Raw{Method: "POST", Path: "/content/123456/label", Body: `[{"prefix":"global","name":"x"}]`}, false); err == nil || !strings.Contains(err.Error(), "410") {
		t.Errorf("a label with v1 gone: %v", err)
	}
	// v2 directly, and a write after which the site does not answer a read: the page as it was returns as the next version
	st.v1Gone = false
	st.calls = nil
	bad := `{"id":"123456","status":"current","title":"VPN runbook","version":{"number":6},"body":{"representation":"storage","value":"<p>worse text</p>"}}`
	st.mu.Lock()
	st.failRead = true
	st.mu.Unlock()
	res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/wiki/api/v2/pages/123456", Body: bad}, false)
	if err == nil || !res.RolledBack {
		t.Fatalf("the change was not put back: %+v %v", res, err)
	}
	if st.version != 7 || st.text != "<p>new text</p>" {
		t.Errorf("after the put-back: version %d, text %q", st.version, st.text)
	}
	if st.seen("/wiki/rest/api/") != 0 {
		t.Errorf("a v2 change touched v1: %v", st.calls)
	}
	// the write checks of the API v2
	for _, c := range []struct {
		m, p, b string
		ok      bool
	}{{"POST", "/pages", `{}`, true}, {"POST", "/blogposts", `{}`, true}, {"POST", "/footer-comments", `{}`, true}, {"PUT", "/pages/12", `{"version":{"number":2}}`, true},
		{"PUT", "/pages/12", `{}`, false}, {"DELETE", "/pages/12", ``, false}, {"POST", "/spaces", `{}`, false}, {"PUT", "/spaces/1", `{"version":{"number":2}}`, false}, {"POST", "/pages/12/labels", `{}`, false}} {
		if err := cfWriteCheck(c.m, c.p, c.b); (err == nil) != c.ok {
			t.Errorf("%s %s: %v", c.m, c.p, err)
		}
	}
}

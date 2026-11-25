package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Confluence (Atlassian), Cloud and Data Center / Server, through its REST API v1 (/rest/api; on Cloud below /wiki) and, on Cloud,
// also v2 (/wiki/api/v2), which Atlassian is moving the v1 endpoints to.  Data Center has v1 only.  On Cloud a read tries v2 first
// and v1 when v2 does not have the endpoint (HTTP 404, 405, 410 or 501), or the other way round for what only v1 has (CQL searches,
// the labels of a page), remembers which one answered, and says in an error when both failed; a write goes to the API that its
// path names, and a v1 create or update of a page or a blog post that v1 no longer has is sent again through v2 (nothing was
// changed by an endpoint that is gone):
//
//	Cloud          https://SITE.atlassian.net/wiki/rest/api/...     Basic: the e-mail address of the account and an API token
//	               (id.atlassian.com ▸ Security ▸ API tokens), as user name and password of the credential
//	Data Center    https://HOST[/CONTEXT]/rest/api/...              Bearer: a personal access token (the credential's token),
//	               or Basic: a user name and a password
//
// Options: "flavor" is cloud or datacenter (when it is not set, an address that ends in .atlassian.net is Cloud, any other is Data
// Center), "context" is the context path of a Data Center installation that has one ("/confluence"; Cloud is always below /wiki).
// The port is 443 unless the device says another (Data Center often answers on 8090 or 8443).  The secret goes into a header,
// never into a URL.  Reads are GETs; a change is RawChange (below).
//
// Confluence is a wiki, not a switch: the "device" is the Confluence site.
//
//   - Facts: the flavor and whether the site answers.  There are no interfaces, neighbors or configuration.
//   - Show (v2 or v1, whichever answers): "show platform", "show spaces [limit=N]", "show pages [space=KEY] [search=TEXT] [label=NAME] [limit=N]" (the newest
//     changes first; "+" in a TEXT is a space), "show page ID" (one page: where it is, who changed it last, its labels and its text
//     as plain text, cut at 20,000 characters).
//   - APIGet: v2 paths (Cloud): /pages, /blogposts, /spaces, /footer-comments, /inline-comments, by ID, with children, descendants,
//     labels, versions, ancestors, attachments (metadata); and v1 paths: /content (a page, a blog post or a comment, by ID, with child, descendant, label, version, history), /content/search
//     and /search with a CQL query, /space.  A v1 read that v1 no longer has is sent to its v2 counterpart (/content/ID, its
//     child/page, label and version, /space, /space/KEY and /content?type=page).  Users, groups, permissions, restrictions, audit
//     and settings are refused.
//   - RawChange (rw keys only, as everywhere), v2 (Cloud): POST /pages, POST /blogposts, POST /footer-comments, PUT /pages/ID and
//     PUT /blogposts/ID ({"spaceId": "...", "status": "current", "title": "...", "parentId": "...", "body": {"representation":
//     "storage", "value": "<p>...</p>"}}; a PUT has "id", "status", "title", "body" and "version": {"number": current + 1}); v1:
//     POST /content (a page, a blog post or a comment: {"type": "page", "title": "...",
//     "space": {"key": "KEY"}, "ancestors": [{"id": "123"}], "body": {"storage": {"value": "<p>...</p>", "representation":
//     "storage"}}}), PUT /content/ID (the whole page again, with version.number = the current number + 1) and POST
//     /content/ID/label.  With the guards on (NETDIR_DEVICE_GUARDS=1) DELETE and everything else (spaces, users, permissions,
//     restrictions, attachments) are refused.  A PUT is read first (the page with its text is the copy in "before") and is put
//     back when the site does not answer a read after it: the page as it was comes back as a new version.
//
// The body of a page is the storage format (XHTML with Confluence's own macros).  Secrets found in a text are hidden (Redact).
// There is nothing to import.  Written against the documentation only; not run against a real Confluence.

func init() { Register("confluence", newConfluence) }

type confluence struct {
	d     Device
	api   *apiClient
	cloud bool
	root  string // the path of the API v1: /wiki/rest/api or CONTEXT/rest/api

	mu    sync.Mutex
	pref  map[string]string // for each kind of read, the API (v1 or v2) that answered last
	space map[string]string // v2 space ID -> key
}

// cfV2 is the root of the API v2 (Cloud only).
const cfV2 = "/wiki/api/v2"

var (
	cfIDRE      = regexp.MustCompile(`^[0-9]{1,18}$`)
	cfKeyRE     = regexp.MustCompile(`^[A-Za-z0-9~_.-]{1,255}$`)
	cfWordRE    = regexp.MustCompile(`^[A-Za-z0-9._:@/+*~-]{1,128}$`)
	cfExpandRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._]*(,[A-Za-z][A-Za-z0-9._]*)*$`)
	cfContextRE = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*$`)
	cfTagRE     = regexp.MustCompile(`(?s)<!--.*?-->|<(?:script|style)[^>]*>.*?</(?:script|style)>|<[^>]+>`)
	cfBreakRE   = regexp.MustCompile(`(?i)<\s*(?:br\s*/?|/p|/li|/tr|/h[1-6]|/div|/ac:[a-z-]+)\s*>`)
	cfBlankRE   = regexp.MustCompile(`[ \t\r\f]*\n[ \t\r\n\f]*\n[ \t\r\n\f]*`)
	cfCDataRE   = regexp.MustCompile(`(?s)<!\[CDATA\[(.*?)\]\]>`)
	cfCursorRE  = regexp.MustCompile(`^[A-Za-z0-9._=:+/-]{1,1000}$`)
	cfIDsRE     = regexp.MustCompile(`^[A-Za-z0-9~_.,-]{1,500}$`)
	cfShortRE   = regexp.MustCompile(`^[A-Za-z0-9._ ~-]{1,64}$`)
	// the parameters of a read by path that take a short word, with the name Confluence knows them by
	cfParam = map[string]string{"spacekey": "spaceKey", "type": "type", "status": "status", "orderby": "orderby", "depth": "depth", "postingday": "postingDay"}
)

const (
	cfPage     = 25    // rows of a list when no limit is given
	cfMaxRows  = 100   // the most rows of one list
	cfTextMax  = 20000 // characters of a page's text
	cfExpandPg = "space,version"
	cfExpandOn = "body.storage,version,space,metadata.labels"
)

func newConfluence(d Device, c Credential) (Driver, error) {
	cloud := strings.HasSuffix(strings.ToLower(strings.TrimSpace(d.Address)), ".atlassian.net")
	switch f := strings.ToLower(strings.TrimSpace(d.Options["flavor"])); f {
	case "":
	case "cloud":
		cloud = true
	case "datacenter", "data-center", "server":
		cloud = false
	default:
		return nil, fmt.Errorf("device %s: option flavor is cloud or datacenter", d.Name)
	}
	root := "/rest/api"
	if cloud {
		root = "/wiki/rest/api"
	} else if ctx := strings.TrimRight(strings.TrimSpace(d.Options["context"]), "/"); ctx != "" {
		if !cfContextRE.MatchString(ctx) {
			return nil, fmt.Errorf("device %s: option context is the context path of the installation, such as /confluence", d.Name)
		}
		root = ctx + root
	}
	var auth string
	switch {
	case c.Token != "" && !cloud:
		auth = "Bearer " + c.Token
	case c.Username != "" && c.Password != "":
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
	case cloud:
		return nil, fmt.Errorf("device %s: Confluence Cloud needs the e-mail address of the account as the user name and an API token as the password", d.Name)
	default:
		return nil, fmt.Errorf("device %s: Confluence needs a personal access token, or a user name and a password", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", auth)
	api.hdr.Set("User-Agent", "netdir")
	return &confluence{d: d, api: api, cloud: cloud, root: root, pref: map[string]string{}, space: map[string]string{}}, nil
}

func (c *confluence) flavor() string {
	if c.cloud {
		return "Confluence Cloud"
	}
	return "Confluence Data Center"
}

// get sends one GET below the API v1 root and reads the JSON answer.
func (c *confluence) get(ctx context.Context, path string) (map[string]any, error) {
	return c.getAt(ctx, c.root, path)
}

// getAt sends one GET below root (the v1 root or cfV2) and reads the JSON answer.
func (c *confluence) getAt(ctx context.Context, root, path string) (map[string]any, error) {
	b, err := c.api.do(ctx, http.MethodGet, root+path, nil, nil)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("GET %s: the answer is not JSON (is this the %s API?): %v", path, c.flavor(), err)
	}
	return v, nil
}

// cfGone says that an answer means "this API does not have that": the endpoint is not there, or has been removed (410), so the
// other API may.  Anything else (sign-in, rights, a server error, no answer) would be the same through the other one.
func cfGone(err error) bool {
	var se *statusError
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone, http.StatusNotImplemented:
		return true
	}
	return false
}

// order is the APIs to try for one kind of read: the one that answered last first; on Cloud v2 before v1; on Data Center v1 only.
func (c *confluence) order(op string) []string {
	if !c.cloud {
		return []string{"v1"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pref[op] == "v1" {
		return []string{"v1", "v2"}
	}
	return []string{"v2", "v1"}
}

// via runs the read of each API in turn (the ones that have a function) until one answers, and remembers which.  An error that
// the other API would repeat ends it; when every API said "gone", the error names them all.
func (c *confluence) via(op string, fns map[string]func() (any, error)) (any, error) {
	var gone []string
	for _, api := range c.order(op) {
		f := fns[api]
		if f == nil {
			continue
		}
		v, err := f()
		if err == nil {
			c.mu.Lock()
			c.pref[op] = api
			c.mu.Unlock()
			return v, nil
		}
		if !cfGone(err) {
			return nil, err
		}
		gone = append(gone, api+": "+err.Error())
	}
	if len(gone) == 0 {
		return nil, errors.New("no API of this site does that")
	}
	return nil, fmt.Errorf("%s (tried %s)", gone[0], strings.Join(gone, "; "))
}

func (c *confluence) Facts(ctx context.Context) (Facts, error) {
	_, err := c.via("facts", map[string]func() (any, error){
		"v1": func() (any, error) { return c.get(ctx, "/space?limit=1") },
		"v2": func() (any, error) { return c.getAt(ctx, cfV2, "/spaces?limit=1") },
	})
	if err != nil {
		return Facts{}, err
	}
	return Facts{Hostname: c.d.Address, Vendor: "Atlassian", Model: c.flavor()}, nil
}

func (c *confluence) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (c *confluence) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (c *confluence) Config(context.Context) (string, error)          { return "", ErrUnsupported }
func (c *confluence) Close(context.Context)                           { c.api.close() }

// cfText turns the storage format of a page (XHTML with macros) into plain text.
func cfText(s string) string {
	// the text of a CDATA section (a code macro keeps it there) is text, whatever it holds: escaped, it survives the tags' removal
	s = cfCDataRE.ReplaceAllStringFunc(s, func(m string) string { return html.EscapeString(cfCDataRE.FindStringSubmatch(m)[1]) })
	s = cfBreakRE.ReplaceAllString(s, "\n")
	s = cfTagRE.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, "\u00a0", " ")
	s = cfBlankRE.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

// cfRow is the part of a content item (v1) that is worth reading: where it is, when and by whom it was changed, and a link.
func cfRow(it map[string]any, base string) map[string]any {
	row := map[string]any{"id": str(it["id"]), "type": str(it["type"]), "title": str(it["title"])}
	if s, ok := it["space"].(map[string]any); ok {
		row["space"] = firstOf(str(s["key"]), str(s["name"]))
	}
	if v, ok := it["version"].(map[string]any); ok {
		row["version"] = v["number"]
		row["modified"] = str(v["when"])
		if by, ok := v["by"].(map[string]any); ok {
			row["modified_by"] = firstOf(str(by["displayName"]), str(by["publicName"]), str(by["username"]))
		}
	}
	if l, ok := it["_links"].(map[string]any); ok && str(l["webui"]) != "" && base != "" {
		row["link"] = base + str(l["webui"])
	}
	return row
}

// cfRow2 is cfRow for an item of the API v2: the space is an ID (turned into its key), the editor an account ID.
func (c *confluence) cfRow2(ctx context.Context, it map[string]any, base, typ string) map[string]any {
	row := map[string]any{"id": str(it["id"]), "type": typ, "title": str(it["title"])}
	if sid := str(it["spaceId"]); sid != "" {
		row["space"] = c.spaceKey(ctx, sid)
	}
	if v, ok := it["version"].(map[string]any); ok {
		row["version"] = v["number"]
		row["modified"] = str(v["createdAt"])
		if a := str(v["authorId"]); a != "" {
			row["modified_by_account"] = a
		}
	}
	if st := str(it["status"]); st != "" {
		row["status"] = st
	}
	if l, ok := it["_links"].(map[string]any); ok && str(l["webui"]) != "" && base != "" {
		row["link"] = base + str(l["webui"])
	}
	return row
}

// spaceKey turns the ID of a space (API v2) into its key; an ID that cannot be resolved is returned as it is.
func (c *confluence) spaceKey(ctx context.Context, id string) string {
	c.mu.Lock()
	k, ok := c.space[id]
	c.mu.Unlock()
	if ok {
		return k
	}
	if v, err := c.getAt(ctx, cfV2, "/spaces?limit=250"); err == nil {
		c.mu.Lock()
		for _, it := range cfResults(v) {
			if str(it["id"]) != "" && str(it["key"]) != "" {
				c.space[str(it["id"])] = str(it["key"])
			}
		}
		k, ok = c.space[id]
		c.mu.Unlock()
		if ok {
			return k
		}
	}
	return id
}

// spaceID turns the key of a space into its ID (API v2).
func (c *confluence) spaceID(ctx context.Context, key string) (string, error) {
	v, err := c.getAt(ctx, cfV2, "/spaces?limit=1&keys="+url.QueryEscape(key))
	if err != nil {
		return "", err
	}
	for _, it := range cfResults(v) {
		if str(it["id"]) != "" {
			return str(it["id"]), nil
		}
	}
	return "", fmt.Errorf("space %s: there is no space with that key (show spaces lists them)", key)
}

// cfBase is the address that the relative links of an answer are below.
func (c *confluence) cfBase(top map[string]any) string {
	if l, ok := top["_links"].(map[string]any); ok && strings.HasPrefix(str(l["base"]), "https://") {
		return str(l["base"])
	}
	b := "https://" + hostPort(c.d, 443)
	if c.cloud {
		return b + "/wiki"
	}
	return b + strings.TrimSuffix(c.root, "/rest/api")
}

const cfUsage = "show platform | spaces [limit=N] | pages [space=KEY] [search=TEXT] [label=NAME] [limit=N] | page ID   (+ in a TEXT is a space)"

func cfArgs(words []string) (map[string]string, error) {
	out := map[string]string{}
	for _, w := range words {
		k, v, ok := strings.Cut(w, "=")
		k = strings.ToLower(k)
		if !ok || (k != "space" && k != "search" && k != "label" && k != "limit") || !cfWordRE.MatchString(v) {
			return nil, fmt.Errorf("%q: an argument is space=KEY, search=TEXT, label=NAME or limit=N (no spaces; + is a space)", w)
		}
		out[k] = v
	}
	if s, ok := out["space"]; ok && !cfKeyRE.MatchString(s) {
		return nil, errors.New("space: the key of a space (show spaces lists them)")
	}
	if l, ok := out["limit"]; ok && (!cfIDRE.MatchString(l) || l == "0") {
		return nil, errors.New("limit: a number above 0")
	}
	return out, nil
}

// cfQuote is a CQL string; the values reaching it have none of the characters that end it.
func cfQuote(v string) string {
	return `"` + strings.NewReplacer("+", " ", `"`, "", `\`, "").Replace(v) + `"`
}

// cfPageOut is what "show page" answers: one page with its text, from either API.
func cfPageOut(row map[string]any, storage string, labels []string) map[string]any {
	row["labels"] = labels
	t := cfText(storage)
	if r := []rune(t); len(r) > cfTextMax {
		t = string(r[:cfTextMax])
		row["text_truncated"] = true
	}
	row["text"] = t
	return row
}

func (c *confluence) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(cfUsage)
	}
	switch strings.ToLower(f[1]) {
	case "platform":
		return obsText(map[string]any{"flavor": c.flavor(), "api": c.root, "api_v2": map[bool]string{true: cfV2, false: ""}[c.cloud], "tip": cfUsage}), nil
	case "page":
		if len(f) != 3 || !cfIDRE.MatchString(f[2]) {
			return "", errors.New("show page ID: the number of the page (show pages lists them)")
		}
		id := f[2]
		v, err := c.via("page", map[string]func() (any, error){
			"v1": func() (any, error) {
				v, err := c.get(ctx, "/content/"+id+"?expand="+cfExpandOn)
				if err != nil {
					return nil, err
				}
				row := cfRow(v, c.cfBase(v))
				if st := str(v["status"]); st != "" {
					row["status"] = st
				}
				var names []string
				if md, ok := v["metadata"].(map[string]any); ok {
					names = cfLabels(md["labels"])
				}
				var text string
				if b, ok := v["body"].(map[string]any); ok {
					if s, ok := b["storage"].(map[string]any); ok {
						text = str(s["value"])
					}
				}
				return cfPageOut(row, text, names), nil
			},
			"v2": func() (any, error) {
				v, err := c.getAt(ctx, cfV2, "/pages/"+id+"?body-format=storage&include-labels=true")
				if err != nil {
					return nil, err
				}
				row := c.cfRow2(ctx, v, c.cfBase(v), "page")
				var text string
				if b, ok := v["body"].(map[string]any); ok {
					if s, ok := b["storage"].(map[string]any); ok {
						text = str(s["value"])
					}
				}
				return cfPageOut(row, text, cfLabels(v["labels"])), nil
			},
		})
		if err != nil {
			return "", err
		}
		return obsText(v), nil
	case "spaces":
		a, err := cfArgs(f[2:])
		if err != nil {
			return "", err
		}
		n := cfLimit(a)
		v, err := c.via("spaces", map[string]func() (any, error){
			"v1": func() (any, error) { return c.get(ctx, "/space?limit="+strconv.Itoa(n)) },
			"v2": func() (any, error) { return c.getAt(ctx, cfV2, "/spaces?limit="+strconv.Itoa(n)) },
		})
		if err != nil {
			return "", err
		}
		top, _ := v.(map[string]any)
		var rows []map[string]any
		for _, it := range cfResults(top) {
			rows = append(rows, map[string]any{"key": str(it["key"]), "name": str(it["name"]), "type": str(it["type"]), "status": str(it["status"])})
		}
		res := map[string]any{"shown": len(rows), "result": rows}
		if cfMore(top) {
			res["note"] = fmt.Sprintf("there are more spaces; the first %d are shown (limit=N, up to %d)", n, cfMaxRows)
		}
		return obsText(res), nil
	case "pages":
		a, err := cfArgs(f[2:])
		if err != nil {
			return "", err
		}
		n := cfLimit(a)
		fns := map[string]func() (any, error){
			"v1": func() (any, error) {
				cql := []string{"type = page"}
				if s := a["space"]; s != "" {
					cql = append(cql, "space = "+cfQuote(s))
				}
				if s := a["label"]; s != "" {
					cql = append(cql, "label = "+cfQuote(s))
				}
				if s := a["search"]; s != "" {
					cql = append(cql, "text ~ "+cfQuote(s))
				}
				q := url.Values{"cql": {strings.Join(cql, " and ") + " order by lastmodified desc"}, "limit": {strconv.Itoa(n)}, "expand": {cfExpandPg}}
				v, err := c.get(ctx, "/content/search?"+q.Encode())
				if err != nil {
					return nil, err
				}
				base := c.cfBase(v)
				var rows []map[string]any
				for _, it := range cfResults(v) {
					rows = append(rows, cfRow(it, base))
				}
				return cfListOut(rows, cfMore(v), n), nil
			},
		}
		if a["search"] == "" && a["label"] == "" { // the API v2 has neither a text search nor a filter by label
			fns["v2"] = func() (any, error) {
				q := url.Values{"sort": {"-modified-date"}, "limit": {strconv.Itoa(n)}}
				if s := a["space"]; s != "" {
					id, err := c.spaceID(ctx, s)
					if err != nil {
						return nil, err
					}
					q.Set("space-id", id)
				}
				v, err := c.getAt(ctx, cfV2, "/pages?"+q.Encode())
				if err != nil {
					return nil, err
				}
				base := c.cfBase(v)
				var rows []map[string]any
				for _, it := range cfResults(v) {
					rows = append(rows, c.cfRow2(ctx, it, base, "page"))
				}
				return cfListOut(rows, cfMore(v), n), nil
			}
		}
		v, err := c.via("pages", fns)
		if err != nil {
			if a["search"] != "" || a["label"] != "" {
				err = fmt.Errorf("%w (a text search and a label filter need the API v1: the API v2 has no search)", err)
			}
			return "", err
		}
		return obsText(v), nil
	}
	return "", errors.New(cfUsage)
}

func cfListOut(rows []map[string]any, more bool, n int) map[string]any {
	res := map[string]any{"shown": len(rows), "result": rows}
	if more {
		res["note"] = fmt.Sprintf("there are more pages; the first %d (newest change first) are shown (limit=N, up to %d)", n, cfMaxRows)
	}
	return res
}

// cfLabels reads the names of the labels of a page, from {"results": [{"name": ...}]} (either API).
func cfLabels(v any) []string {
	names := []string{}
	if lb, ok := v.(map[string]any); ok {
		if rs, ok := lb["results"].([]any); ok {
			for _, r := range rs {
				if m, ok := r.(map[string]any); ok && str(m["name"]) != "" {
					names = append(names, str(m["name"]))
				}
			}
		}
	}
	return names
}

func cfLimit(a map[string]string) int {
	n := cfPage
	if v, err := strconv.Atoi(a["limit"]); err == nil {
		n = v
	}
	if n > cfMaxRows {
		n = cfMaxRows
	}
	return n
}

func cfResults(v map[string]any) []map[string]any {
	var out []map[string]any
	rs, _ := v["results"].([]any)
	for _, r := range rs {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func cfMore(v map[string]any) bool {
	l, _ := v["_links"].(map[string]any)
	return str(l["next"]) != ""
}

// ---- reading by path ----

// cfSub are the parts of one content item that can be read below it (v1); permissions and restrictions are not among them.
var cfSub = map[string][]string{"child": {"page", "comment", "attachment"}, "descendant": {"page", "comment"}, "label": nil, "version": nil, "history": nil}

// cfSub2 are the parts of one item of the API v2 that can be read below it, for each kind of item.
var cfSub2 = map[string][]string{
	"pages":           {"children", "descendants", "ancestors", "labels", "versions", "footer-comments", "inline-comments", "attachments"},
	"blogposts":       {"labels", "versions", "footer-comments", "inline-comments", "attachments"},
	"spaces":          {"pages", "blogposts", "labels"},
	"footer-comments": {"children"},
	"inline-comments": {"children"},
}

// cfPath cuts a path (with or without the API root of this site) down to what is read and says which API it is for ("v1", "v2");
// a path that is not allowed is an error.
func (c *confluence) cfPath(p string) (api string, seg []string, err error) {
	pp := "/" + strings.TrimPrefix(p, "/")
	api = "v1"
	switch {
	case strings.HasPrefix(pp, cfV2+"/"):
		pp, api = strings.TrimPrefix(pp, cfV2), "v2"
	case strings.HasPrefix(pp, "/api/v2/"):
		pp, api = strings.TrimPrefix(pp, "/api/v2"), "v2"
	default:
		for _, r := range []string{c.root, "/wiki/rest/api", "/rest/api"} {
			if strings.HasPrefix(pp, r+"/") || pp == r {
				pp = strings.TrimPrefix(pp, r)
				break
			}
		}
	}
	seg = strings.Split(strings.Trim(pp, "/"), "/")
	bad := errors.New("path: /content, /content/ID (with /child, /child/page, /descendant, /label, /version or /history), /content/search, /search or /space; on Cloud also /pages, /blogposts, /spaces, /footer-comments and /inline-comments of the API v2 (see device_api_catalog)")
	if _, v2 := cfSub2[seg[0]]; v2 {
		if !c.cloud {
			return "", nil, errors.New("path: the API v2 is Confluence Cloud's; this site has the API v1 (/content, /space, /search)")
		}
		api = "v2"
	}
	if api == "v2" {
		kinds, ok := cfSub2[seg[0]]
		switch {
		case !ok:
			return "", nil, bad
		case len(seg) == 1, len(seg) == 2 && cfIDRE.MatchString(seg[1]):
			return api, seg, nil
		case len(seg) == 3 && cfIDRE.MatchString(seg[1]):
			for _, k := range kinds {
				if k == seg[2] {
					return api, seg, nil
				}
			}
		}
		return "", nil, bad
	}
	switch seg[0] {
	case "content":
		switch {
		case len(seg) == 1, len(seg) == 2 && (seg[1] == "search" || cfIDRE.MatchString(seg[1])):
			return api, seg, nil
		case len(seg) >= 3 && len(seg) <= 4 && cfIDRE.MatchString(seg[1]):
			kinds, ok := cfSub[seg[2]]
			if !ok {
				return "", nil, bad
			}
			if len(seg) == 3 {
				return api, seg, nil
			}
			for _, k := range kinds {
				if k == seg[3] {
					return api, seg, nil
				}
			}
		}
	case "search":
		if len(seg) == 1 {
			return api, seg, nil
		}
	case "space":
		if len(seg) == 1 || len(seg) == 2 && cfKeyRE.MatchString(seg[1]) || len(seg) == 3 && cfKeyRE.MatchString(seg[1]) && seg[2] == "content" {
			return api, seg, nil
		}
	}
	return "", nil, bad
}

// cfQuery checks the parameters of a read by path and returns them, with the names Confluence knows.
func cfQuery(api string, qs string) (url.Values, error) {
	vals, err := url.ParseQuery(qs)
	if err != nil {
		return nil, errors.New("path: the query is not valid")
	}
	q := url.Values{}
	for k, vs := range vals {
		v := vs[0]
		kk := strings.ToLower(k)
		max := cfMaxRows
		if api == "v2" {
			max = 250
		}
		switch {
		case kk == "expand" && api == "v1":
			if !cfExpandRE.MatchString(v) || len(v) > 500 {
				return nil, errors.New("path: expand is property names separated by commas")
			}
			q.Set("expand", v)
		case (kk == "cql" || kk == "title") && (api == "v1" || kk == "title"):
			if len(v) > 500 || junCtlRE.MatchString(v) {
				return nil, fmt.Errorf("path: %s is too long, or holds a control character", k)
			}
			q.Set(kk, v)
		case kk == "limit":
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > max {
				return nil, fmt.Errorf("path: limit is a number from 1 to %d", max)
			}
			q.Set(kk, v)
		case kk == "start" && api == "v1":
			if !cfIDRE.MatchString(v) {
				return nil, errors.New("path: start is a number")
			}
			q.Set(kk, v)
		case kk == "cursor" && api == "v2":
			if !cfCursorRE.MatchString(v) {
				return nil, errors.New("path: cursor is the value of the next link of a list")
			}
			q.Set(kk, v)
		case api == "v1" && (kk == "spacekey" || kk == "type" || kk == "status" || kk == "orderby" || kk == "depth" || kk == "postingday"):
			if !cfShortRE.MatchString(v) {
				return nil, fmt.Errorf("path: %s is a short word", k)
			}
			q.Set(cfParam[kk], v)
		case api == "v2" && (kk == "body-format" || kk == "sort" || kk == "status" || kk == "type" || kk == "depth" || kk == "include-labels" || kk == "include-versions" || kk == "include-version"):
			if !cfShortRE.MatchString(v) {
				return nil, fmt.Errorf("path: %s is a short word", k)
			}
			q.Set(kk, v)
		case api == "v2" && (kk == "space-id" || kk == "ids" || kk == "keys" || kk == "parent-id"):
			if !cfIDsRE.MatchString(v) {
				return nil, fmt.Errorf("path: %s is IDs or keys separated by commas", k)
			}
			q.Set(kk, v)
		default:
			if api == "v2" {
				return nil, fmt.Errorf("path: %q is not a parameter here (limit, cursor, title, body-format, sort, status, type, depth, space-id, ids, keys, parent-id, include-labels, include-version)", k)
			}
			return nil, fmt.Errorf("path: %q is not a parameter here (expand, cql, title, limit, start, spaceKey, type, status, orderby, depth, postingDay)", k)
		}
	}
	return q, nil
}

// cfToV2 is the path of the API v2 that has what a v1 read asked for ("" when it has nothing like it).
func cfToV2(seg []string, q url.Values) string {
	v := url.Values{}
	if l := q.Get("limit"); l != "" {
		v.Set("limit", l)
	}
	with := func(p string) string {
		if len(v) > 0 {
			return p + "?" + v.Encode()
		}
		return p
	}
	switch {
	case len(seg) == 1 && seg[0] == "content" && (q.Get("type") == "page" || q.Get("type") == ""):
		return with("/pages")
	case len(seg) == 2 && seg[0] == "content" && cfIDRE.MatchString(seg[1]):
		if strings.Contains(q.Get("expand"), "body") {
			v.Set("body-format", "storage")
		}
		if strings.Contains(q.Get("expand"), "label") {
			v.Set("include-labels", "true")
		}
		return with("/pages/" + seg[1])
	case len(seg) == 4 && seg[0] == "content" && seg[2] == "child" && seg[3] == "page":
		return with("/pages/" + seg[1] + "/children")
	case len(seg) == 3 && seg[0] == "content" && seg[2] == "label":
		return with("/pages/" + seg[1] + "/labels")
	case len(seg) == 3 && seg[0] == "content" && seg[2] == "version":
		return with("/pages/" + seg[1] + "/versions")
	case len(seg) == 1 && seg[0] == "space":
		return with("/spaces")
	case len(seg) == 2 && seg[0] == "space":
		v.Set("keys", seg[1])
		return with("/spaces")
	}
	return ""
}

func (c *confluence) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	api, seg, err := c.cfPath(pp)
	if err != nil {
		return nil, false, err
	}
	q, err := cfQuery(api, qs)
	if err != nil {
		return nil, false, err
	}
	if q.Get("limit") == "" && (len(seg) == 1 || len(seg) == 2 && seg[1] == "search" || seg[0] == "search") {
		q.Set("limit", strconv.Itoa(cfPage))
	}
	send := func(root, p string, q url.Values) (any, error) {
		if len(q) > 0 {
			p += "?" + q.Encode()
		}
		b, err := c.api.do(ctx, http.MethodGet, root+p, nil, nil)
		if err != nil {
			return nil, err
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", p, err)
		}
		return obsScrub(Redact(v)), nil
	}
	p := "/" + strings.Join(seg, "/")
	if api == "v2" {
		v, err := send(cfV2, p, q)
		return v, false, err
	}
	v, err := send(c.root, p, q)
	if err != nil && c.cloud && cfGone(err) { // v1 does not have it (any more): the v2 path that has the same, when there is one
		if alt := cfToV2(seg, q); alt != "" {
			ap, aqs, _ := strings.Cut(alt, "?")
			aq, _ := url.ParseQuery(aqs)
			if v2, err2 := send(cfV2, ap, aq); err2 == nil {
				return v2, false, nil
			}
		}
		return nil, false, fmt.Errorf("%w (the API v1 does not have this and there is no API v2 path that does the same: %s)", err, map[bool]string{true: "a CQL search is v1 only", false: "see device_api_catalog"}[seg[0] == "search" || len(seg) == 2 && seg[1] == "search"])
	}
	return v, false, err
}

func (c *confluence) APICatalog(context.Context) (any, error) {
	how := "Confluence REST API v1 below " + c.root + ": /content (pages, blog posts, comments; one item: /content/<id>, and below it /child, /child/page, /child/comment, /descendant, /label, /version, /history), " +
		"/content/search?cql=... and /search?cql=... (CQL), /space and /space/<KEY>. Parameters: expand (space,version,body.storage,metadata.labels), cql, title, limit (up to 100), start, spaceKey, type, status, orderby, depth. "
	ex := []string{"/content/search?cql=type=page and space=KB order by lastmodified desc&limit=10&expand=space,version", "/content/123456?expand=body.storage,version", "/space?limit=50", "/search?cql=text ~ \"vpn\""}
	if c.cloud {
		how += "Cloud also has the API v2 (" + cfV2 + "): /pages, /pages/<id> (and /children, /descendants, /ancestors, /labels, /versions, /footer-comments, /inline-comments, /attachments), /blogposts, /spaces (and /spaces/<id>/pages), /footer-comments and /inline-comments; " +
			"parameters limit (up to 250), cursor (from the next link), body-format=storage, sort=-modified-date, space-id, ids, keys, title, status, include-labels. It has no text search: CQL is v1. A v1 read that v1 no longer has is sent to the v2 path that does the same, when there is one. "
		ex = append(ex, "/pages?sort=-modified-date&limit=10", "/pages/123456?body-format=storage&include-labels=true", "/spaces?keys=KB")
	}
	how += "Users, groups, permissions, restrictions, audit and settings are refused. Changes are device_change_raw: POST /content (page, blogpost or comment), PUT /content/<id> (the whole page, version.number = current + 1), POST /content/<id>/label"
	if c.cloud {
		how += "; and in the API v2 POST /pages, POST /blogposts, POST /footer-comments, PUT /pages/<id>, PUT /blogposts/<id>. A v1 create or update of a page or a blog post that v1 no longer has is sent through v2"
	}
	return map[string]any{"how": how + "; no deletes.", "examples": ex,
		"tip": "show pages search=vpn, show page ID (device_show) read the same in one call, through whichever API answers; the body of a page is the storage format (XHTML)."}, nil
}

// ---- changing ----

// cfKind says what a body is: "page", "blogpost" or "comment" (v1 "type"), "" when it is none of them.
func cfKind(b map[string]any) string {
	switch t := str(b["type"]); t {
	case "page", "blogpost", "comment":
		return t
	}
	return ""
}

// cfWriteCheck allows what a change may be: a page, a blog post or a comment created, a page written again, a label added.  The
// paths of the API v2 are the ones named in the header.
func cfWriteCheck(method, p, body string) error {
	p = strings.SplitN(p, "?", 2)[0]
	seg := strings.Split(strings.Trim(p, "/"), "/")
	var b map[string]any
	if body != "" {
		_ = json.Unmarshal([]byte(body), &b)
	}
	switch {
	case method == http.MethodPost && len(seg) == 1 && seg[0] == "content":
		if t := cfKind(b); t == "" {
			return fmt.Errorf("body: type %q is refused: a page, a blogpost or a comment is created here", str(b["type"]))
		}
		return nil
	case method == http.MethodPut && len(seg) == 2 && seg[0] == "content" && cfIDRE.MatchString(seg[1]):
		if t := cfKind(b); t == "" {
			return fmt.Errorf("body: type %q is refused: a page, a blogpost or a comment is written here", str(b["type"]))
		}
		if v, ok := b["version"].(map[string]any); !ok || v["number"] == nil {
			return errors.New(`body: a PUT carries the whole page with "version": {"number": <the current number + 1>} (read it first: show page ID or /content/ID?expand=version,body.storage)`)
		}
		return nil
	case method == http.MethodPost && len(seg) == 3 && seg[0] == "content" && cfIDRE.MatchString(seg[1]) && seg[2] == "label":
		return nil
	case method == http.MethodPost && len(seg) == 1 && (seg[0] == "pages" || seg[0] == "blogposts" || seg[0] == "footer-comments"):
		return nil
	case method == http.MethodPut && len(seg) == 2 && (seg[0] == "pages" || seg[0] == "blogposts") && cfIDRE.MatchString(seg[1]):
		if v, ok := b["version"].(map[string]any); !ok || v["number"] == nil {
			return errors.New(`body: a PUT carries the whole page with "version": {"number": <the current number + 1>} (read it first: show page ID)`)
		}
		return nil
	}
	return errors.New("method and path: Confluence is changed with POST /content, PUT /content/ID and POST /content/ID/label, and on Cloud POST /pages, /blogposts, /footer-comments and PUT /pages/ID, /blogposts/ID of the API v2 (no deletes, no spaces, users, permissions or restrictions)")
}

// RawChange: see the header.  A rw key only: the gate is the same as for every platform.  The path says which API; a v1 create
// or update of a page or a blog post that v1 has not got (404, 405, 410, 501: nothing was changed) is sent again through v2.
func (c *confluence) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	v2 := false
	for _, pre := range []string{cfV2, "/api/v2"} {
		if strings.HasPrefix(r.Path, pre+"/") {
			r.Path, v2 = strings.TrimPrefix(r.Path, pre), true
			break
		}
	}
	if !v2 {
		for _, pre := range []string{c.root, "/wiki/rest/api", "/rest/api"} {
			if strings.HasPrefix(r.Path, pre+"/") {
				r.Path = strings.TrimPrefix(r.Path, pre)
				break
			}
		}
		if seg := strings.SplitN(strings.Trim(r.Path, "/"), "/", 2); seg[0] != "content" { // /pages, /blogposts, /spaces ... are the API v2's
			if _, ok := cfSub2[seg[0]]; ok {
				v2 = true
			}
		}
	}
	if v2 {
		if !c.cloud {
			return RawResult{DryRun: dry}, errors.New("path: the API v2 is Confluence Cloud's; this site has the API v1 (/content)")
		}
		return c.rawV2(ctx, r, dry)
	}
	res, err := c.rawV1(ctx, r, dry)
	if err == nil || res.Applied || !c.cloud || !cfGone(err) {
		return res, err
	}
	alt, ok := c.cfToV2Raw(ctx, r)
	if !ok {
		return res, err
	}
	res2, err2 := c.rawV2(ctx, alt, dry)
	if err2 != nil {
		return res2, fmt.Errorf("%w (the API v1 does not have this; through the API v2: %v)", err, err2)
	}
	res2.Note = strings.TrimSpace(res2.Note + " Sent through the API v2: the API v1 answered that it does not have " + r.Method + " " + r.Path + ".")
	return res2, nil
}

// cfToV2Raw turns a v1 create or update of a page or a blog post into the same change in the API v2.
func (c *confluence) cfToV2Raw(ctx context.Context, r Raw) (Raw, bool) {
	var b struct {
		Type      string `json:"type"`
		Title     string `json:"title"`
		Space     struct{ Key string }
		Ancestors []struct {
			ID any `json:"id"`
		}
		Body    struct{ Storage struct{ Value string } }
		Version struct {
			Number  float64
			Message string
		}
	}
	if json.Unmarshal([]byte(r.Body), &b) != nil || (b.Type != "page" && b.Type != "blogpost") {
		return r, false
	}
	kind := "pages"
	if b.Type == "blogpost" {
		kind = "blogposts"
	}
	body := map[string]any{"representation": "storage", "value": b.Body.Storage.Value}
	seg := strings.Split(strings.Trim(strings.SplitN(r.Path, "?", 2)[0], "/"), "/")
	switch {
	case r.Method == http.MethodPost && len(seg) == 1 && seg[0] == "content":
		if b.Space.Key == "" || b.Title == "" {
			return r, false
		}
		sid, err := c.spaceID(ctx, b.Space.Key)
		if err != nil {
			return r, false
		}
		out := map[string]any{"spaceId": sid, "status": "current", "title": b.Title, "body": body}
		if n := len(b.Ancestors); n > 0 && b.Type == "page" && str(b.Ancestors[n-1].ID) != "" {
			out["parentId"] = str(b.Ancestors[n-1].ID)
		}
		j, _ := json.Marshal(out)
		return Raw{Method: http.MethodPost, Path: "/" + kind, Body: string(j)}, true
	case r.Method == http.MethodPut && len(seg) == 2 && seg[0] == "content" && cfIDRE.MatchString(seg[1]):
		if b.Version.Number < 1 || b.Title == "" {
			return r, false
		}
		ver := map[string]any{"number": int(b.Version.Number)}
		if b.Version.Message != "" {
			ver["message"] = b.Version.Message
		}
		j, _ := json.Marshal(map[string]any{"id": seg[1], "status": "current", "title": b.Title, "body": body, "version": ver})
		return Raw{Method: http.MethodPut, Path: "/" + kind + "/" + seg[1], Body: string(j)}, true
	}
	return r, false
}

func (c *confluence) rawV1(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if r.Method == http.MethodPut && !strings.Contains(r.Path, "?") { // the copy taken first holds the text, so that it can be put back
		r.Path += "?expand=" + cfExpandOn
	}
	h := jsonHdr()
	h.Set("X-Atlassian-Token", "no-check")
	auth := http.Header{"Accept": {"application/json"}}
	pid := strings.TrimPrefix(strings.SplitN(r.Path, "?", 2)[0], "/content/")
	return restRaw(ctx, restSpec{
		api: c.api, hdr: h, auth: auth, json: true,
		wire: func(p string) string { return c.root + p },
		guard: func(method, p string) error {
			return cfWriteCheck(method, p, r.Body)
		},
		restore: func(snap []byte) (any, bool) {
			var old struct {
				ID, Type, Title string
				Space           struct{ Key string }
				Body            struct{ Storage struct{ Value string } }
			}
			if json.Unmarshal(snap, &old) != nil || old.Title == "" || old.Space.Key == "" || !cfIDRE.MatchString(pid) {
				return nil, false
			}
			rctx := context.WithoutCancel(ctx)
			cur, err := c.get(rctx, "/content/"+pid+"?expand=version") // the change may have been made: the next number follows the current one
			if err != nil {
				return nil, false
			}
			v, _ := cur["version"].(map[string]any)
			n, _ := v["number"].(float64)
			if n < 1 {
				return nil, false
			}
			return map[string]any{"id": old.ID, "type": firstOf(old.Type, "page"), "title": old.Title, "space": map[string]any{"key": old.Space.Key},
				"body":    map[string]any{"storage": map[string]any{"value": old.Body.Storage.Value, "representation": "storage"}},
				"version": map[string]any{"number": int(n) + 1, "message": "put back by netdir"}}, true
		},
		alive: func(ctx context.Context) error {
			_, err := c.get(ctx, "/space?limit=1")
			return err
		},
	}, r, dry)
}

// rawV2 is a change through the API v2.  A PUT is read first with its text (the page as it is now), so that it can be put back.
func (c *confluence) rawV2(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	h := jsonHdr()
	auth := http.Header{"Accept": {"application/json"}}
	seg := strings.Split(strings.Trim(strings.SplitN(r.Path, "?", 2)[0], "/"), "/")
	var old map[string]any
	return restRaw(ctx, restSpec{
		api: c.api, hdr: h, auth: auth, json: true,
		wire: func(p string) string { return cfV2 + p },
		guard: func(method, p string) error {
			return cfWriteCheck(method, p, r.Body)
		},
		prep: func(ctx context.Context) error {
			if r.Method == http.MethodPut && len(seg) == 2 && cfIDRE.MatchString(seg[1]) {
				if v, err := c.getAt(ctx, cfV2, "/"+seg[0]+"/"+seg[1]+"?body-format=storage"); err == nil {
					old = v
				}
			}
			return nil
		},
		restore: func([]byte) (any, bool) {
			if old == nil || str(old["title"]) == "" || len(seg) != 2 {
				return nil, false
			}
			value := ""
			if b, ok := old["body"].(map[string]any); ok {
				if s, ok := b["storage"].(map[string]any); ok {
					value = str(s["value"])
				}
			}
			cur, err := c.getAt(context.WithoutCancel(ctx), cfV2, "/"+seg[0]+"/"+seg[1]) // the change may have been made: the next number follows the current one
			if err != nil {
				return nil, false
			}
			v, _ := cur["version"].(map[string]any)
			n, _ := v["number"].(float64)
			if n < 1 {
				return nil, false
			}
			return map[string]any{"id": seg[1], "status": firstOf(str(old["status"]), "current"), "title": str(old["title"]),
				"body":    map[string]any{"representation": "storage", "value": value},
				"version": map[string]any{"number": int(n) + 1, "message": "put back by netdir"}}, true
		},
		alive: func(ctx context.Context) error {
			_, err := c.getAt(ctx, cfV2, "/spaces?limit=1")
			return err
		},
	}, r, dry)
}

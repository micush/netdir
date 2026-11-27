package device

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubCode is an answer that is only an HTTP status.
type stubCode int

type mediaStub struct {
	mu      sync.Mutex
	reqs    []string // "METHOD /path?query"
	bodies  []string
	logins  int
	logouts int
}

func (s *mediaStub) last() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		return "", ""
	}
	return s.reqs[len(s.reqs)-1], s.bodies[len(s.bodies)-1]
}

func (s *mediaStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

// mediaStubServer is a media application on loopback: auth says whether a request carries the key (else 401), pre handles a
// request first (a login), answers are keyed by "METHOD /path?query", "/path?query" or "/path".  Every request is recorded with its
// body, and none may carry SECRETKEY in its URL unless keyInQuery (Tautulli).
func mediaStubServer(t *testing.T, plat string, useTLS, keyInQuery bool, auth func(*http.Request) bool, pre func(http.ResponseWriter, *http.Request, *mediaStub) bool, answers map[string]any) (Device, *mediaStub) {
	t.Helper()
	st := &mediaStub{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !keyInQuery && (strings.Contains(r.URL.String(), "SECRETKEY") || strings.Contains(r.URL.String(), "s3cret")) {
			t.Errorf("a secret is in the URL: %s", r.URL)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		if pre != nil && pre(w, r, st) {
			return
		}
		if !auth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}
		uri := r.URL.Path
		if r.URL.RawQuery != "" {
			uri += "?" + r.URL.RawQuery
		}
		st.mu.Lock()
		st.reqs = append(st.reqs, r.Method+" "+uri)
		st.bodies = append(st.bodies, string(b))
		st.mu.Unlock()
		q := r.URL.Query()
		q.Del("apikey")
		clean := r.URL.Path
		if e := q.Encode(); e != "" {
			clean += "?" + e
		}
		var a any
		var ok bool
		for _, k := range []string{r.Method + " " + uri, r.Method + " " + clean, uri, clean, r.Method + " " + r.URL.Path, r.URL.Path} {
			if a, ok = answers[k]; ok {
				break
			}
		}
		if !ok {
			if r.Method != http.MethodGet {
				a = J{"ok": true}
			} else {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		switch v := a.(type) {
		case stubCode:
			w.WriteHeader(int(v))
		case string:
			_, _ = w.Write([]byte(v))
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
	})
	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	d := Device{Name: plat + "1", Platform: plat, Address: host, Port: pn, Insecure: true}
	if !useTLS {
		d.Options = map[string]string{"scheme": "http"}
	}
	return d, st
}

func headerAuth(name string) func(*http.Request) bool {
	return func(r *http.Request) bool { return r.Header.Get(name) == "SECRETKEY" }
}

func TestMediaRegistered(t *testing.T) {
	ports := map[string]int{"sonarr": 8989, "radarr": 7878, "lidarr": 8686, "prowlarr": 9696, "bazarr": 6767, "qbittorrent": 8080, "tautulli": 8181, "seerr": 5055, "plex": 32400, "jellyfin": 8096}
	for p, port := range ports {
		if DefaultPort(p) != port {
			t.Errorf("%s: default port %d", p, DefaultPort(p))
		}
	}
	d := Device{Name: "x", Platform: "sonarr", Address: "10.0.0.5"}
	if _, err := Open(d, Credential{Username: "u", Password: "p"}); err == nil {
		t.Error("an *arr without an API key opened")
	}
	if _, err := Open(Device{Name: "q", Platform: "qbittorrent", Address: "10.0.0.5"}, Credential{Token: "x"}); err == nil {
		t.Error("qBittorrent without a password or auth=none opened")
	}
	if _, err := Open(Device{Name: "q", Platform: "qbittorrent", Address: "10.0.0.5", Options: map[string]string{"auth": "none"}}, Credential{Token: "x"}); err != nil {
		t.Errorf("auth=none: %v", err)
	}
	for _, o := range []map[string]string{{"scheme": "ftp"}, {"url_base": "sonarr"}, {"url_base": "/a/../b"}, {"url_base": "/a b"}} {
		if _, err := Open(Device{Name: "x", Platform: "sonarr", Address: "10.0.0.5", Options: o}, Credential{Token: "k"}); err == nil {
			t.Errorf("%v accepted", o)
		}
	}
}

// Field names: Sonarr's /system/status, /series, /episodefile, /queue, /health, /config/host and /command as in Servarr's
// OpenAPI; checked against this stub only.
func sonarrAnswers() map[string]any {
	return map[string]any{
		"/api/v3/system/status": J{"appName": "Sonarr", "instanceName": "Sonarr", "version": "4.0.11.2680", "startTime": "2026-11-27T10:00:00Z", "osName": "debian", "urlBase": ""},
		"/api/v3/series": []any{J{"id": 12, "title": "Blue Bloods", "year": 2010, "path": "/mnt/dpool2/media/tv/Blue Bloods", "monitored": true, "statistics": J{"episodeFileCount": 293}},
			J{"id": 7, "title": "Bluey", "year": 2018, "path": "/mnt/dpool2/media/tv/Bluey"}, J{"id": 9, "title": "Bluey Minisodes", "path": "/tv/b"}},
		"/api/v3/episodefile?seriesId=12":  []any{J{"id": 100, "seriesId": 12, "path": "/mnt/dpool2/media/tv/Blue Bloods/Season 1/x.mp4", "size": 123, "quality": J{"quality": J{"name": "WEBRip-1080p"}}, "mediaInfo": J{"x": 1}}},
		"/api/v3/queue?page=1&pageSize=50": J{"page": 1, "totalRecords": 1, "records": []any{J{"id": 5, "title": "Show.S01E01", "status": "completed", "trackedDownloadState": "importPending", "statusMessages": []any{J{"title": "x", "messages": []any{"No files found"}}}, "outputPath": "/downloads/x", "customFormats": []any{}}}},
		"/api/v3/health":                   []any{J{"source": "RootFolderCheck", "type": "error", "message": "Missing root folder: /mnt/dpool2/media/tv"}, J{"source": "UpdateCheck", "type": "notice", "message": "update"}},
		"/api/v3/config/host":              J{"apiKey": "SECRETKEY", "password": "pw", "username": "admin", "port": 8989},
		"/api/v3/command":                  []any{J{"id": 40, "name": "RescanSeries", "status": "completed"}},
		"POST /api/v3/command":             J{"id": 41, "name": "RescanSeries", "status": "queued"},
	}
}

func TestSonarr(t *testing.T) {
	old := nowUnix
	nowUnix = func() int64 { return time.Date(2026, 11, 27, 11, 0, 0, 0, time.UTC).Unix() }
	defer func() { nowUnix = old }()
	d, st := mediaStubServer(t, "sonarr", true, false, headerAuth("X-Api-Key"), nil, sonarrAnswers())
	drv := open(t, d, Credential{Token: "SECRETKEY"})
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f != (Facts{Hostname: "Sonarr", Vendor: "Servarr", Model: "Sonarr", OSVersion: "4.0.11.2680", UptimeS: 3600}) {
		t.Fatalf("facts: %v %+v", err, f)
	}
	if _, err := drv.Interfaces(ctx); err != ErrUnsupported {
		t.Errorf("interfaces: %v", err)
	}
	if _, err := drv.Config(ctx); err != ErrUnsupported {
		t.Errorf("config: %v", err)
	}
	// a title with spaces, filtered and projected
	out, err := drv.Show(ctx, "show series name=Blue Bloods")
	if err != nil || !strings.Contains(out, `"count": 1`) || !strings.Contains(out, "Blue Bloods") || strings.Contains(out, "Bluey") {
		t.Errorf("show series: %v %s", err, out)
	}
	// the title is turned into the id
	out, err = drv.Show(ctx, "show episodefiles series=Blue Bloods")
	if err != nil || !strings.Contains(out, "WEBRip-1080p") || strings.Contains(out, "mediaInfo") {
		t.Errorf("episodefiles: %v %s", err, out)
	}
	if r, _ := st.last(); r != "GET /api/v3/episodefile?seriesId=12" {
		t.Errorf("request: %s", r)
	}
	if _, err := drv.Show(ctx, "show episodefiles series=Blue"); err == nil || !strings.Contains(err.Error(), "matches 3") {
		t.Errorf("an ambiguous title: %v", err)
	}
	if _, err := drv.Show(ctx, "show episodefiles series=Nothing Like It"); err == nil {
		t.Error("an unknown title")
	}
	out, err = drv.Show(ctx, "show queue")
	if err != nil || !strings.Contains(out, "importPending") || strings.Contains(out, "customFormats") {
		t.Errorf("queue: %v %s", err, out)
	}
	if out, err = drv.Show(ctx, "show queue full=yes"); err != nil || !strings.Contains(out, "customFormats") {
		t.Errorf("queue full: %v %s", err, out)
	}
	for _, bad := range []string{"show nothing", "show series bogus=1", "show queue lines=0", "show command", "show command id=a/b", "show", "show series name="} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// health warnings and errors are alerts; a notice is not
	al, err := drv.(AlertReporter).ActiveAlerts(ctx)
	if err != nil || len(al) != 1 || !strings.Contains(al[0], "Missing root folder") {
		t.Errorf("alerts: %v %v", err, al)
	}
	// the API: below /api/v3, the key hidden
	a := drv.(APIer)
	v, _, err := a.APIGet(ctx, "/api/v3/config/host")
	if m, _ := v.(map[string]any); err != nil || m["apiKey"] != "(hidden)" || m["password"] != "(hidden)" || m["port"] != float64(8989) {
		t.Errorf("config/host: %v %v", err, v)
	}
	before := st.count()
	for _, bad := range []string{"/api/v2/x", "/other", "/api/v3/series?apikey=x", "/api/v3/series?X-Api-Key=x", "/api/v3/../x", "/api/v3x/series"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was sent", bad)
		}
	}
	if st.count() != before {
		t.Error("a refused path reached the server")
	}
	if cat, err := a.APICatalog(ctx); err != nil || cat.(map[string]any)["commands"] == nil {
		t.Errorf("catalog: %v %v", err, cat)
	}
	// a command, by title, dry run first
	rc := drv.(RawChanger)
	n := st.count()
	res, err := rc.RawChange(ctx, Raw{Method: "CALL", Path: "RescanSeries", Body: `{"series": "Blue Bloods"}`}, true)
	if err != nil || res.Applied || !strings.Contains(res.Note, `"seriesId":12`) || !strings.Contains(res.Before, "RescanSeries") {
		t.Errorf("dry run: %v %+v", err, res)
	}
	for _, r := range st.reqs[n:] {
		if !strings.HasPrefix(r, "GET ") {
			t.Errorf("a dry run sent %s", r)
		}
	}
	res, err = rc.RawChange(ctx, Raw{Method: "CALL", Path: "RescanSeries", Body: `{"series": "Blue Bloods"}`}, false)
	r, body := st.last()
	if err != nil || !res.Applied || !strings.Contains(res.Answer, "41") || r != "POST /api/v3/command" || !strings.Contains(body, `"seriesId":12`) || !strings.Contains(body, `"name":"RescanSeries"`) {
		t.Errorf("command: %v %+v %s %s", err, res, r, body)
	}
	for _, bad := range []Raw{{Method: "CALL", Path: "rescan; rm"}, {Method: "CALL", Path: ""}, {Method: "CALL", Path: "RescanSeries", Body: "[1]"},
		{Method: "PUT", Path: "/api/v2/x"}, {Method: "GET", Path: "/api/v3/series"}, {Method: "POST", Path: "/api/v3/x?apikey=1"}, {Method: "CALL", Path: "RescanSeries", Lines: []string{"x"}}} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	// a REST change: the path is read first; DELETE is refused while the guards are on
	res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "/api/v3/config/host", Body: `{"port": 8990}`}, true)
	if err != nil || !strings.Contains(res.Before, "(hidden)") || strings.Contains(res.Before, "SECRETKEY") {
		t.Errorf("PUT dry run: %v %+v", err, res)
	}
	if _, err := rc.RawChange(ctx, Raw{Method: "DELETE", Path: "/api/v3/series/12"}, false); err == nil {
		t.Error("DELETE with the guards on")
	}
	// a wrong key: 401, not echoed
	_, err = open(t, d, Credential{Token: "WRONGKEY"}).Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "WRONGKEY") {
		t.Errorf("wrong key: %v", err)
	}
}

func TestArrPlainHTTPAndURLBase(t *testing.T) {
	ans := map[string]any{"/sonarr/api/v3/system/status": J{"appName": "Sonarr", "version": "4"}}
	d, _ := mediaStubServer(t, "sonarr", false, false, headerAuth("X-Api-Key"), nil, ans)
	d.Options["url_base"] = "/sonarr/"
	if f, err := open(t, d, Credential{Token: "SECRETKEY"}).Facts(context.Background()); err != nil || f.OSVersion != "4" {
		t.Errorf("http with url_base: %v %+v", err, f)
	}
	// without the option the driver speaks HTTPS, and a plain server does not answer it
	delete(d.Options, "scheme")
	if _, err := open(t, d, Credential{Token: "SECRETKEY"}).Facts(context.Background()); err == nil {
		t.Error("HTTPS to a plain HTTP server worked")
	}
}

func TestRadarrLidarrProwlarr(t *testing.T) {
	ctx := context.Background()
	d, st := mediaStubServer(t, "radarr", true, false, headerAuth("X-Api-Key"), nil, map[string]any{
		"/api/v3/system/status": J{"appName": "Radarr", "instanceName": "Radarr4K", "version": "5.14"},
		"/api/v3/movie":         []any{J{"id": 3, "title": "Heat", "year": 1995}},
		"/api/v3/command":       []any{},
	})
	drv := open(t, d, Credential{Token: "SECRETKEY"})
	if f, err := drv.Facts(ctx); err != nil || f.Hostname != "Radarr4K" || f.Model != "Radarr" {
		t.Errorf("radarr facts: %v %+v", err, f)
	}
	if _, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "RefreshMovie", Body: `{"movie": "heat"}`}, false); err != nil {
		t.Fatal(err)
	}
	if _, body := st.last(); !strings.Contains(body, `"movieIds":[3]`) {
		t.Errorf("movieIds: %s", body)
	}
	d, st = mediaStubServer(t, "lidarr", true, false, headerAuth("X-Api-Key"), nil, map[string]any{
		"/api/v1/system/status":    J{"appName": "Lidarr", "version": "2.8"},
		"/api/v1/artist":           []any{J{"id": 4, "artistName": "Portishead"}},
		"/api/v1/album?artistId=4": []any{J{"id": 1, "title": "Dummy", "releaseDate": "1994"}},
	})
	drv = open(t, d, Credential{Token: "SECRETKEY"})
	if f, err := drv.Facts(ctx); err != nil || f.Model != "Lidarr" || f.OSVersion != "2.8" {
		t.Errorf("lidarr facts: %v %+v", err, f)
	}
	if out, err := drv.Show(ctx, "show albums artist=portishead"); err != nil || !strings.Contains(out, "Dummy") {
		t.Errorf("albums: %v %s", err, out)
	}
	d, _ = mediaStubServer(t, "prowlarr", true, false, headerAuth("X-Api-Key"), nil, map[string]any{
		"/api/v1/system/status": J{"appName": "Prowlarr", "version": "1.28"},
		"/api/v1/health":        []any{},
	})
	drv = open(t, d, Credential{Token: "SECRETKEY"})
	if f, err := drv.Facts(ctx); err != nil || f.Model != "Prowlarr" {
		t.Errorf("prowlarr facts: %v %+v", err, f)
	}
	if al, err := drv.(AlertReporter).ActiveAlerts(ctx); err != nil || len(al) != 0 {
		t.Errorf("prowlarr alerts: %v %v", err, al)
	}
	_ = st
}

// Field names: Bazarr's /api/system/status (data.bazarr_version, start_time), /api/system/health (data[].object, issue) and
// /api/series (data[].sonarrSeriesId) as in Bazarr's API documentation; checked against this stub only.
func TestBazarr(t *testing.T) {
	ctx := context.Background()
	d, st := mediaStubServer(t, "bazarr", true, false, headerAuth("X-API-KEY"), nil, map[string]any{
		"/api/system/status": J{"data": J{"bazarr_version": "1.5.1", "operating_system": "Linux", "start_time": float64(time.Now().Unix() - 100)}},
		"/api/system/health": J{"data": []any{J{"object": "Sonarr", "issue": "Unable to connect"}}},
		"/api/series":        J{"data": []any{J{"sonarrSeriesId": 12, "title": "Blue Bloods", "path": "/tv/Blue Bloods"}}, "total": 1},
	})
	drv := open(t, d, Credential{Token: "SECRETKEY"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Model != "Bazarr" || f.OSVersion != "1.5.1" || f.UptimeS < 90 {
		t.Errorf("facts: %v %+v", err, f)
	}
	if al, err := drv.(AlertReporter).ActiveAlerts(ctx); err != nil || len(al) != 1 || al[0] != "Sonarr: Unable to connect" {
		t.Errorf("alerts: %v %v", err, al)
	}
	if out, err := drv.Show(ctx, "show series name=blue"); err != nil || !strings.Contains(out, `"count": 1`) {
		t.Errorf("series: %v %s", err, out)
	}
	res, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "series-action", Body: `{"series": "Blue Bloods", "action": "scan-disk"}`}, false)
	r, body := st.last()
	if err != nil || !res.Applied || r != "PATCH /api/series" {
		t.Fatalf("series-action: %v %+v %s", err, res, r)
	}
	if q, _ := url.ParseQuery(body); q.Get("seriesid") != "12" || q.Get("action") != "scan-disk" {
		t.Errorf("form: %s", body)
	}
}

// Field names and behaviour: qBittorrent's WebUI API (v2): the form login that answers "Ok." and sets SID, 403 without it, the
// Referer check, /app/version as text, and /torrents/stop (Web API 2.11, qBittorrent 5) or /torrents/pause before it.
func qbitStub(t *testing.T, apiVer string) (Device, *mediaStub) {
	sid := "SESSIONSID1"
	pre := func(w http.ResponseWriter, r *http.Request, st *mediaStub) bool {
		if r.Header.Get("Referer") == "" {
			t.Errorf("no Referer: %s", r.URL)
		}
		switch r.URL.Path {
		case "/api/v2/auth/login":
			_ = r.ParseForm()
			if r.Method != http.MethodPost || r.PostForm.Get("username") != "admin" || r.PostForm.Get("password") != "s3cret" {
				_, _ = w.Write([]byte("Fails."))
				return true
			}
			st.mu.Lock()
			st.logins++
			st.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: sid, Path: "/"})
			_, _ = w.Write([]byte("Ok."))
			return true
		case "/api/v2/auth/logout":
			st.mu.Lock()
			st.logouts++
			st.mu.Unlock()
			return true
		}
		if c, err := r.Cookie("SID"); err != nil || c.Value != sid {
			w.WriteHeader(http.StatusForbidden) // what qBittorrent answers without a session
			return true
		}
		return false
	}
	auth := func(r *http.Request) bool {
		c, err := r.Cookie("SID")
		return err == nil && c.Value == sid
	}
	ans := map[string]any{
		"/api/v2/app/version":       "v5.0.2",
		"/api/v2/app/webapiVersion": apiVer,
		"/api/v2/torrents/info": []any{J{"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "Blue.Bloods.S14E01.1080p", "state": "stalledUP", "category": "tv", "save_path": "/downloads", "magnet_uri": "magnet:?x"},
			J{"hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "Heat.1995", "state": "downloading", "category": "movies"}},
		"/api/v2/torrents/info?filter=downloading": []any{J{"hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "Heat.1995", "state": "downloading"}},
		"/api/v2/app/preferences":                  J{"save_path": "/downloads", "web_ui_password": "x", "web_ui_api_key": "k", "web_ui_username": "admin"},
	}
	return mediaStubServer(t, "qbittorrent", true, false, auth, pre, ans)
}

func TestQBittorrent(t *testing.T) {
	ctx := context.Background()
	d, st := qbitStub(t, "2.11.2")
	drv, err := Open(d, Credential{Username: "admin", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := drv.Facts(ctx)
	if err != nil || f.OSVersion != "v5.0.2" || f.Model != "qBittorrent (Web API 2.11.2)" || f.Vendor != "qBittorrent" {
		t.Fatalf("facts: %v %+v", err, f)
	}
	out, err := drv.Show(ctx, "show torrents filter=downloading")
	if err != nil || !strings.Contains(out, "Heat.1995") || strings.Contains(out, "Blue") {
		t.Errorf("torrents: %v %s", err, out)
	}
	if out, err = drv.Show(ctx, "show torrents name=blue bloods"); err != nil || !strings.Contains(out, "stalledUP") || strings.Contains(out, "magnet") {
		t.Errorf("by name: %v %s", err, out)
	}
	if out, err = drv.Show(ctx, "show preferences"); err != nil || strings.Contains(out, `"k"`) || !strings.Contains(out, "/downloads") {
		t.Errorf("preferences: %v %s", err, out)
	}
	rc := drv.(RawChanger)
	res, err := rc.RawChange(ctx, Raw{Method: "CALL", Path: "stop", Body: `{"torrent": "Blue.Bloods"}`}, false)
	r, body := st.last()
	if err != nil || !res.Applied || r != "POST /api/v2/torrents/stop" || body != "hashes=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("stop: %v %+v %s %s", err, res, r, body)
	}
	res, err = rc.RawChange(ctx, Raw{Method: "CALL", Path: "setLocation", Body: `{"hashes": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "location": "/data/tv"}`}, true)
	if err != nil || res.Applied || !strings.Contains(res.Note, "/data/tv") {
		t.Errorf("setLocation dry: %v %+v", err, res)
	}
	if _, err := rc.RawChange(ctx, Raw{Method: "CALL", Path: "delete", Body: `{"hashes": "all", "deleteFiles": true}`}, false); err == nil {
		t.Error("delete with the guards on")
	}
	// device_api_get: reads only; qBittorrent 4 paused with a GET
	a := drv.(APIer)
	if v, _, err := a.APIGet(ctx, "/api/v2/torrents/info?category=tv"); err != nil || v == nil {
		t.Errorf("api get: %v", err)
	}
	n := st.count()
	for _, bad := range []string{"/api/v2/torrents/pause?hashes=all", "/api/v2/torrents/delete", "/api/v2/auth/login", "/api/v2/app/shutdown", "/api/v2/torrents/info?SID=x"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was sent", bad)
		}
	}
	if st.count() != n {
		t.Error("a refused path reached the server")
	}
	drv.Close(ctx)
	if st.logins != 1 || st.logouts != 1 {
		t.Errorf("one login and one logout: %d %d", st.logins, st.logouts)
	}
	// a wrong password: refused, not echoed
	_, err = open(t, d, Credential{Username: "admin", Password: "nopenope"}).Facts(ctx)
	if err == nil || !strings.Contains(err.Error(), "login was refused") || strings.Contains(err.Error(), "nopenope") {
		t.Errorf("wrong password: %v", err)
	}
}

func TestQBittorrentLegacyAndRelogin(t *testing.T) {
	ctx := context.Background()
	d, st := qbitStub(t, "2.9.3")
	drv := open(t, d, Credential{Username: "admin", Password: "s3cret"})
	if _, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "start", Body: `{"hashes": "all"}`}, false); err != nil {
		t.Fatal(err)
	}
	if r, _ := st.last(); r != "POST /api/v2/torrents/resume" {
		t.Errorf("before qBittorrent 5: %s", r)
	}
	// the session expires: the next request logs in again
	bareDriver(drv).(*media).api.hc.Jar.SetCookies(&url.URL{Scheme: "https", Host: net.JoinHostPort(d.Address, strconv.Itoa(d.Port)), Path: "/"}, []*http.Cookie{{Name: "SID", Value: "stale", Path: "/"}})
	st.mu.Lock()
	st.logins = 0
	st.mu.Unlock()
	if _, err := drv.Facts(ctx); err != nil || st.logins != 1 {
		t.Errorf("relogin: %v %d", err, st.logins)
	}
	// auth=none: no login at all (a whitelisted address)
	d2, st2 := mediaStubServer(t, "qbittorrent", true, false, func(*http.Request) bool { return true }, nil, map[string]any{"/api/v2/app/version": "v4.6.7"})
	d2.Options = map[string]string{"auth": "none"}
	if f, err := open(t, d2, Credential{Token: "unused"}).Facts(ctx); err != nil || f.OSVersion != "v4.6.7" {
		t.Errorf("auth=none: %v %+v", err, f)
	}
	for _, r := range st2.reqs {
		if strings.Contains(r, "auth/login") {
			t.Error("a login with auth=none")
		}
	}
}

// Field names: Tautulli's API v2 envelope {"response": {"result", "message", "data"}} and get_tautulli_info's fields, as in
// Tautulli's API reference; checked against this stub only.
func TestTautulli(t *testing.T) {
	ctx := context.Background()
	ok := func(d any) any { return J{"response": J{"result": "success", "message": nil, "data": d}} }
	auth := func(r *http.Request) bool { return r.URL.Query().Get("apikey") == "SECRETKEY" }
	d, st := mediaStubServer(t, "tautulli", true, true, auth, nil, map[string]any{
		"/api/v2?cmd=get_tautulli_info":                           ok(J{"tautulli_version": "v2.15.0", "tautulli_platform_device_name": "gofer"}),
		"/api/v2?cmd=get_activity":                                ok(J{"stream_count": "1", "sessions": []any{J{"session_key": "7", "full_title": "Heat"}}}),
		"/api/v2?cmd=get_history&length=50":                       ok(J{"recordsTotal": 1, "data": []any{J{"full_title": "Blue Bloods - Pilot", "user": "joe", "reference_id": 1}}}),
		"/api/v2?cmd=get_settings":                                ok(J{"General": J{"api_key": "SECRETKEY", "pms_token": "PLEXTOKEN", "http_port": 8181}}),
		"/api/v2?cmd=terminate_session&message=bye&session_key=7": ok(nil),
		"/api/v2?cmd=delete_history":                              J{"response": J{"result": "error", "message": "no row_ids"}},
	})
	drv := open(t, d, Credential{Token: "SECRETKEY"})
	if f, err := drv.Facts(ctx); err != nil || f != (Facts{Hostname: "gofer", Vendor: "Tautulli", Model: "Tautulli", OSVersion: "v2.15.0"}) {
		t.Fatalf("facts: %v %+v", err, f)
	}
	if out, err := drv.Show(ctx, "show history"); err != nil || !strings.Contains(out, "Pilot") || strings.Contains(out, "reference_id") {
		t.Errorf("history: %v %s", err, out)
	}
	a := drv.(APIer)
	v, _, err := a.APIGet(ctx, "/api/v2?cmd=get_settings")
	if j, _ := json.Marshal(v); err != nil || strings.Contains(string(j), "SECRETKEY") || strings.Contains(string(j), "PLEXTOKEN") || !strings.Contains(string(j), "8181") {
		t.Errorf("settings: %v %s", err, j)
	}
	n := st.count()
	for _, bad := range []string{"/api/v2?cmd=get_apikey", "/api/v2?cmd=delete_history", "/api/v2?cmd=restart", "/api/v2?cmd=get_activity&apikey=x", "/api/v2?cmd=sql&query=x", "/api/v1"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was sent", bad)
		}
	}
	if st.count() != n {
		t.Error("a refused path reached the server")
	}
	rc := drv.(RawChanger)
	res, err := rc.RawChange(ctx, Raw{Method: "CALL", Path: "terminate_session", Body: `{"session_key": 7, "message": "bye"}`}, false)
	if err != nil || !res.Applied || strings.Contains(res.Answer+res.Before, "SECRETKEY") {
		t.Errorf("terminate: %v %+v", err, res)
	}
	// Tautulli's own error, without the key
	_, err = rc.RawChange(ctx, Raw{Method: "CALL", Path: "delete_history"}, false)
	if err == nil {
		t.Error("delete_history with the guards on")
	}
	SetGuards(false)
	_, err = rc.RawChange(ctx, Raw{Method: "CALL", Path: "delete_history"}, false)
	SetGuards(true)
	if err == nil || !strings.Contains(err.Error(), "no row_ids") {
		t.Errorf("an error result: %v", err)
	}
	for _, bad := range []Raw{{Method: "CALL", Path: "get_history"}, {Method: "POST", Path: "/api/v2"}, {Method: "CALL", Path: "Bad Cmd"}} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	// a wrong key: the error never holds the key, even though it travels in the URL
	_, err = open(t, d, Credential{Token: "WRONGKEY99"}).Facts(ctx)
	if err == nil || strings.Contains(err.Error(), "WRONGKEY99") || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong key: %v", err)
	}
	// an unreachable Tautulli: the transport error names the URL, and the key is taken out of it
	d.Port = 1
	_, err = open(t, d, Credential{Token: "SECRETKEY"}).Facts(ctx)
	if err == nil || strings.Contains(err.Error(), "SECRETKEY") {
		t.Errorf("unreachable: %v", err)
	}
}

// Field names: Seerr's /api/v1/status (version), /settings/main (applicationTitle, apiKey) and /request as in its OpenAPI;
// checked against this stub only.
func TestSeerr(t *testing.T) {
	ctx := context.Background()
	d, st := mediaStubServer(t, "seerr", true, false, headerAuth("X-Api-Key"), nil, map[string]any{
		"/api/v1/status":        J{"version": "2.7.3", "commitTag": "abc", "updateAvailable": false},
		"/api/v1/settings/main": J{"applicationTitle": "Requests", "apiKey": "SECRETKEY"},
		"/api/v1/request?take=50&skip=0&sort=added&filter=pending": J{"pageInfo": J{"results": 1}, "results": []any{J{"id": 3, "status": 1, "type": "tv", "seasons": []any{}}}},
		"/api/v1/request/3": J{"id": 3, "status": 1},
	})
	drv := open(t, d, Credential{Token: "SECRETKEY"})
	if f, err := drv.Facts(ctx); err != nil || f != (Facts{Hostname: "Requests", Vendor: "Seerr", Model: "Seerr", OSVersion: "2.7.3"}) {
		t.Fatalf("facts: %v %+v", err, f)
	}
	if out, err := drv.Show(ctx, "show requests filter=pending"); err != nil || !strings.Contains(out, `"count": 1`) || strings.Contains(out, "seasons") {
		t.Errorf("requests: %v %s", err, out)
	}
	if out, err := drv.Show(ctx, "show settings"); err != nil || strings.Contains(out, "SECRETKEY") {
		t.Errorf("settings: %v %s", err, out)
	}
	res, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "approve", Body: `{"id": 3}`}, false)
	if r, _ := st.last(); err != nil || !res.Applied || r != "POST /api/v1/request/3/approve" || !strings.Contains(res.Before, `"status":1`) {
		t.Errorf("approve: %v %+v %s", err, res, r)
	}
	if _, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "approve", Body: `{"id": "3/../x"}`}, false); err == nil {
		t.Error("an id with a path in it")
	}
	if _, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "delete-request", Body: `{"id": 3}`}, false); err == nil {
		t.Error("delete-request with the guards on")
	}
}

// Field names: Plex's MediaContainer (friendlyName, version) as Plex answers with Accept: application/json; checked against
// this stub only.
func TestPlex(t *testing.T) {
	ctx := context.Background()
	d, st := mediaStubServer(t, "plex", true, false, headerAuth("X-Plex-Token"), nil, map[string]any{
		"/":                           J{"MediaContainer": J{"friendlyName": "gofer", "version": "1.41.2.9200", "platform": "Linux"}},
		"/library/sections":           J{"MediaContainer": J{"size": 2, "Directory": []any{J{"key": "1", "title": "Movies", "type": "movie", "Location": []any{J{"path": "/media/movies"}}, "uuid": "x"}, J{"key": "2", "title": "TV Shows", "type": "show"}}}},
		"/myplex/account":             J{"MyPlex": J{"authToken": "PLEXTOKEN", "username": "joe"}},
		"/library/sections/2/refresh": "",
	})
	drv := open(t, d, Credential{Token: "SECRETKEY"})
	if f, err := drv.Facts(ctx); err != nil || f != (Facts{Hostname: "gofer", Vendor: "Plex", Model: "Plex Media Server", OSVersion: "1.41.2.9200"}) {
		t.Fatalf("facts: %v %+v", err, f)
	}
	if out, err := drv.Show(ctx, "show libraries"); err != nil || !strings.Contains(out, `"plex_key": "1"`) || !strings.Contains(out, "/media/movies") || strings.Contains(out, "uuid") || !strings.Contains(out, `"count": 2`) {
		t.Errorf("libraries: %v %s", err, out)
	}
	a := drv.(APIer)
	if v, _, err := a.APIGet(ctx, "/myplex/account"); err != nil || strings.Contains(func() string { j, _ := json.Marshal(v); return string(j) }(), "PLEXTOKEN") {
		t.Errorf("account: %v %v", err, v)
	}
	n := st.count()
	for _, bad := range []string{"/library/sections/1/refresh", "/status/sessions/terminate?sessionId=1", "/:/scrobble?key=1", "/security/token", "/video/:/transcode/universal/start", "/library/sections?X-Plex-Token=x", "/playQueues"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was sent", bad)
		}
	}
	if st.count() != n {
		t.Error("a refused path reached the server")
	}
	res, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "refresh", Body: `{"id": "2", "path": "/media/tv/Blue Bloods"}`}, false)
	if r, _ := st.last(); err != nil || !res.Applied || r != "GET /library/sections/2/refresh?path=%2Fmedia%2Ftv%2FBlue%20Bloods" {
		t.Errorf("refresh: %v %+v %s", err, res, r)
	}
}

// Field names: Jellyfin's /System/Info (ServerName, Version) and /ScheduledTasks as in its OpenAPI; the MediaBrowser
// Authorization header as Jellyfin 10.9 and later read it; checked against this stub only.
func TestJellyfin(t *testing.T) {
	ctx := context.Background()
	auth := func(r *http.Request) bool {
		return strings.Contains(r.Header.Get("Authorization"), `Token="SECRETKEY"`)
	}
	d, st := mediaStubServer(t, "jellyfin", true, false, auth, nil, map[string]any{
		"/System/Info":    J{"ServerName": "gofer", "Version": "10.10.3", "OperatingSystemDisplayName": "Linux", "Id": "abc"},
		"/ScheduledTasks": []any{J{"Id": "6330ee8fb4a957f33981f89aa78b030f", "Name": "Scan Media Library", "State": "Idle", "Triggers": []any{}}},
		"/ScheduledTasks/6330ee8fb4a957f33981f89aa78b030f": J{"Id": "6330ee8fb4a957f33981f89aa78b030f", "State": "Idle"},
	})
	drv := open(t, d, Credential{Token: "SECRETKEY"})
	if f, err := drv.Facts(ctx); err != nil || f != (Facts{Hostname: "gofer", Vendor: "Jellyfin", Model: "Jellyfin Server", OSVersion: "10.10.3"}) {
		t.Fatalf("facts: %v %+v", err, f)
	}
	if out, err := drv.Show(ctx, "show tasks name=scan"); err != nil || !strings.Contains(out, "Scan Media Library") || strings.Contains(out, "Triggers") {
		t.Errorf("tasks: %v %s", err, out)
	}
	res, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "run-task", Body: `{"id": "6330ee8fb4a957f33981f89aa78b030f"}`}, false)
	if r, _ := st.last(); err != nil || !res.Applied || r != "POST /ScheduledTasks/Running/6330ee8fb4a957f33981f89aa78b030f" || !strings.Contains(res.Before, "Idle") {
		t.Errorf("run-task: %v %+v %s", err, res, r)
	}
	a := drv.(APIer)
	for _, bad := range []string{"/Videos/1/stream", "/Auth/Keys", "/Audio/1/universal", "/Items/1/master.m3u8"} {
		if _, _, err := a.APIGet(ctx, bad); err == nil {
			t.Errorf("%s was sent", bad)
		}
	}
	if _, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "CALL", Path: "restart"}, false); err == nil {
		t.Error("restart with the guards on")
	}
}

func TestParseKV(t *testing.T) {
	m, err := parseKV(" name=Blue Bloods lines=5 ")
	if err != nil || m["name"] != "Blue Bloods" || m["lines"] != "5" {
		t.Errorf("%v %v", err, m)
	}
	for _, bad := range []string{"x", "junk name=a", "a=1 a=2", "a="} {
		if _, err := parseKV(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !qbitLegacy("2.9.3") || qbitLegacy("2.11.2") || qbitLegacy("3.0") || qbitLegacy("") {
		t.Error("qbitLegacy")
	}
}

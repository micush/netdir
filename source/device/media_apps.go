package device

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The tables of the media applications (the engine is media.go).  Field and endpoint names are those of each application's own
// API documentation (Servarr's OpenAPI, Bazarr's, qBittorrent's WebUI API wiki, Tautulli's API reference, Seerr's OpenAPI,
// Plex's and Jellyfin's); the tests check them against stubs only.

func init() {
	for _, s := range []*mediaSpec{sonarrSpec(), radarrSpec(), lidarrSpec(), prowlarrSpec(), bazarrSpec(), qbitSpec(), tautulliSpec(), seerrSpec(), plexSpec(), jellyfinSpec()} {
		registerMedia(s)
	}
}

// ---- the *arr family (Servarr) ----

func arrFacts(ctx context.Context, m *media) (Facts, error) {
	s, err := m.getMap(ctx, "/system/status")
	if err != nil {
		return Facts{}, err
	}
	f := Facts{Hostname: firstOf(str(s["instanceName"]), str(s["appName"]), m.d.Name), Vendor: "Servarr", Model: firstOf(str(s["appName"]), m.spec.model),
		OSVersion: str(s["version"])}
	if t, err := time.Parse(time.RFC3339Nano, str(s["startTime"])); err == nil {
		if up := nowUnix() - t.Unix(); up > 0 {
			f.UptimeS = up
		}
	}
	return f, nil
}

// arrAlerts are the warnings and errors of System ▸ Status ▸ Health.
func arrAlerts(ctx context.Context, m *media) ([]string, error) {
	v, err := m.get(ctx, "/health")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows(v) {
		t := strings.ToLower(str(r["type"]))
		if t == "warning" || t == "error" {
			out = append(out, fmt.Sprintf("%s: %s: %s", t, str(r["source"]), str(r["message"])))
		}
	}
	return out, nil
}

var arrCmdRE = regexp.MustCompile(`^[A-Z][A-Za-z]{2,63}$`)

// arrCommand: CALL RefreshSeries {"series": "Blue Bloods"} is POST /command {"name": "RefreshSeries", "seriesId": 123}.
func arrCommand(_ *media, action string, body map[string]any) (mcall, error) {
	if !arrCmdRE.MatchString(action) {
		return mcall{}, fmt.Errorf("path %q: an action, or the name of a command (RefreshSeries, RescanSeries, DownloadedEpisodesScan, RefreshMovie, ...)", action)
	}
	body["name"] = action
	return mcall{method: "POST", path: "/command", enc: "json", before: "/command"}, nil
}

func arrShows(extra map[string]mshow) map[string]mshow {
	s := map[string]mshow{
		"status":          {path: "/system/status", help: "version, start time, OS, paths"},
		"health":          {path: "/health", help: "the warnings of System ▸ Status"},
		"rootfolders":     {path: "/rootfolder", cols: []string{"id", "path", "accessible", "freeSpace", "unmappedFolders"}, help: "root folders and whether they are reachable"},
		"diskspace":       {path: "/diskspace", help: "free space of each disk it sees"},
		"queue":           {path: "/queue?page=1&pageSize={n}", cols: []string{"id", "title", "status", "trackedDownloadStatus", "trackedDownloadState", "statusMessages", "errorMessage", "outputPath", "downloadClient", "sizeleft", "timeleft"}, help: "the download queue and its import problems"},
		"history":         {path: "/history?page=1&pageSize={n}&sortKey=date&sortDirection=descending", cols: []string{"id", "date", "eventType", "sourceTitle", "data"}, help: "grabs, imports, failures, newest first"},
		"logs":            {path: "/log?page=1&pageSize={n}&sortKey=time&sortDirection=descending", cols: []string{"time", "level", "logger", "message", "exception"}, help: "the log, newest first"},
		"tasks":           {path: "/system/task", cols: []string{"name", "taskName", "interval", "lastExecution", "lastDuration", "nextExecution"}, help: "scheduled tasks"},
		"commands":        {path: "/command", cols: []string{"id", "name", "commandName", "status", "queued", "started", "ended", "message", "result"}, help: "commands queued, running and done"},
		"command":         {path: "/command/{id}", help: "one command, by the id CALL answered"},
		"indexers":        {path: "/indexer", name: "name", cols: []string{"id", "name", "protocol", "implementation", "enableRss", "enableAutomaticSearch", "enable", "priority"}, help: "indexers"},
		"downloadclients": {path: "/downloadclient", name: "name", cols: []string{"id", "name", "implementation", "protocol", "enable", "priority"}, help: "download clients"},
		"tags":            {path: "/tag", help: "tags"},
		"backups":         {path: "/system/backup", help: "backups"},
		"notifications":   {path: "/notification", name: "name", cols: []string{"id", "name", "implementation", "onGrab", "onDownload"}, help: "connections"},
	}
	for k, v := range extra {
		s[k] = v
	}
	return s
}

func sonarrSpec() *mediaSpec {
	return &mediaSpec{platform: "sonarr", vendor: "Servarr", model: "Sonarr", port: 8989, root: "/api/v3", auth: "header", hdr: "X-Api-Key",
		facts: arrFacts, alerts: arrAlerts, anyCall: arrCommand,
		res: map[string]mres{"series": {list: "/series", title: "title", id: "id", param: "seriesId", field: "seriesId"}},
		shows: arrShows(map[string]mshow{
			"series":       {path: "/series", name: "title", cols: []string{"id", "title", "year", "path", "status", "monitored", "rootFolderPath", "statistics"}, help: "every series; name= picks by title"},
			"episodes":     {path: "/episode", args: "series", cols: []string{"id", "seasonNumber", "episodeNumber", "title", "airDate", "hasFile", "episodeFileId", "monitored"}, help: "series=TITLE|ID: its episodes"},
			"episodefiles": {path: "/episodefile", args: "series", cols: []string{"id", "seasonNumber", "path", "relativePath", "size", "dateAdded", "quality"}, help: "series=TITLE|ID: its files on disk"},
			"wanted":       {path: "/wanted/missing?page=1&pageSize={n}&sortKey=airDateUtc&sortDirection=descending", cols: []string{"id", "seriesId", "seasonNumber", "episodeNumber", "title", "airDate", "monitored"}, help: "missing episodes"},
			"calendar":     {path: "/calendar", help: "episodes airing soon"},
			"manualimport": {path: "/manualimport", args: "folder", cols: []string{"path", "relativePath", "series", "seasonNumber", "episodes", "quality", "rejections"}, help: "folder=/path: what a manual import would take and why it refuses"},
		}),
		calls:   map[string]mcall{},
		catalog: []string{"/api/v3/system/status", "/api/v3/series", "/api/v3/episodefile?seriesId=1", "/api/v3/queue", "/api/v3/health", "/api/v3/rootfolder"},
	}
}

func radarrSpec() *mediaSpec {
	return &mediaSpec{platform: "radarr", vendor: "Servarr", model: "Radarr", port: 7878, root: "/api/v3", auth: "header", hdr: "X-Api-Key",
		facts: arrFacts, alerts: arrAlerts, anyCall: arrCommand,
		res: map[string]mres{"movie": {list: "/movie", title: "title", id: "id", param: "movieId", field: "movieIds"}},
		shows: arrShows(map[string]mshow{
			"movies":       {path: "/movie", name: "title", cols: []string{"id", "title", "year", "path", "hasFile", "monitored", "status", "sizeOnDisk", "rootFolderPath"}, help: "every movie; name= picks by title"},
			"moviefiles":   {path: "/moviefile", args: "movie", cols: []string{"id", "path", "relativePath", "size", "dateAdded", "quality"}, help: "movie=TITLE|ID: its files on disk"},
			"wanted":       {path: "/wanted/missing?page=1&pageSize={n}", cols: []string{"id", "title", "year", "monitored", "status"}, help: "missing movies"},
			"calendar":     {path: "/calendar", help: "releases soon"},
			"manualimport": {path: "/manualimport", args: "folder", cols: []string{"path", "relativePath", "movie", "quality", "rejections"}, help: "folder=/path: what a manual import would take"},
		}),
		calls:   map[string]mcall{},
		catalog: []string{"/api/v3/system/status", "/api/v3/movie", "/api/v3/moviefile?movieId=1", "/api/v3/queue", "/api/v3/health"},
	}
}

func lidarrSpec() *mediaSpec {
	return &mediaSpec{platform: "lidarr", vendor: "Servarr", model: "Lidarr", port: 8686, root: "/api/v1", auth: "header", hdr: "X-Api-Key",
		facts: arrFacts, alerts: arrAlerts, anyCall: arrCommand,
		res: map[string]mres{"artist": {list: "/artist", title: "artistName", id: "id", param: "artistId", field: "artistId"}},
		shows: arrShows(map[string]mshow{
			"artists":    {path: "/artist", name: "artistName", cols: []string{"id", "artistName", "path", "status", "monitored", "statistics"}, help: "every artist; name= picks by name"},
			"albums":     {path: "/album", args: "artist", name: "title", cols: []string{"id", "title", "releaseDate", "monitored", "statistics"}, help: "artist=NAME|ID: the albums"},
			"trackfiles": {path: "/trackfile", args: "artist", cols: []string{"id", "path", "size", "dateAdded", "quality"}, help: "artist=NAME|ID: its files on disk"},
			"wanted":     {path: "/wanted/missing?page=1&pageSize={n}", cols: []string{"id", "title", "artistId", "releaseDate", "monitored"}, help: "missing albums"},
		}),
		calls:   map[string]mcall{},
		catalog: []string{"/api/v1/system/status", "/api/v1/artist", "/api/v1/album?artistId=1", "/api/v1/queue", "/api/v1/health"},
	}
}

func prowlarrSpec() *mediaSpec {
	return &mediaSpec{platform: "prowlarr", vendor: "Servarr", model: "Prowlarr", port: 9696, root: "/api/v1", auth: "header", hdr: "X-Api-Key",
		facts: arrFacts, alerts: arrAlerts, anyCall: arrCommand,
		shows: arrShows(map[string]mshow{
			"indexerstats": {path: "/indexerstats", help: "queries, grabs and failures per indexer"},
			"applications": {path: "/applications", name: "name", cols: []string{"id", "name", "implementation", "syncLevel", "enable"}, help: "the *arr applications it feeds"},
			"history":      {path: "/history?page=1&pageSize={n}&sortKey=date&sortDirection=descending", cols: []string{"id", "date", "eventType", "indexerId", "successful", "data"}, help: "searches and grabs"},
		}),
		calls: map[string]mcall{
			"test-indexers": {method: "POST", path: "/indexer/testall", help: "test every indexer"},
		},
		catalog: []string{"/api/v1/system/status", "/api/v1/indexer", "/api/v1/indexerstats", "/api/v1/applications", "/api/v1/health"},
	}
}

// ---- Bazarr ----

func bazarrData(v any) any {
	if o, ok := v.(map[string]any); ok {
		if d, ok := o["data"]; ok {
			return d
		}
	}
	return v
}

func bazarrSpec() *mediaSpec {
	return &mediaSpec{platform: "bazarr", vendor: "Bazarr", model: "Bazarr", port: 6767, root: "/api", auth: "header", hdr: "X-API-KEY",
		facts: func(ctx context.Context, m *media) (Facts, error) {
			v, err := m.get(ctx, "/system/status")
			if err != nil {
				return Facts{}, err
			}
			s, _ := bazarrData(v).(map[string]any)
			if s == nil || str(s["bazarr_version"]) == "" {
				return Facts{}, errors.New("GET /api/system/status: no bazarr_version in the answer")
			}
			f := Facts{Hostname: m.d.Name, Vendor: "Bazarr", Model: "Bazarr", OSVersion: str(s["bazarr_version"])}
			if st := num(s["start_time"]); st > 0 && nowUnix() > st {
				f.UptimeS = nowUnix() - st
			}
			return f, nil
		},
		alerts: func(ctx context.Context, m *media) ([]string, error) {
			v, err := m.get(ctx, "/system/health")
			if err != nil {
				return nil, err
			}
			var out []string
			for _, r := range rows(bazarrData(v)) {
				out = append(out, fmt.Sprintf("%s: %s", str(r["object"]), str(r["issue"])))
			}
			return out, nil
		},
		res: map[string]mres{
			"series": {list: "/series?start=0&length=-1", title: "title", id: "sonarrSeriesId", param: "seriesid[]", field: "seriesid"},
			"movie":  {list: "/movies?start=0&length=-1", title: "title", id: "radarrId", param: "radarrid[]", field: "radarrid"},
		},
		shows: map[string]mshow{
			"status":           {path: "/system/status", help: "version, start time, OS"},
			"health":           {path: "/system/health", help: "the problems of System ▸ Status"},
			"badges":           {path: "/badges", help: "counts: missing subtitles, providers throttled, health issues"},
			"tasks":            {path: "/system/tasks", cols: []string{"name", "job_id", "interval", "next_run_in", "job_running"}, help: "scheduled tasks (job_id is what CALL run-task takes)"},
			"logs":             {path: "/system/logs", help: "the log"},
			"providers":        {path: "/providers", help: "providers and their throttling"},
			"languages":        {path: "/system/languages", help: "languages"},
			"announcements":    {path: "/system/announcements", help: "announcements"},
			"series":           {path: "/series?start=0&length=-1", name: "title", cols: []string{"sonarrSeriesId", "title", "path", "profileId", "episodeFileCount", "episodeMissingCount"}, help: "series; name= picks by title"},
			"movies":           {path: "/movies?start=0&length=-1", name: "title", cols: []string{"radarrId", "title", "path", "profileId", "missing_subtitles", "subtitles"}, help: "movies; name= picks by title"},
			"episodes":         {path: "/episodes", args: "series", cols: []string{"sonarrEpisodeId", "season", "episode", "title", "missing_subtitles", "subtitles", "path"}, help: "series=TITLE|ID: its episodes and subtitles"},
			"wanted-episodes":  {path: "/episodes/wanted?start=0&length={n}", cols: []string{"seriesTitle", "episode_number", "episodeTitle", "missing_subtitles", "sonarrSeriesId", "sonarrEpisodeId"}, help: "episodes missing subtitles"},
			"wanted-movies":    {path: "/movies/wanted?start=0&length={n}", cols: []string{"title", "missing_subtitles", "radarrId"}, help: "movies missing subtitles"},
			"history-episodes": {path: "/episodes/history?start=0&length={n}", help: "subtitle history of episodes"},
			"history-movies":   {path: "/movies/history?start=0&length={n}", help: "subtitle history of movies"},
		},
		calls: map[string]mcall{
			"run-task":        {method: "POST", path: "/system/tasks", enc: "form", help: "taskid: run a scheduled task now (show tasks)"},
			"series-action":   {method: "PATCH", path: "/series", enc: "form", before: "/series?start=0&length=-1&seriesid[]={seriesid}", help: "series (title or id) and action: scan-disk, search-missing or search-wanted"},
			"movie-action":    {method: "PATCH", path: "/movies", enc: "form", before: "/movies?start=0&length=-1&radarrid[]={radarrid}", help: "movie (title or id) and action: scan-disk, search-missing or search-wanted"},
			"reset-providers": {method: "POST", path: "/providers", enc: "form", help: `action: "reset" clears the throttled providers`},
		},
		catalog: []string{"/api/system/status", "/api/badges", "/api/series?start=0&length=-1", "/api/episodes/wanted?start=0&length=25", "/api/providers"},
	}
}

// ---- qBittorrent ----

func qbitSpec() *mediaSpec {
	torrent := []string{"hash", "name", "state", "progress", "size", "dlspeed", "upspeed", "eta", "ratio", "category", "tags", "save_path", "content_path", "num_seeds", "num_leechs", "added_on"}
	hashes := func(path string, help string) mcall {
		return mcall{method: "POST", path: path, enc: "form", before: "/torrents/info?hashes={hashes}", help: help}
	}
	return &mediaSpec{platform: "qbittorrent", vendor: "qBittorrent", model: "qBittorrent", port: 8080, root: "/api/v2", auth: "login",
		facts: func(ctx context.Context, m *media) (Facts, error) {
			ver, err := m.get(ctx, "/app/version")
			if err != nil {
				return Facts{}, err
			}
			api, _ := m.get(ctx, "/app/webapiVersion")
			m.mu.Lock()
			m.webAPI = str(api)
			m.mu.Unlock()
			model := "qBittorrent"
			if str(api) != "" {
				model += " (Web API " + str(api) + ")"
			}
			return Facts{Hostname: m.d.Name, Vendor: "qBittorrent", Model: model, OSVersion: str(ver)}, nil
		},
		res: map[string]mres{"torrent": {list: "/torrents/info", title: "name", id: "hash", field: "hashes"}},
		shows: map[string]mshow{
			"version":     {path: "/app/buildInfo", help: "the build: Qt, libtorrent, Boost, OpenSSL"},
			"transfer":    {path: "/transfer/info", help: "speeds, totals, connection status"},
			"torrents":    {path: "/torrents/info", args: "filter category tag sort", name: "name", cols: torrent, help: "torrents; filter=downloading|seeding|completed|stopped|active|errored|stalled..., category=, tag=, name="},
			"torrent":     {path: "/torrents/properties?hash={id}", help: "id=HASH: one torrent's properties"},
			"files":       {path: "/torrents/files?hash={id}", cols: []string{"index", "name", "size", "progress", "priority"}, help: "id=HASH: its files"},
			"trackers":    {path: "/torrents/trackers?hash={id}", cols: []string{"url", "status", "msg", "num_peers", "num_seeds"}, help: "id=HASH: its trackers"},
			"categories":  {path: "/torrents/categories", help: "categories and their save paths"},
			"tags":        {path: "/torrents/tags", help: "tags"},
			"preferences": {path: "/app/preferences", help: "every setting (passwords hidden)"},
			"log":         {path: "/log/main?last_known_id=-1", help: "the log"},
			"maindata":    {path: "/sync/maindata", help: "everything the Web UI shows, at once"},
		},
		calls: map[string]mcall{
			"stop":              hashes("/torrents/stop", `torrent (a name) or hashes ("h1|h2" or "all"): stop (pause before qBittorrent 5)`),
			"start":             hashes("/torrents/start", "torrent or hashes: start (resume before qBittorrent 5)"),
			"recheck":           hashes("/torrents/recheck", "torrent or hashes: check the data again"),
			"reannounce":        hashes("/torrents/reannounce", "torrent or hashes: announce to the trackers now"),
			"setLocation":       hashes("/torrents/setLocation", "torrent or hashes, location: move the data"),
			"setCategory":       hashes("/torrents/setCategory", "torrent or hashes, category"),
			"addTags":           hashes("/torrents/addTags", "torrent or hashes, tags (comma separated)"),
			"removeTags":        hashes("/torrents/removeTags", "torrent or hashes, tags"),
			"delete":            {method: "POST", path: "/torrents/delete", enc: "form", before: "/torrents/info?hashes={hashes}", guard: true, help: "torrent or hashes, deleteFiles (true deletes the data too)"},
			"rename":            {method: "POST", path: "/torrents/rename", enc: "form", before: "/torrents/properties?hash={hash}", help: "hash, name"},
			"createCategory":    {method: "POST", path: "/torrents/createCategory", enc: "form", before: "/torrents/categories", help: "category, savePath"},
			"editCategory":      {method: "POST", path: "/torrents/editCategory", enc: "form", before: "/torrents/categories", help: "category, savePath"},
			"setPreferences":    {method: "POST", path: "/app/setPreferences", enc: "form", before: "/app/preferences", help: `json: an object of settings, e.g. {"json": {"save_path": "/data"}}`},
			"toggleSpeedLimits": {method: "POST", path: "/transfer/toggleSpeedLimitsMode", before: "/transfer/speedLimitsMode", help: "switch the alternative speed limits on or off"},
		},
		readOK: func(p string) error {
			if !qbitReadRE.MatchString(strings.SplitN(p, "?", 2)[0]) {
				return errors.New("path: a read endpoint of /api/v2 (app/version, app/preferences, torrents/info, torrents/properties, transfer/info, sync/maindata, log/main, ...); qBittorrent before 5 also changes things with a GET")
			}
			return nil
		},
		catalog: []string{"/api/v2/torrents/info?filter=downloading", "/api/v2/transfer/info", "/api/v2/app/preferences", "/api/v2/torrents/categories", "/api/v2/sync/maindata"},
	}
}

var qbitReadRE = regexp.MustCompile(`^/api/v2/(app/(version|webapiVersion|buildInfo|preferences|defaultSavePath|networkInterfaceList|networkInterfaceAddressList)|log/(main|peers)|sync/(maindata|torrentPeers)|transfer/(info|speedLimitsMode|downloadLimit|uploadLimit)|torrents/(info|properties|trackers|webseeds|files|pieceStates|pieceHashes|categories|tags|count)|rss/items|search/(status|results|plugins))$`)

// qbitLegacy: before Web API 2.11 (qBittorrent 5) stop and start were called pause and resume.
func qbitLegacy(api string) bool {
	maj, rest, _ := strings.Cut(api, ".")
	min, _, _ := strings.Cut(rest, ".")
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(min)
	return err1 == nil && err2 == nil && (a < 2 || a == 2 && b < 11)
}

// ---- Tautulli ----

func tautulliUnwrap(v any) (any, error) {
	o, ok := v.(map[string]any)
	if !ok {
		return v, nil
	}
	r, ok := o["response"].(map[string]any)
	if !ok {
		return v, nil
	}
	if res := str(r["result"]); res != "" && res != "success" {
		return nil, fmt.Errorf("Tautulli answered %s: %s", res, firstOf(str(r["message"]), "no message"))
	}
	return r["data"], nil
}

var tautCmdRE = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)

func tautulliSpec() *mediaSpec {
	c := func(cmd string) string { return "?cmd=" + cmd }
	return &mediaSpec{platform: "tautulli", vendor: "Tautulli", model: "Tautulli", port: 8181, root: "/api/v2", auth: "query", unwrap: tautulliUnwrap,
		facts: func(ctx context.Context, m *media) (Facts, error) {
			s, err := m.getMap(ctx, c("get_tautulli_info"))
			if err != nil {
				return Facts{}, err
			}
			return Facts{Hostname: firstOf(str(s["tautulli_platform_device_name"]), m.d.Name), Vendor: "Tautulli", Model: "Tautulli",
				OSVersion: str(s["tautulli_version"])}, nil
		},
		shows: map[string]mshow{
			"info":           {path: c("get_tautulli_info"), help: "version, platform"},
			"server":         {path: c("get_server_info"), help: "the Plex server it watches"},
			"activity":       {path: c("get_activity"), help: "what is playing now, and how (transcode, bandwidth)"},
			"history":        {path: c("get_history") + "&length={n}", args: "user section_id rating_key search", cols: []string{"date", "full_title", "user", "platform", "player", "started", "stopped", "duration", "watched_status", "transcode_decision"}, help: "plays, newest first; user=, section_id=, search="},
			"libraries":      {path: c("get_libraries"), cols: []string{"section_id", "section_name", "section_type", "count", "parent_count", "child_count"}, help: "libraries"},
			"users":          {path: c("get_users"), cols: []string{"user_id", "username", "friendly_name", "is_active", "is_admin"}, help: "users"},
			"recently-added": {path: c("get_recently_added") + "&count={n}", cols: []string{"added_at", "full_title", "title", "media_type", "library_name", "rating_key"}, help: "recently added"},
			"home-stats":     {path: c("get_home_stats"), help: "most watched, most active users"},
			"logs":           {path: c("get_logs") + "&start=0&end={n}", help: "Tautulli's own log"},
			"plex-log":       {path: c("get_plex_log") + "&window={n}", help: "the Plex server's log, as Tautulli reads it"},
			"notifiers":      {path: c("get_notifiers"), help: "notification agents"},
			"notifications":  {path: c("get_notification_log") + "&length={n}", help: "notifications sent"},
			"status":         {path: c("status"), help: "whether Tautulli is up"},
		},
		calls: map[string]mcall{
			"terminate_session":      {method: "GET", path: c("terminate_session"), enc: "query", before: c("get_activity"), help: "session_key or session_id, message: stop a stream"},
			"refresh_libraries_list": {method: "GET", path: c("refresh_libraries_list"), help: "read the libraries from Plex again"},
			"refresh_users_list":     {method: "GET", path: c("refresh_users_list"), help: "read the users from Plex again"},
			"notify":                 {method: "GET", path: c("notify"), enc: "query", help: "notifier_id, subject, body"},
			"backup_db":              {method: "GET", path: c("backup_db"), help: "back up the database"},
			"restart":                {method: "GET", path: c("restart"), guard: true, help: "restart Tautulli"},
		},
		anyCall: func(_ *media, action string, _ map[string]any) (mcall, error) {
			switch {
			case !tautCmdRE.MatchString(action):
				return mcall{}, fmt.Errorf("path %q: a Tautulli command name, e.g. terminate_session", action)
			case strings.HasPrefix(action, "get_") || action == "sql":
				return mcall{}, fmt.Errorf("%s: a read; use device_show or device_api_get", action)
			}
			g := strings.HasPrefix(action, "delete") || strings.HasPrefix(action, "undelete") || action == "update" || action == "restart" || action == "logout_user_session"
			return mcall{method: "GET", path: c(action), enc: "query", guard: g}, nil
		},
		readOK: func(p string) error {
			_, q, _ := strings.Cut(p, "?")
			cmd := ""
			for _, kv := range strings.Split(q, "&") {
				if k, v, _ := strings.Cut(kv, "="); k == "cmd" {
					cmd = v
				}
			}
			if !(strings.HasPrefix(cmd, "get_") || cmd == "status" || cmd == "arnold" || cmd == "docs") || cmd == "get_apikey" {
				return errors.New("path: /api/v2?cmd=get_... (the get_ commands only: the others change something; get_apikey is never sent)")
			}
			return nil
		},
		catalog: []string{"/api/v2?cmd=get_activity", "/api/v2?cmd=get_history&length=25", "/api/v2?cmd=get_libraries", "/api/v2?cmd=get_server_info"},
	}
}

// ---- Seerr (Overseerr, Jellyseerr) ----

func seerrSpec() *mediaSpec {
	req := func(m, p, before, help string, guard bool) mcall {
		return mcall{method: m, path: p, before: before, help: help, guard: guard}
	}
	return &mediaSpec{platform: "seerr", vendor: "Seerr", model: "Seerr", port: 5055, root: "/api/v1", auth: "header", hdr: "X-Api-Key",
		facts: func(ctx context.Context, m *media) (Facts, error) {
			s, err := m.getMap(ctx, "/status")
			if err != nil {
				return Facts{}, err
			}
			name := m.d.Name
			if mn, err := m.getMap(ctx, "/settings/main"); err == nil && str(mn["applicationTitle"]) != "" {
				name = str(mn["applicationTitle"])
			}
			return Facts{Hostname: name, Vendor: "Seerr", Model: "Seerr", OSVersion: str(s["version"])}, nil
		},
		shows: map[string]mshow{
			"status":        {path: "/status", help: "version, update available, restart required"},
			"about":         {path: "/settings/about", help: "totals, time zone, version"},
			"requests":      {path: "/request?take={n}&skip=0&sort=added", args: "filter", cols: []string{"id", "status", "type", "is4k", "createdAt", "media", "requestedBy"}, help: "requests, newest first; filter=all|approved|pending|processing|available|failed"},
			"request":       {path: "/request/{id}", help: "id=N: one request"},
			"request-count": {path: "/request/count", help: "requests by state"},
			"issues":        {path: "/issue?take={n}&skip=0&sort=added", args: "filter", cols: []string{"id", "issueType", "status", "problemSeason", "problemEpisode", "media", "createdBy", "createdAt"}, help: "issues; filter=open|resolved|all"},
			"issue":         {path: "/issue/{id}", help: "id=N: one issue and its comments"},
			"issue-count":   {path: "/issue/count", help: "issues by type and state"},
			"users":         {path: "/user?take={n}&skip=0", cols: []string{"id", "displayName", "userType", "permissions", "requestCount", "createdAt"}, help: "users"},
			"media":         {path: "/media?take={n}&skip=0", args: "filter", cols: []string{"id", "mediaType", "tmdbId", "tvdbId", "status", "status4k", "updatedAt"}, help: "media it tracks"},
			"jobs":          {path: "/settings/jobs", cols: []string{"id", "name", "type", "interval", "nextExecutionTime", "running"}, help: "scheduled jobs (id is what run-job takes)"},
			"cache":         {path: "/settings/cache", help: "caches"},
			"settings":      {path: "/settings/main", help: "main settings (the API key hidden)"},
			"sonarr":        {path: "/settings/sonarr", help: "its Sonarr servers"},
			"radarr":        {path: "/settings/radarr", help: "its Radarr servers"},
			"search":        {path: "/search?page=1", args: "query", cols: []string{"id", "mediaType", "title", "name", "releaseDate", "firstAirDate", "mediaInfo"}, help: "query=TEXT: search titles"},
			"movie":         {path: "/movie/{id}", help: "id=TMDB id"},
			"tv":            {path: "/tv/{id}", help: "id=TMDB id"},
		},
		calls: map[string]mcall{
			"approve":        req("POST", "/request/{id}/approve", "/request/{id}", "id: approve a request", false),
			"decline":        req("POST", "/request/{id}/decline", "/request/{id}", "id: decline a request", false),
			"retry":          req("POST", "/request/{id}/retry", "/request/{id}", "id: send a failed request again", false),
			"delete-request": req("DELETE", "/request/{id}", "/request/{id}", "id: delete a request", true),
			"request":        {method: "POST", path: "/request", enc: "json", help: "mediaType (movie|tv), mediaId (TMDB id), seasons ([1,2] or \"all\"), is4k"},
			"run-job":        req("POST", "/settings/jobs/{id}/run", "/settings/jobs", "id: run a job now", false),
			"cancel-job":     req("POST", "/settings/jobs/{id}/cancel", "/settings/jobs", "id: cancel a running job", false),
			"flush-cache":    req("POST", "/settings/cache/{id}/flush", "/settings/cache", "id: flush a cache", false),
			"resolve-issue":  req("POST", "/issue/{id}/resolved", "/issue/{id}", "id: mark an issue resolved", false),
			"reopen-issue":   req("POST", "/issue/{id}/open", "/issue/{id}", "id: open it again", false),
			"comment-issue":  {method: "POST", path: "/issue/{id}/comment", enc: "json", before: "/issue/{id}", help: "id, message"},
			"media-status":   req("POST", "/media/{id}/{status}", "/media?take=1&skip=0", "id, status: available, pending, processing, unknown or deleted", false),
			"delete-media":   req("DELETE", "/media/{id}", "", "id: forget a media item (not its files)", true),
		},
		catalog: []string{"/api/v1/status", "/api/v1/request?take=20&skip=0&filter=pending", "/api/v1/issue?take=20&skip=0", "/api/v1/settings/jobs", "/api/v1/media?take=20&skip=0"},
	}
}

// ---- Plex Media Server ----

func plexMC(v any) map[string]any {
	o, _ := v.(map[string]any)
	if mc, ok := o["MediaContainer"].(map[string]any); ok {
		return mc
	}
	return o
}

var plexWriteRE = regexp.MustCompile(`(?i)(/:/|/refresh|/terminate|/transcode|/playqueues|/scrobble|/unscrobble|/analyze|/emptytrash|/optimize|/clean/|/security|/butler/|/sync/|/livetv/dvrs/[^/]+/reloadguide|/updater/apply)`)

// plexKeys copies each "key" of a Plex answer into "plex_key": netdir hides every field named key (it is a secret on most
// platforms), and Plex's key is a library's id or an item's path.
func plexKeys(v any) (any, error) {
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			if k, ok := t["key"]; ok {
				if _, has := t["plex_key"]; !has {
					t["plex_key"] = k
				}
			}
			for _, y := range t {
				walk(y)
			}
		case []any:
			for _, y := range t {
				walk(y)
			}
		}
	}
	walk(v)
	return v, nil
}

func plexSpec() *mediaSpec {
	return &mediaSpec{platform: "plex", vendor: "Plex", model: "Plex Media Server", port: 32400, root: "", auth: "header", hdr: "X-Plex-Token", unwrap: plexKeys,
		facts: func(ctx context.Context, m *media) (Facts, error) {
			v, err := m.get(ctx, "/")
			if err != nil {
				return Facts{}, err
			}
			mc := plexMC(v)
			if mc == nil || str(mc["version"]) == "" {
				return Facts{}, errors.New("GET /: not the answer of a Plex Media Server")
			}
			return Facts{Hostname: firstOf(str(mc["friendlyName"]), m.d.Name), Vendor: "Plex", Model: "Plex Media Server",
				OSVersion: str(mc["version"])}, nil
		},
		shows: map[string]mshow{
			"server":         {path: "/", help: "name, version, platform, what it can do"},
			"identity":       {path: "/identity", help: "machine identifier, version"},
			"libraries":      {path: "/library/sections", cols: []string{"plex_key", "title", "type", "agent", "scanner", "refreshing", "Location", "scannedAt"}, help: "libraries (plex_key is the id)"},
			"library":        {path: "/library/sections/{id}/all", name: "title", cols: []string{"ratingKey", "title", "year", "addedAt", "viewCount", "leafCount"}, help: "id=PLEX_KEY: what a library holds; name= picks by title"},
			"item":           {path: "/library/metadata/{id}", help: "id=RATINGKEY: one item, its media and files"},
			"children":       {path: "/library/metadata/{id}/children", cols: []string{"ratingKey", "title", "index", "leafCount", "viewedLeafCount"}, help: "id=RATINGKEY: seasons or episodes"},
			"sessions":       {path: "/status/sessions", cols: []string{"title", "grandparentTitle", "type", "User", "Player", "Session", "TranscodeSession"}, help: "what is playing now"},
			"history":        {path: "/status/sessions/history/all?sort=viewedAt:desc&X-Plex-Container-Start=0&X-Plex-Container-Size={n}", cols: []string{"title", "grandparentTitle", "type", "viewedAt", "accountID", "deviceID"}, help: "plays, newest first"},
			"recently-added": {path: "/library/recentlyAdded?X-Plex-Container-Start=0&X-Plex-Container-Size={n}", cols: []string{"ratingKey", "title", "grandparentTitle", "parentTitle", "type", "addedAt", "librarySectionTitle"}, help: "recently added"},
			"activities":     {path: "/activities", help: "scans and other work in progress"},
			"butler":         {path: "/butler", help: "the butler's scheduled tasks"},
			"accounts":       {path: "/accounts", help: "accounts on this server"},
			"devices":        {path: "/devices", help: "devices that have connected"},
			"prefs":          {path: "/:/prefs", help: "settings (tokens hidden)"},
			"search":         {path: "/hubs/search?limit=10", args: "query", help: "query=TEXT: search every library"},
		},
		calls: map[string]mcall{
			"refresh":         {method: "GET", path: "/library/sections/{id}/refresh", enc: "query", before: "/library/sections", help: "id (the library's plex_key), and optionally path (one folder) or force=1: scan a library"},
			"refresh-all":     {method: "GET", path: "/library/sections/all/refresh", help: "scan every library"},
			"refresh-item":    {method: "PUT", path: "/library/metadata/{id}/refresh", before: "/library/metadata/{id}", help: "id (ratingKey): refresh one item's metadata"},
			"analyze":         {method: "PUT", path: "/library/sections/{id}/analyze", help: "id: analyze a library's media"},
			"empty-trash":     {method: "PUT", path: "/library/sections/{id}/emptyTrash", guard: true, help: "id: forget what is no longer on disk"},
			"clean-bundles":   {method: "PUT", path: "/library/clean/bundles", guard: true, help: "delete unused metadata bundles"},
			"optimize":        {method: "PUT", path: "/library/optimize", help: "optimize the database"},
			"butler-run":      {method: "POST", path: "/butler/{task}", before: "/butler", help: "task: run a butler task now (show butler)"},
			"butler-stop":     {method: "DELETE", path: "/butler", help: "stop the butler's tasks"},
			"terminate":       {method: "GET", path: "/status/sessions/terminate", enc: "query", before: "/status/sessions", help: "sessionId (Session.id), reason: stop a stream"},
			"cancel-activity": {method: "DELETE", path: "/activities/{id}", before: "/activities", help: "id (uuid): cancel a scan"},
		},
		readOK: func(p string) error {
			if plexWriteRE.MatchString(strings.SplitN(p, "?", 2)[0]) {
				return errors.New("path: refused, it is a Plex GET that changes something or hands out a token (refresh, terminate, transcode, /:/, security); use device_change_raw CALL or device_show")
			}
			return nil
		},
		catalog: []string{"/library/sections", "/status/sessions", "/library/recentlyAdded", "/activities", "/identity"},
	}
}

// ---- Jellyfin ----

var jellyWriteRE = regexp.MustCompile(`(?i)^/(videos|audio|livetv/livestreamfiles|auth|startup|quickconnect)(/|$)|/(stream|master\.m3u8|main\.m3u8|hls1?)(/|$|\.)`)

func jellyfinSpec() *mediaSpec {
	return &mediaSpec{platform: "jellyfin", vendor: "Jellyfin", model: "Jellyfin Server", port: 8096, root: "", auth: "mediabrowser",
		facts: func(ctx context.Context, m *media) (Facts, error) {
			s, err := m.getMap(ctx, "/System/Info")
			if err != nil {
				return Facts{}, err
			}
			return Facts{Hostname: firstOf(str(s["ServerName"]), m.d.Name), Vendor: "Jellyfin", Model: "Jellyfin Server", OSVersion: str(s["Version"])}, nil
		},
		shows: map[string]mshow{
			"info":      {path: "/System/Info", help: "version, OS, paths, pending restart"},
			"sessions":  {path: "/Sessions", cols: []string{"Id", "UserName", "Client", "DeviceName", "NowPlayingItem", "PlayState", "TranscodingInfo", "LastActivityDate"}, help: "clients and what they play"},
			"libraries": {path: "/Library/VirtualFolders", name: "Name", cols: []string{"Name", "ItemId", "CollectionType", "Locations", "RefreshStatus", "RefreshProgress"}, help: "libraries and their folders"},
			"tasks":     {path: "/ScheduledTasks", name: "Name", cols: []string{"Id", "Name", "State", "CurrentProgressPercentage", "Category", "LastExecutionResult"}, help: "scheduled tasks (Id is what run-task takes)"},
			"task":      {path: "/ScheduledTasks/{id}", help: "id: one task"},
			"logs":      {path: "/System/Logs", help: "log files"},
			"activity":  {path: "/System/ActivityLog/Entries?startIndex=0&limit={n}", cols: []string{"Date", "Name", "Type", "Severity", "ShortOverview"}, help: "the activity log, newest first"},
			"users":     {path: "/Users", cols: []string{"Id", "Name", "LastLoginDate", "LastActivityDate", "HasPassword"}, help: "users"},
			"devices":   {path: "/Devices", cols: []string{"Id", "Name", "AppName", "LastUserName", "DateLastActivity"}, help: "devices"},
			"plugins":   {path: "/Plugins", cols: []string{"Name", "Version", "Status", "Id"}, help: "plugins"},
			"items":     {path: "/Items?Recursive=true&Limit={n}", args: "searchTerm parentId includeItemTypes", cols: []string{"Id", "Name", "Type", "ProductionYear", "Path"}, help: "searchTerm=, parentId=, includeItemTypes=Movie|Series|Episode"},
			"item":      {path: "/Items?Ids={id}&Fields=Path,MediaSources", help: "id: one item, its path and media"},
			"counts":    {path: "/Items/Counts", help: "how many of each kind"},
		},
		calls: map[string]mcall{
			"scan-all":      {method: "POST", path: "/Library/Refresh", before: "/Library/VirtualFolders", help: "scan every library"},
			"refresh-item":  {method: "POST", path: "/Items/{id}/Refresh", enc: "query", help: "id, and optionally Recursive, MetadataRefreshMode, ImageRefreshMode, ReplaceAllMetadata"},
			"run-task":      {method: "POST", path: "/ScheduledTasks/Running/{id}", before: "/ScheduledTasks/{id}", help: "id: run a scheduled task now"},
			"stop-task":     {method: "DELETE", path: "/ScheduledTasks/Running/{id}", before: "/ScheduledTasks/{id}", help: "id: stop a running task"},
			"stop-playback": {method: "POST", path: "/Sessions/{id}/Playing/Stop", before: "/Sessions", help: "id (session): stop what it plays"},
			"message":       {method: "POST", path: "/Sessions/{id}/Message", enc: "json", help: "id (session), Header, Text, TimeoutMs"},
			"restart":       {method: "POST", path: "/System/Restart", guard: true, help: "restart the server"},
			"delete-item":   {method: "DELETE", path: "/Items/{id}", guard: true, before: "/Items?Ids={id}&Fields=Path", help: "id: delete an item AND ITS FILES"},
		},
		readOK: func(p string) error {
			if jellyWriteRE.MatchString(strings.SplitN(p, "?", 2)[0]) {
				return errors.New("path: refused, it streams media or hands out keys (Videos, Audio, Auth, streams)")
			}
			return nil
		},
		catalog: []string{"/System/Info", "/Sessions", "/Library/VirtualFolders", "/ScheduledTasks", "/Items?Recursive=true&searchTerm=Blue&Limit=10"},
	}
}

package mcp

import (
	"strings"
)

func mcpDeviceRawTool() mcpTool {
	return mcpTool{name: "device_change_raw", title: "Change device configuration", noNode: true, write: true, destructive: true,
		desc: "Make any configuration change on devices: the platform's own write. REST platforms (Cisco IOS-XE RESTCONF, Aruba AOS-CX, Aruba Fabric Composer, Proxmox VE, FortiOS cmdb, Infoblox WAPI, F5 BIG-IP iControl, Technitium, Cisco Meraki, Observium, Microsoft Entra Graph): method POST, PUT, PATCH or DELETE, " +
			"path and body (JSON; Technitium: name=value&name=value). PAN-OS and Panorama: method is the action (set, edit, delete, rename, move), path the XPath below /config/, body the XML element. " +
			"Arista EOS and Cisco NX-OS: lines of configuration. DNS Director and NTP Director (dnsdir, ntpdir): method SET with a JSON object of settings in body (merged into its configuration), or POST or PUT of a /api/ route. FileDirector (filedir): method PUT (text) or PUT-BASE64 of one file, path FOLDER:dir/file (256 KB at most); MKDIR, DELETE (to the folder's trash), MOVE and RENAME (path FOLDER:dir/file, body the new place, \\\"OTHER:new/path\\\" for another folder), COPY, EMPTY-TRASH (path FOLDER, removes for good) and TRASH-RESTORE (body WHEN NAME) change the tree (filedir 43 or later; device_show \\\"show trash folder=F\\\" lists the trash); for a bigger file method UPLOAD-URL (path FOLDER:dir/file, body the minutes it lasts, default 15) hands back a link to send the file to with curl -T FILE URL from a machine that can reach the gateway (filedir 42 or later; device_show \"show download-url folder=F path=P\" gives the link to fetch one). multi-media[encoder] (mediaencoder): method SET with a JSON object of settings in body, or method CALL with the action as the path (start_job: STARTS A REAL ENCODE JOB, it is not a scan; to see what would be encoded use device_show \"show scan target=movies|tv\" instead; stop_job, stop_cluster_jobs, drain_node, create_schedule, update_schedule, toggle_schedule, run_schedule, delete_schedule, clear_queue, purge_quarantine: deletes the files in quarantine, all of them unless older_than_days is in the body) and its arguments as the JSON body; it has no dry run, so a dry run shows how things stand now. Media applications (sonarr, radarr, lidarr, prowlarr, bazarr, qbittorrent, tautulli, seerr, plex, jellyfin): method CALL with an action as the path and its arguments as a JSON body, or POST, PUT, PATCH or DELETE of a path below the API root with a JSON body. The *arr apps take any command name as the action, e.g. CALL RescanSeries, RefreshSeries, DownloadedEpisodesScan, RefreshMovie, MissingEpisodeSearch. A title in the body (series, movie, artist; for qBittorrent, torrent) is turned into its id, so {\"series\": \"Blue Bloods\"} works. Other actions: Bazarr run-task, series-action, movie-action; qBittorrent stop, start, recheck, reannounce, setLocation, setCategory, delete, setPreferences; Tautulli any command name (terminate_session, ...); Seerr approve, decline, retry, run-job, resolve-issue; Plex refresh (id, optional path), refresh-item, butler-run, terminate; Jellyfin scan-all, refresh-item, run-task, stop-playback. device_api_catalog lists all of them. A dry run reads what the action touches and says what it would send. Plan it first with dry_run: true: REST platforms and PAN-OS return what the path holds now, EOS returns the switch's own diff. " +
			"An rw key may change anything the device's own login allows, including users, keys, file operations and the management port: there is no list of refusals, so a change that cuts the management access cuts it (a read before the change, put-back of a failed PUT or PATCH, the confirmed commit and the checkpoint remain). A reboot is accepted where the platform has one: IOS-XE POST /restconf/operations/Cisco-IOS-XE-rpc:reload, AOS-CX POST <rest root>/boot?image=primary, FortiOS POST /api/v2/monitor/system/os/reboot, BIG-IP POST /mgmt/tm/sys with {\"command\":\"reboot\"}, Meraki POST /devices/SERIAL/reboot, Proxmox POST /nodes/NODE/status with {\"command\":\"reboot\"}, PAN-OS/Panorama method reboot, EOS and NX-OS the single line reload. Nothing is read back after a reboot and nothing is put back; the device is unreachable for a few minutes, and save: true writes the configuration first. Infoblox, Technitium, AFC, the directors, Observium and Entra have no reboot here. REST changes that fail, or after which the device stops answering, are put back with the saved copy (PUT/PATCH only); " +
			"EOS commits with a 3-minute timer and confirms it only when the switch answers; NX-OS rolls back to a checkpoint. A POST or DELETE cannot be undone by this tool, and the result is not read back for equality. save: true makes it survive a reboot (save config, write memory, commit).",
		props: []mcpProp{
			{name: "target", typ: "string", required: true, desc: "The devices: a name, tag:TAG, platform:PLATFORM, gateway:N or \"all\" (list_devices)."},
			{name: "method", typ: "string", desc: "REST: POST, PUT, PATCH, DELETE. PAN-OS: set, edit, delete, rename, move."},
			{name: "path", typ: "string", desc: "REST path (as device_api_get takes it, e.g. /restconf/data/Cisco-IOS-XE-native:native/ntp) or PAN-OS XPath."},
			{name: "body", typ: "string", desc: "The request body as text."},
			{name: "lines", typ: "string", desc: "EOS and NX-OS: the configuration lines, one per line of this text."},
			{name: "save", typ: "boolean", desc: "Save the change so it survives a reboot."},
			{name: "dry_run", typ: "boolean", desc: "Only plan: change nothing."},
		},
		run: func(c *mcpCtx) (any, error) {
			dry, _ := c.flag("dry_run")
			save, _ := c.flag("save")
			body := map[string]any{"target": c.str("target"), "method": c.str("method"), "path": c.str("path"), "body": c.str("body"), "save": save, "dry_run": dry}
			if l := strings.TrimSpace(c.str("lines")); l != "" {
				body["lines"] = strings.Split(l, "\n")
			}
			b, err := c.call("POST", "/api/devices/raw", body, "")
			return asAny(b), err
		}}
}

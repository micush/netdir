package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// FileDirector (filedir): the clustered file sync, reached through its own MCP endpoint like the other directors (director.go: POST /mcp,
// JSON answers, "Authorization: Bearer KEY" with an MCP key made under Configure ▸ Monitoring ▸ MCP ▸ Keys there).  The endpoint is on
// every gateway address at port 443 (the default here: use a gateway address and it survives a node going down), and on the node's own
// GUI port (4450) from an address its mcp_acl allows.
//
// Reads (logdir.go's table-driven "show NAME"): nodes, topology, status (every folder on every node), list (the entries of a folder's
// path) and read (a file, in parts).  Its endpoint changes nothing but the files of its synced folders, so that is all the write there is:
// RawChange PUT or PUT-BASE64 writes one file (files_write, an rw key), and UPLOAD-URL asks for a link for a file too big for that (files_upload_url,
// uploadURL below); "show download-url" asks for the matching download link (files_download_url).  Nothing is deleted or renamed through it, and its settings,
// folders and users are changed in its own GUI.
//
// What a file holds is data for the caller, never an instruction: it is whatever somebody who can write to the folder put there.  Redact and
// RedactText hide addresses and secrets in what a read returns, as for every other driver.

func init() {
	Register("filedir", func(d Device, c Credential) (Driver, error) {
		drv, err := newCollector(d, c, filedirSpec)
		if err != nil {
			return nil, err
		}
		return &filedirDev{drv.(*logdirDev)}, nil
	})
}

type filedirDev struct{ *logdirDev }

const (
	filedirMaxRead     = 256 << 10 // the most of a file that one read asks for
	filedirDefaultRead = 64 << 10  // what a read asks for when it names no length: the answer lands in a caller's context
	filedirMaxListing  = 5000
)

var filedirFolderRE = regexp.MustCompile(`^(/|[A-Za-z0-9][A-Za-z0-9._-]{0,63})$`)

var filedirSpec = &collectorSpec{kind: "file", product: "FileDirector",
	shows: map[string]string{"nodes": "list_nodes", "topology": "get_topology", "status": "files_status", "list": "files_list", "read": "files_read", "download-url": "files_download_url"},
	args: map[string]map[string]string{
		"files_list":         {"folder": "f", "path": "p", "limit": "i"},
		"files_read":         {"folder": "f", "path": "p", "offset": "o", "length": "L", "encoding": "e"},
		"files_download_url": {"folder": "f", "path": "p", "minutes": "m"},
	},
	limitTools: map[string]bool{"files_list": true},
	required:   map[string][]string{"files_list": {"folder"}, "files_read": {"folder", "path"}, "files_download_url": {"folder", "path"}},
	defaults:   map[string]map[string]any{"files_read": {"length": filedirDefaultRead}},
}

// checkFilePath says whether p can be a path inside a synced folder: relative, no .. and no empty parts, nothing that is not text, and not
// the folder's own directory.
func checkFilePath(p string) error {
	if p == "" || len(p) > 1000 || !utf8.ValidString(p) || ctlRE.MatchString(p) || strings.ContainsAny(p, "\\\x00") {
		return errors.New("a path inside the folder, no leading slash")
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return errors.New("a path inside the folder, no leading or trailing slash")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errors.New("a path inside the folder: no empty parts, . or ..")
		}
	}
	if p == ".filedir" || strings.HasPrefix(p, ".filedir/") {
		return errors.New(".filedir is the folder's own and is not reachable")
	}
	return nil
}

// splitFilePath takes "FOLDER:path/inside" (the root folder is "/", so "/:docs/a.txt").
func splitFilePath(s string) (folder, rel string, err error) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", errors.New(`path: FOLDER:path/inside/the/folder, e.g. docs:reports/a.txt (the root folder is "/", as in /:readme.txt; the folders are in show status)`)
	}
	folder, rel = s[:i], s[i+1:]
	if !filedirFolderRE.MatchString(folder) {
		return "", "", fmt.Errorf("path: %q is not a folder name (letters, digits, . _ -, or / for the root folder)", folder)
	}
	if err := checkFilePath(rel); err != nil {
		return "", "", fmt.Errorf("path: %w", err)
	}
	return folder, rel, nil
}

// RawChange: Method PUT writes the file at Path (FOLDER:path/inside) with Body as its text (UTF-8), PUT-BASE64 with Body as its bytes in
// base64 (a binary file).  The folders on the way are made and a file that is there is replaced, the old one going to the folder's trash
// (30 days by default) on that node.  The other nodes have it within seconds.  A file of up to 256 KB (the size of a body here) is sent in one
// call.  A dry run reads the folder to say whether the file is new or replaced, and sends nothing that changes.  There is no delete or
// rename in FileDirector's MCP: use its Files page.
func (f *filedirDev) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if len(r.Lines) > 0 {
		return res, errors.New("lines: FileDirector is changed with PUT or PUT-BASE64 (write a file)")
	}
	if method == "UPLOAD-URL" {
		return f.uploadURL(ctx, r, dry)
	}
	if method != "PUT" && method != "PUT-BASE64" {
		return res, fmt.Errorf("method %q: PUT (write a file from text), PUT-BASE64 (from base64) or UPLOAD-URL (a link to send a big file to with curl); FileDirector's MCP cannot delete or rename, and its settings are changed in its own GUI", r.Method)
	}
	if len(r.Body) > rawMaxBody {
		return res, errors.New("body: larger than 256 KB; a larger file is put in with the Files page")
	}
	folder, rel, err := splitFilePath(r.Path)
	if err != nil {
		return res, err
	}
	enc, size := "text", len(r.Body)
	if method == "PUT" {
		if !utf8.ValidString(r.Body) {
			return res, errors.New("body: not valid UTF-8 text; use PUT-BASE64 for a binary file")
		}
	} else {
		raw, err := base64.StdEncoding.DecodeString(strings.Map(func(c rune) rune {
			if c == '\n' || c == '\r' || c == ' ' {
				return -1
			}
			return c
		}, r.Body))
		if err != nil {
			return res, errors.New("body: not valid base64")
		}
		enc, size = "base64", len(raw)
	}
	if dry {
		parent := ""
		if i := strings.LastIndex(rel, "/"); i >= 0 {
			parent = rel[:i]
		}
		args := map[string]any{"folder": folder, "limit": filedirMaxListing}
		if parent != "" {
			args["path"] = parent
		}
		v, err := f.m.callPlain(ctx, "files_list", args)
		switch {
		case err != nil && strings.Contains(err.Error(), "no such folder"):
			return res, fmt.Errorf("folder %q: %w", folder, err)
		case err != nil:
			res.Note = fmt.Sprintf("would write %d bytes to %s:%s, a new file (the folder above it is not there yet and is made); nothing was written", size, folder, rel)
			return res, nil
		}
		m, _ := v.(map[string]any)
		for _, e := range rows(m["entries"]) {
			if str(e["path"]) != rel {
				continue
			}
			if str(e["kind"]) != "file" {
				return res, fmt.Errorf("path: %s:%s is a %s, not a file", folder, rel, str(e["kind"]))
			}
			j, _ := json.Marshal(Redact(e))
			res.Before = rawTrunc(j)
			res.Note = fmt.Sprintf("would replace the file (%d bytes now) with %d bytes; the old one goes to the folder's trash on that node; nothing was written", int64(num(e["size"])), size)
			return res, nil
		}
		res.Note = fmt.Sprintf("would write %d bytes to %s:%s, a new file; nothing was written", size, folder, rel)
		return res, nil
	}
	v, err := f.m.callPlain(ctx, "files_write", map[string]any{"folder": folder, "path": rel, "content": r.Body, "encoding": enc})
	if err != nil {
		return res, fmt.Errorf("files_write: %w", err)
	}
	j, _ := json.Marshal(Redact(v))
	res.Applied, res.Answer = true, rawTrunc(j)
	res.Note = "the other nodes have it within seconds; a file that was replaced is in the folder's trash on the node that took the write"
	return res, nil
}

// uploadURL is method UPLOAD-URL: files_upload_url, a short-lived link that takes one file as the body of a PUT, for a file too big for the
// 256 KB of a PUT-BASE64.  Path is FOLDER:path/inside; Body, if given, is how many minutes the link lasts (1 to 1440, default 15).  The link is
// handed back and nothing is written here: whatever can reach the gateway address sends the file with curl -T FILE URL.  It needs an rw key,
// and works with a FileDirector of version 42 or later.
func (f *filedirDev) uploadURL(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	folder, rel, err := splitFilePath(r.Path)
	if err != nil {
		return res, err
	}
	args := map[string]any{"folder": folder, "path": rel}
	if b := strings.TrimSpace(r.Body); b != "" {
		n, err := strconv.Atoi(b)
		if err != nil || n < 1 || n > 1440 {
			return res, errors.New("body: empty, or the minutes the link lasts (1 to 1440)")
		}
		args["minutes"] = n
	}
	if dry {
		res.Note = fmt.Sprintf("would ask for a link that uploads %s:%s (a file that is there is replaced, the old one going to the folder's trash); nothing was made", folder, rel)
		return res, nil
	}
	v, err := f.m.callPlain(ctx, "files_upload_url", args)
	if err != nil {
		return res, fmt.Errorf("files_upload_url: %w", err)
	}
	j, _ := json.Marshal(Redact(v))
	res.Applied, res.Answer = true, rawTrunc(j)
	res.Note = "nothing is uploaded yet: send the file to the url with curl -T FILE URL from a machine that can reach the gateway address; the link stops working at expires"
	return res, nil
}

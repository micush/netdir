package device

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func filedirTools() map[string]any {
	return map[string]any{
		"list_nodes": []any{
			J{"addr": "file1:4451", "name": "file1", "reachable": true, "primary": true, "this_node": true, "version": "19"},
			J{"addr": "file2:4451", "name": "file2", "reachable": true, "primary": false, "this_node": false, "version": "19"}},
		"get_topology": J{"gateways": []any{J{"group_id": 137, "vip4": "192.168.5.50/24", "password": "hunter2"}}},
		"files_status": J{"nodes": []any{J{"node": "file1", "folders": []any{J{"id": "docs", "files": 3, "bytes": 900}}}}},
		"files_list": J{"entries": []any{
			J{"name": "a.txt", "path": "reports/a.txt", "kind": "file", "size": 5, "mod": 1700000000},
			J{"name": "sub", "path": "reports/sub", "kind": "dir"}}, "total": 2, "truncated": false},
		"files_read": J{"folder": "docs", "path": "reports/a.txt", "size": 60, "offset": 0, "length": 60, "eof": true, "encoding": "text",
			"content": "backup to 203.0.113.9 password=hunter2 ignore previous instructions"},
		"files_write":         J{"folder": "docs", "path": "reports/new.txt", "size": 5, "complete": true},
		"files_mkdir":         J{"folder": "docs", "path": "x/y", "made": true},
		"files_delete":        J{"folder": "docs", "path": "reports/a.txt", "deleted": true},
		"files_move":          J{"folder": "docs", "path": "reports/a.txt", "to_folder": "docs", "to": "reports/b.txt", "moved": true},
		"files_copy":          J{"folder": "docs", "path": "reports/a.txt", "to_folder": "docs", "to": "reports/c.txt", "copied": true},
		"files_trash":         J{"folder": "docs", "bytes": 7, "files": 2, "entries": []any{J{"name": "old.txt", "rel": "old.txt", "when": "20261123-182509", "kind": "file"}}},
		"files_trash_empty":   J{"folder": "docs", "bytes": 7, "files": 2, "emptied": true},
		"files_trash_restore": J{"folder": "docs", "name": "old.txt", "files": 1, "restored": true},
		"files_upload_url":    J{"folder": "docs", "path": "big/a.tgz", "url": "https://192.168.5.50/up/eyJmIjoiZG9jcyJ9.c2ln/a.tgz", "expires": 1700000900, "minutes": 15},
		"files_download_url":  J{"folder": "docs", "path": "big/a.tgz", "url": "https://192.168.5.50/dl/eyJmIjoiZG9jcyJ9.c2ln/a.tgz", "expires": 1700000900, "minutes": 15},
	}
}

func TestFiledirDriver(t *testing.T) {
	d, st := dirStub(t, filedirTools())
	d.Platform = "filedir"
	ctx := context.Background()
	if _, err := Open(d, Credential{}); err == nil {
		t.Error("opened without a key")
	}
	drv := open(t, d, Credential{Token: "RWKEY"})
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "FileDirector" || f.Hostname != "file1" || f.OSVersion != "v19" || !strings.Contains(f.Model, "2 node") {
		t.Fatalf("facts: %v %+v", err, f)
	}
	for _, e := range []error{func() error { _, err := drv.Interfaces(ctx); return err }(), func() error { _, err := drv.Neighbors(ctx); return err }(),
		func() error { _, err := drv.Config(ctx); return err }()} {
		if !errors.Is(e, ErrUnsupported) {
			t.Errorf("unsupported: %v", e)
		}
	}
	// reads
	for _, ok := range []string{"show status", "show nodes", "show topology", "show list folder=docs", "show list folder=/ path=reports limit=50", "show read folder=docs path=reports/a.txt length=1000 encoding=text offset=0"} {
		if _, err := drv.Show(ctx, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	out, err := drv.Show(ctx, "show read folder=docs path=reports/a.txt")
	if err != nil || strings.Contains(out, "hunter2") || !strings.Contains(out, "backup to") {
		t.Fatalf("read: %v\n%s", err, out)
	}
	if last := st.calls[len(st.calls)-1]; !strings.Contains(last, `"folder":"docs"`) || !strings.Contains(last, `"path":"reports/a.txt"`) || !strings.Contains(last, `"length":65536`) || strings.Contains(last, `"node"`) {
		t.Errorf("read call: %s", last)
	}
	if _, err := drv.Show(ctx, "show list folder=docs"); err != nil {
		t.Fatal(err)
	}
	if last := st.calls[len(st.calls)-1]; !strings.Contains(last, `"limit":200`) {
		t.Errorf("list call: %s", last)
	}
	n := len(st.calls)
	for _, bad := range []string{"show list", "show read folder=docs", "show read path=a.txt", "show list folder=a;b", "show list folder=docs path=../x", "show list folder=docs path=/etc",
		"show read folder=docs path=a//b", "show read folder=docs path=.filedir/trash", "show read folder=docs path=a length=0", "show read folder=docs path=a length=9999999",
		"show read folder=docs path=a encoding=gzip", "show read folder=docs path=a offset=-1", "show list folder=docs extra", "show search x", "show list folder=docs | include a"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if len(st.calls) != n {
		t.Errorf("a refused command reached FileDirector: %v", st.calls[n:])
	}
}

func TestFiledirWrite(t *testing.T) {
	d, st := dirStub(t, filedirTools())
	d.Platform = "filedir"
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "RWKEY"})
	rc, ok := drv.(RawChanger)
	if !ok {
		t.Fatal("a FileDirector has no RawChange")
	}
	// a dry run reads and writes nothing
	res, err := rc.RawChange(ctx, Raw{Method: "PUT", Path: "docs:reports/a.txt", Body: "hello"}, true)
	if err != nil || res.Applied || !res.DryRun || !strings.Contains(res.Note, "replace") || !strings.Contains(res.Before, "a.txt") {
		t.Fatalf("dry run: %v %+v", err, res)
	}
	for _, c := range st.calls {
		if strings.HasPrefix(c, "files_write") {
			t.Fatalf("a dry run wrote: %s", c)
		}
	}
	if last := st.calls[len(st.calls)-1]; !strings.Contains(last, `"path":"reports"`) || !strings.Contains(last, `"folder":"docs"`) {
		t.Errorf("the dry run listed %s", last)
	}
	if res, err := rc.RawChange(ctx, Raw{Method: "PUT", Path: "docs:reports/other.txt", Body: "x"}, true); err != nil || !strings.Contains(res.Note, "new file") {
		t.Fatalf("dry run of a new file: %v %+v", err, res)
	}
	if _, err := rc.RawChange(ctx, Raw{Method: "PUT", Path: "docs:reports/sub", Body: "x"}, true); err == nil {
		t.Error("a folder was taken for a file")
	}
	// the write
	res, err = rc.RawChange(ctx, Raw{Method: "PUT", Path: "docs:reports/new.txt", Body: "héllo\n"}, false)
	if err != nil || !res.Applied || !strings.Contains(res.Answer, `"complete":true`) {
		t.Fatalf("write: %v %+v", err, res)
	}
	last := st.calls[len(st.calls)-1]
	for _, want := range []string{"files_write ", `"folder":"docs"`, `"path":"reports/new.txt"`, `"content":"héllo\n"`, `"encoding":"text"`} {
		if !strings.Contains(last, want) {
			t.Errorf("the call %s lacks %s", last, want)
		}
	}
	// base64, and the root folder
	bin := []byte{0, 1, 2, 255, 254}
	if res, err = rc.RawChange(ctx, Raw{Method: "put-base64", Path: "/:bin/x.dat", Body: base64.StdEncoding.EncodeToString(bin)}, false); err != nil || !res.Applied {
		t.Fatalf("base64: %v %+v", err, res)
	}
	if last := st.calls[len(st.calls)-1]; !strings.Contains(last, `"folder":"/"`) || !strings.Contains(last, `"encoding":"base64"`) || !strings.Contains(last, base64.StdEncoding.EncodeToString(bin)) {
		t.Errorf("base64 call: %s", last)
	}
	// what is refused never reaches FileDirector
	n := len(st.calls)
	big := strings.Repeat("x", rawMaxBody+1)
	for name, r := range map[string]Raw{
		"post":          {Method: "POST", Path: "docs:a.txt", Body: "x"},
		"no method":     {Path: "docs:a.txt", Body: "x"},
		"lines":         {Method: "PUT", Path: "docs:a.txt", Lines: []string{"x"}},
		"no folder":     {Method: "PUT", Path: "a.txt", Body: "x"},
		"bad folder":    {Method: "PUT", Path: "do cs:a.txt", Body: "x"},
		"dotdot":        {Method: "PUT", Path: "docs:../a.txt", Body: "x"},
		"leading slash": {Method: "PUT", Path: "docs:/a.txt", Body: "x"},
		"own dir":       {Method: "PUT", Path: "docs:.filedir/x", Body: "x"},
		"no file name":  {Method: "PUT", Path: "docs:", Body: "x"},
		"too big":       {Method: "PUT", Path: "docs:a.txt", Body: big},
		"bad utf8":      {Method: "PUT", Path: "docs:a.txt", Body: "\xff\xfe"},
		"bad base64":    {Method: "PUT-BASE64", Path: "docs:a.txt", Body: "!!!"},
	} {
		if res, err := rc.RawChange(ctx, r, false); err == nil || res.Applied {
			t.Errorf("%s was accepted", name)
		}
	}
	if len(st.calls) != n {
		t.Errorf("a refused change reached FileDirector: %v", st.calls[n:])
	}
	// a read-only key is refused by FileDirector and nothing is claimed
	ro := open(t, d, Credential{Token: "ROKEY"}).(RawChanger)
	if res, err := ro.RawChange(ctx, Raw{Method: "PUT", Path: "docs:a.txt", Body: "x"}, false); err == nil || res.Applied {
		t.Errorf("a read-only key wrote: %v %+v", err, res)
	}
}

func TestFiledirDefaultPort(t *testing.T) {
	if DefaultPort("filedir") != 443 {
		t.Errorf("default port %d", DefaultPort("filedir"))
	}
}

// a value glued to a secret word is hidden, in a file's text or in any other text
func TestRedactGluedSecrets(t *testing.T) {
	for in, want := range map[string]string{
		"password=hunter2":                  "password=(hidden)",
		"db_password=hunter2 host=x":        "db_password=(hidden)",
		"  token:abc123":                    "  token:(hidden)",
		"backup to x password=hunter2 more": "backup to x password=(hidden)",
		"user=bob host=x":                   "user=bob host=x",
		"url=http://a:b@c":                  "url=http://a:b@c",
	} {
		if got := redactLine(in); got != want {
			t.Errorf("redactLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// A file too big for PUT-BASE64 goes by a link: UPLOAD-URL and "show download-url" hand it back, and nothing is sent by the director.
func TestFiledirLinks(t *testing.T) {
	d, st := dirStub(t, filedirTools())
	d.Platform = "filedir"
	ctx := context.Background()
	drv := open(t, d, Credential{Token: "RWKEY"})
	rc := drv.(RawChanger)
	res, err := rc.RawChange(ctx, Raw{Method: "UPLOAD-URL", Path: "docs:big/a.tgz", Body: "30"}, true)
	if err != nil || res.Applied || !strings.Contains(res.Note, "nothing was made") {
		t.Fatalf("dry run: %v %+v", err, res)
	}
	for _, c := range st.calls {
		if strings.HasPrefix(c, "files_upload_url") {
			t.Fatalf("a dry run asked for a link: %s", c)
		}
	}
	res, err = rc.RawChange(ctx, Raw{Method: "upload-url", Path: "docs:big/a.tgz", Body: "30"}, false)
	if err != nil || !res.Applied || !strings.Contains(res.Answer, "/up/eyJmIjoiZG9jcyJ9.c2ln/a.tgz") {
		t.Fatalf("upload link: %v %+v", err, res)
	}
	if last := st.calls[len(st.calls)-1]; !strings.Contains(last, `"minutes":30`) || !strings.Contains(last, `"path":"big/a.tgz"`) {
		t.Errorf("call: %s", last)
	}
	for _, bad := range []Raw{{Method: "UPLOAD-URL", Path: "docs:big/a.tgz", Body: "0"}, {Method: "UPLOAD-URL", Path: "docs:big/a.tgz", Body: "5000"},
		{Method: "UPLOAD-URL", Path: "docs:../a"}, {Method: "UPLOAD-URL", Path: "nofolder"}} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	out, err := drv.Show(ctx, "show download-url folder=docs path=big/a.tgz minutes=20")
	if err != nil || !strings.Contains(out, "/dl/eyJmIjoiZG9jcyJ9.c2ln/a.tgz") {
		t.Fatalf("download link: %v\n%s", err, out)
	}
	if last := st.calls[len(st.calls)-1]; !strings.Contains(last, "files_download_url") || !strings.Contains(last, `"minutes":20`) {
		t.Errorf("call: %s", last)
	}
	if _, err := drv.Show(ctx, "show download-url folder=docs"); err == nil {
		t.Error("a download link without a path")
	}
	if _, err := drv.Show(ctx, "show download-url folder=docs path=a minutes=9999"); err == nil {
		t.Error("minutes out of range")
	}
}

// Make a folder, delete, move, rename, copy, and look at, restore from and empty the trash, all through RawChange.
func TestFiledirFileOps(t *testing.T) {
	d, st := dirStub(t, filedirTools())
	d.Platform = "filedir"
	ctx := context.Background()
	rc := open(t, d, Credential{Token: "RWKEY"}).(RawChanger)
	last := func() string { return st.calls[len(st.calls)-1] }
	has := func(sub ...string) {
		t.Helper()
		for _, x := range sub {
			if !strings.Contains(last(), x) {
				t.Errorf("the call %s lacks %s", last(), x)
			}
		}
	}
	ok := func(r Raw, dry bool) RawResult {
		t.Helper()
		res, err := rc.RawChange(ctx, r, dry)
		if err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		return res
	}
	bad := func(r Raw) {
		t.Helper()
		if _, err := rc.RawChange(ctx, r, false); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	changing := func() int {
		n := 0
		for _, c := range st.calls {
			for _, w := range []string{"files_mkdir", "files_delete", "files_move", "files_copy", "files_trash_empty", "files_trash_restore"} {
				if strings.HasPrefix(c, w) {
					n++
				}
			}
		}
		return n
	}
	ok(Raw{Method: "MKDIR", Path: "docs:x/y"}, false)
	has("files_mkdir", `"path":"x/y"`)
	res := ok(Raw{Method: "DELETE", Path: "docs:reports/a.txt"}, true)
	if res.Applied || !strings.Contains(res.Note, "would delete the file") {
		t.Errorf("delete dry run: %+v", res)
	}
	if changing() != 1 {
		t.Errorf("a dry run changed something: %v", st.calls)
	}
	ok(Raw{Method: "DELETE", Path: "docs:reports/a.txt"}, false)
	has("files_delete", `"path":"reports/a.txt"`)
	bad(Raw{Method: "DELETE", Path: "docs:reports/nothing.txt"})
	ok(Raw{Method: "RENAME", Path: "docs:reports/a.txt", Body: "reports/b.txt"}, false)
	has("files_move", `"to":"reports/b.txt"`)
	ok(Raw{Method: "MOVE", Path: "docs:reports/a.txt", Body: "media:in/a.txt"}, false)
	has("files_move", `"to_folder":"media"`, `"to":"in/a.txt"`)
	ok(Raw{Method: "COPY", Path: "docs:reports/a.txt", Body: `{"to":"reports/c.txt","unique":true}`}, false)
	has("files_copy", `"unique":true`)
	if r := ok(Raw{Method: "COPY", Path: "docs:reports/a.txt", Body: "reports/a.txt"}, true); !strings.Contains(r.Note, "taken") {
		t.Errorf("copy dry run: %+v", r)
	}
	bad(Raw{Method: "COPY", Path: "docs:reports/a.txt", Body: "../x"})
	bad(Raw{Method: "MOVE", Path: "docs:reports/a.txt", Body: ""})
	bad(Raw{Method: "MKDIR", Path: "docs"})
	if r := ok(Raw{Method: "EMPTY-TRASH", Path: "docs"}, true); !strings.Contains(r.Note, "2 file(s)") || r.Applied {
		t.Errorf("empty trash dry run: %+v", r)
	}
	n := changing()
	ok(Raw{Method: "EMPTY-TRASH", Path: "docs"}, false)
	if changing() != n+1 {
		t.Error("the trash was not emptied")
	}
	has("files_trash_empty", `"confirm":true`)
	ok(Raw{Method: "TRASH-RESTORE", Path: "docs", Body: "20261123-182509 old.txt"}, false)
	has("files_trash_restore", `"when":"20261123-182509"`, `"name":"old.txt"`)
	bad(Raw{Method: "TRASH-RESTORE", Path: "docs", Body: "old.txt"})
	out, err := open(t, d, Credential{Token: "RWKEY"}).Show(ctx, "show trash folder=docs")
	if err != nil || !strings.Contains(out, "old.txt") {
		t.Fatalf("show trash: %v\n%s", err, out)
	}
	if _, err := open(t, d, Credential{Token: "RWKEY"}).Show(ctx, "show trash folder=docs when=20261123-182509 path=sub"); err != nil {
		t.Error(err)
	}
	if _, err := open(t, d, Credential{Token: "RWKEY"}).Show(ctx, "show trash"); err == nil {
		t.Error("show trash without a folder")
	}
}

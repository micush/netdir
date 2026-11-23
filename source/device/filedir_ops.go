package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The rest of what a read-write key can do to the files of a FileDirector (filedir 43 or later), as RawChange methods:
//
//	MKDIR         Path FOLDER:dir                     make a folder (and the ones on the way)
//	DELETE        Path FOLDER:path                    delete a file or folder tree; it goes to the folder's trash
//	MOVE, RENAME  Path FOLDER:path, Body the new place move or rename; Body "new/path" in the same folder, "OTHER:new/path" in another
//	COPY          Path FOLDER:path, Body the new place
//	TRASH-RESTORE Path FOLDER, Body "WHEN NAME"        put an entry of the trash back (show trash lists them)
//	EMPTY-TRASH   Path FOLDER                          remove what is in the folder's trash for good
//
// For MOVE, RENAME and COPY the Body may also be a JSON object {"to": "...", "to_folder": "...", "unique": true}; unique picks a free name
// ("name copy.ext") when the new one is taken.  Each node keeps its own trash, so the trash methods act on the node that answers.  A dry run
// checks the arguments and reads the folder, and changes nothing.

var filedirOps = map[string]bool{"MKDIR": true, "DELETE": true, "MOVE": true, "RENAME": true, "COPY": true, "TRASH-RESTORE": true, "EMPTY-TRASH": true}

var trashWhenRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// splitFolderOnly takes "FOLDER" or "FOLDER:" (the trash methods name no path).
func splitFolderOnly(s string) (string, error) {
	folder := strings.TrimSuffix(s, ":")
	if !filedirFolderRE.MatchString(folder) {
		return "", fmt.Errorf("path: %q is not a folder name (letters, digits, . _ -, or / for the root folder)", s)
	}
	return folder, nil
}

// kindOf says what is at rel in a folder ("file", "dir") or "" when nothing is, by listing its parent.
func (f *filedirDev) kindOf(ctx context.Context, folder, rel string) (kind string, size int64, err error) {
	parent := ""
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		parent = rel[:i]
	}
	args := map[string]any{"folder": folder, "limit": filedirMaxListing}
	if parent != "" {
		args["path"] = parent
	}
	v, err := f.m.callPlain(ctx, "files_list", args)
	if err != nil {
		if strings.Contains(err.Error(), "no such folder") {
			return "", 0, fmt.Errorf("folder %q: %w", folder, err)
		}
		return "", 0, nil // the parent is not there: neither is the path
	}
	m, _ := v.(map[string]any)
	for _, e := range rows(m["entries"]) {
		if str(e["path"]) == rel {
			return str(e["kind"]), num(e["size"]), nil
		}
	}
	return "", 0, nil
}

func (f *filedirDev) fileOp(ctx context.Context, method string, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	call := func(tool string, args map[string]any) (RawResult, error) {
		v, err := f.m.callPlain(ctx, tool, args)
		if err != nil {
			return res, fmt.Errorf("%s: %w", tool, err)
		}
		j, _ := json.Marshal(Redact(v))
		res.Applied, res.Answer = true, rawTrunc(j)
		return res, nil
	}
	switch method {
	case "EMPTY-TRASH", "TRASH-RESTORE":
		folder, err := splitFolderOnly(r.Path)
		if err != nil {
			return res, err
		}
		if method == "EMPTY-TRASH" {
			if dry {
				v, err := f.m.callPlain(ctx, "files_trash", map[string]any{"folder": folder})
				if err != nil {
					return res, fmt.Errorf("files_trash: %w", err)
				}
				m, _ := v.(map[string]any)
				res.Note = fmt.Sprintf("would remove the %d file(s), %d bytes, in the trash of %s on the node that answers, for good; nothing was removed", num(m["files"]), num(m["bytes"]), folder)
				return res, nil
			}
			out, err := call("files_trash_empty", map[string]any{"folder": folder, "confirm": true})
			out.Note = "removed for good, on the node that answered; each node keeps its own trash"
			return out, err
		}
		when, name, ok := strings.Cut(strings.TrimSpace(r.Body), " ")
		name = strings.TrimSpace(name)
		if !ok || name == "" || !trashWhenRE.MatchString(when) {
			return res, errors.New(`body: "WHEN NAME" as show trash lists them, e.g. 20261123-182509 keep.txt`)
		}
		if dry {
			res.Note = fmt.Sprintf("would put %s of the deletion %s back in %s; nothing was changed", name, when, folder)
			return res, nil
		}
		return call("files_trash_restore", map[string]any{"folder": folder, "when": when, "name": name})
	}
	folder, rel, err := splitFilePath(r.Path)
	if err != nil {
		return res, err
	}
	switch method {
	case "MKDIR":
		if dry {
			res.Note = fmt.Sprintf("would make the folder %s:%s (and the ones on the way); nothing was made", folder, rel)
			return res, nil
		}
		return call("files_mkdir", map[string]any{"folder": folder, "path": rel})
	case "DELETE":
		kind, size, err := f.kindOf(ctx, folder, rel)
		if err != nil {
			return res, err
		}
		if kind == "" {
			return res, fmt.Errorf("path: %s:%s is not there", folder, rel)
		}
		if dry {
			res.Note = fmt.Sprintf("would delete the %s %s:%s (%d bytes); it goes to the folder's trash on the node that answers; nothing was deleted", kind, folder, rel, size)
			return res, nil
		}
		out, err := call("files_delete", map[string]any{"folder": folder, "path": rel})
		out.Note = "kept in the folder's trash for 30 days on the node that answered (show trash, TRASH-RESTORE, EMPTY-TRASH)"
		return out, err
	}
	// MOVE, RENAME, COPY
	to, toFolder, unique := strings.TrimSpace(r.Body), "", false
	if strings.HasPrefix(to, "{") {
		var j struct {
			To       string `json:"to"`
			ToFolder string `json:"to_folder"`
			Unique   bool   `json:"unique"`
		}
		if json.Unmarshal([]byte(to), &j) != nil {
			return res, errors.New(`body: the new place, or {"to": "...", "to_folder": "...", "unique": true}`)
		}
		to, toFolder, unique = j.To, j.ToFolder, j.Unique
	} else if i := strings.Index(to, ":"); i > 0 && filedirFolderRE.MatchString(to[:i]) {
		toFolder, to = to[:i], to[i+1:]
	}
	if toFolder != "" && !filedirFolderRE.MatchString(toFolder) {
		return res, fmt.Errorf("body: %q is not a folder name", toFolder)
	}
	if err := checkFilePath(to); err != nil {
		return res, fmt.Errorf("body: the new place: %w", err)
	}
	kind, size, err := f.kindOf(ctx, folder, rel)
	if err != nil {
		return res, err
	}
	if kind == "" {
		return res, fmt.Errorf("path: %s:%s is not there", folder, rel)
	}
	tool, verb := "files_copy", "copy"
	if method != "COPY" {
		tool, verb = "files_move", "move"
	}
	dest := folder
	if toFolder != "" {
		dest = toFolder
	}
	if dry {
		note := fmt.Sprintf("would %s the %s %s:%s (%d bytes) to %s:%s", verb, kind, folder, rel, size, dest, to)
		if k, _, _ := f.kindOf(ctx, dest, to); k != "" {
			if unique {
				note += fmt.Sprintf("; that name is taken, so a free one (\"name copy\") would be used")
			} else {
				note += fmt.Sprintf("; but that name is taken (a %s), which is refused unless unique is true", k)
			}
		}
		res.Note = note + "; nothing was changed"
		return res, nil
	}
	args := map[string]any{"folder": folder, "path": rel, "to": to}
	if toFolder != "" {
		args["to_folder"] = toFolder
	}
	if unique {
		args["unique"] = true
	}
	return call(tool, args)
}

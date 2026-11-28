package web

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Users: the local accounts that may sign in to the web GUI, which are the
// members of the GUI group (web.group, "netdir" by default).  They are managed
// with the standard shadow-utils tools (useradd, usermod, userdel, chpasswd),
// so PAM and the operating system stay the one source of truth.  New accounts
// have no shell and no home directory: they exist only to sign in here.
//
// Accounts are per node (they are operating-system accounts); in a cluster the
// Node menu picks the node whose accounts you manage.  Passwords never appear
// in a command line: they go to chpasswd on its standard input.

// UserInfo is one account.
type UserInfo struct {
	Name     string `json:"name"`
	ReadOnly bool   `json:"read_only,omitempty"` // in the read-only group only: may look, not change
	Expires  int64  `json:"expires"`             // Unix seconds, 0 = never
	Expired  bool   `json:"expired"`             // the operating system refuses it now
}

// UsersView is what the Users page shows.
type UsersView struct {
	Group string `json:"group"`
	// ReadGroup is the local read-only group the page manages; empty when the read-only setting is empty.
	ReadGroup string     `json:"read_group"`
	Users     []UserInfo `json:"users"`
	// Others are the local accounts that could be added to the group (people, not system accounts).
	Others []string `json:"others"`
}

var UsersGroupFile = "/etc/group"

var UsersPasswdFile = "/etc/passwd"

var UsersShadowFile = "/etc/shadow"

var NologinShells = []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}

var UsersNow = time.Now

// validUserName is deliberately stricter than useradd: lower-case letters,
// digits, "_" and "-", 1-32 characters, starting with a letter or "_".
func ValidUserName(u string) bool {
	if u == "" || len(u) > 32 {
		return false
	}
	for i, c := range []byte(u) {
		switch {
		case c >= 'a' && c <= 'z', c == '_':
		case (c >= '0' && c <= '9' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// validAccountName is what the group page accepts for an account that already exists, which may come from a directory
// (sssd: Active Directory, LDAP): upper-case letters, "." "@" and "\\" are common there.  It never holds what would break
// a line of /etc/group.
func ValidAccountName(u string) bool {
	if u == "" || len(u) > 64 {
		return false
	}
	for i, c := range []byte(u) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case (c >= '0' && c <= '9' || c == '-' || c == '.' || c == '@' || c == '\\') && i > 0:
		default:
			return false
		}
	}
	return true
}

// usersLookup says whether the name system (NSS: files, sssd, ...) knows the account (replaceable in tests).
var UsersLookup = func(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

func FirstLocalGroup(list []string) string {
	if b, err := os.ReadFile(UsersGroupFile); err == nil {
		for _, g := range list { // keep the order of the setting when several are local
			for _, l := range strings.Split(string(b), "\n") {
				if name, _, _ := strings.Cut(l, ":"); name == g {
					return g
				}
			}
		}
	}
	return list[0]
}

// groupMembers lists the members of the group: the names on its line in
// /etc/group, and accounts whose primary group it is.
func GroupMembers(group string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if n = strings.TrimSpace(n); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	gid := ""
	if b, err := os.ReadFile(UsersGroupFile); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) >= 4 && f[0] == group {
				gid = f[2]
				for _, n := range strings.Split(f[3], ",") {
					add(n)
				}
			}
		}
	}
	if gid != "" {
		if b, err := os.ReadFile(UsersPasswdFile); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if f := strings.Split(l, ":"); len(f) >= 7 && f[3] == gid {
					add(f[0])
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// userExists: the account is known to this machine, in /etc/passwd or in a directory.
func UserExists(name string) bool { return LocalAccount(name) || UsersLookup(name) }

// localAccount: the account is in /etc/passwd, so the tools of shadow-utils can manage it.
func LocalAccount(name string) bool {
	b, err := os.ReadFile(UsersPasswdFile)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.SplitN(l, ":", 2)[0] == name {
			return true
		}
	}
	return false
}

// otherAccounts lists the accounts on this machine that are not in the group and could be: ordinary accounts (a user
// id from 1000 up, not "nobody"), by name.  A system account can still be added by typing its name.
func OtherAccounts(groups ...string) []string {
	in := map[string]bool{"root": true}
	for _, g := range groups {
		if g == "" {
			continue
		}
		for _, n := range GroupMembers(g) {
			in[n] = true
		}
	}
	out := []string{}
	b, err := os.ReadFile(UsersPasswdFile)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 || in[f[0]] || !ValidUserName(f[0]) {
			continue
		}
		if uid, err := strconv.Atoi(f[2]); err != nil || uid < 1000 || uid >= 65534 {
			continue
		}
		out = append(out, f[0])
	}
	sort.Strings(out)
	return out
}

// listedInGroup says whether name is named on the group's line in /etc/group (as opposed to being a member only
// because the group is its primary group, which gpasswd cannot undo).
func ListedInGroup(group, name string) bool {
	b, err := os.ReadFile(UsersGroupFile)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Split(l, ":"); len(f) >= 4 && f[0] == group {
			for _, n := range strings.Split(f[3], ",") {
				if strings.TrimSpace(n) == name {
					return true
				}
			}
		}
	}
	return false
}

func UserDate(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02")
}

func CheckPassword(p string, min int) error {
	switch {
	case p == "":
		return errors.New("a password is required")
	case len(p) > 256:
		return errors.New("the password is too long")
	case strings.ContainsAny(p, "\r\n"):
		return errors.New("the password may not contain a line break")
	case utf8.RuneCountInString(p) < min:
		return fmt.Errorf("the password must have at least %d characters", min)
	}
	return nil
}

// expiredNow: an expiry date (Unix seconds, 0 = none) that has already passed.
func ExpiredNow(expires int64) bool { return expires > 0 && expires <= UsersNow().Unix() }

func InList(list []string, name string) bool {
	for _, n := range list {
		if n == name && n != "root" {
			return true
		}
	}
	return false
}

var CryptHashRe = regexp.MustCompile(`^\$[0-9a-z]+\$[A-Za-z0-9./$,=+-]{4,200}$`)

// shadowHash is the stored password hash of an account.
func ShadowHash(name string) string {
	b, err := os.ReadFile(UsersShadowFile)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Split(l, ":"); len(f) >= 2 && f[0] == name {
			return f[1]
		}
	}
	return ""
}

// localExpiry is the account's expiry in Unix seconds, 0 for none.
func LocalExpiry(name string) int64 {
	b, err := os.ReadFile(UsersShadowFile)
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Split(l, ":"); len(f) >= 8 && f[0] == name && f[7] != "" {
			if d, err := strconv.ParseInt(f[7], 10, 64); err == nil && d > 0 {
				return d * 86400
			}
		}
	}
	return 0
}

func AccessWord(ro bool) string {
	if ro {
		return "read-only"
	}
	return "full access"
}

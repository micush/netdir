package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"netdir/internal/cluster"
	"netdir/internal/core"
	"netdir/internal/web"
)

// guiGroup is the local group the Users page manages: the first of the login groups (a comma-separated list; the
// later ones may be directory groups, which are managed in the directory) that is in /etc/group, else the first one.
func (m *Mgmt) guiGroup() string {
	list := web.SplitGroups("netdir")
	if p := m.webPolicy.Load(); p != nil && p.Group != "" {
		list = web.SplitGroups(p.Group)
	}
	if len(list) == 0 {
		return "netdir"
	}
	return web.FirstLocalGroup(list)
}

// roGroup is the local group the Users page keeps the read-only accounts in: the first of web.read_group that is in
// /etc/group, else the first one; empty when the setting is empty.
func (m *Mgmt) roGroup() string {
	if p := m.webPolicy.Load(); p != nil {
		if list := web.SplitGroups(p.ReadGroup); len(list) > 0 {
			return web.FirstLocalGroup(list)
		}
	}
	return ""
}

// UsersList returns the group's accounts with their expiry dates.
func (m *Mgmt) UsersList() web.UsersView {
	g := m.guiGroup()
	exp := map[string]int64{}
	if b, err := os.ReadFile(web.UsersShadowFile); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Split(l, ":"); len(f) >= 8 && f[7] != "" {
				if d, err := strconv.ParseInt(f[7], 10, 64); err == nil && d >= 0 {
					exp[f[0]] = d
				}
			}
		}
	}
	today := web.UsersNow().Unix() / 86400
	rg := m.roGroup()
	v := web.UsersView{Group: g, ReadGroup: rg, Users: []web.UserInfo{}, Others: web.OtherAccounts(g, rg)}
	full := map[string]bool{}
	for _, n := range web.GroupMembers(g) {
		full[n] = true
	}
	names := web.GroupMembers(g)
	if rg != "" {
		for _, n := range web.GroupMembers(rg) {
			if !full[n] {
				names = append(names, n)
			}
		}
		sort.Strings(names)
	}
	for _, n := range names {
		if n == "root" {
			continue // never listed, never managed
		}
		u := web.UserInfo{Name: n, ReadOnly: !full[n]}
		if d, ok := exp[n]; ok {
			u.Expires = d * 86400
			u.Expired = today >= d
		}
		v.Users = append(v.Users, u)
	}
	return v
}

// checkPassword applies the rules of the Users page, with the minimum length of the web settings.
func (m *Mgmt) checkPassword(p string) error {
	min := core.DefaultMinPassword
	if pol := m.webPolicy.Load(); pol != nil {
		min = pol.MinPassword()
	}
	return web.CheckPassword(p, min)
}

// endUserSessions signs name out of every browser session on this node.  It is called when the account's
// password changes, when it is deleted and when it has expired: a session that was open must not outlive that.
func (m *Mgmt) endUserSessions(name string) {
	if fn := m.endSessions.Load(); fn != nil {
		(*fn)(name)
	}
}

func (m *Mgmt) setUserPassword(name, password string) error {
	// chpasswd reads "name:password" lines; a line break would add a second
	// one (checked above), and the name cannot contain ":".
	if out, err := core.UsersRun(name+":"+password+"\n", "chpasswd"); err != nil {
		return fmt.Errorf("chpasswd failed: %s", core.FirstNonEmpty(out, err.Error()))
	}
	return nil
}

// memberOf: the account is in the login group or in the read-only group (root is never one).
func (m *Mgmt) memberOf(name string) bool { return m.fullMember(name) || m.roMember(name) }

// fullMember: in the login group, so it can change things.
func (m *Mgmt) fullMember(name string) bool { return web.InList(web.GroupMembers(m.guiGroup()), name) }

// roMember: in the read-only group and not in the login group.
func (m *Mgmt) roMember(name string) bool {
	rg := m.roGroup()
	return rg != "" && !m.fullMember(name) && web.InList(web.GroupMembers(rg), name)
}

// usersFan sends a change to the other members and returns the text to show.
func (m *Mgmt) usersFan(msg core.UsersMsg, done string) (string, bool) {
	if m.cl == nil || !m.cl.Enabled() {
		return done, false
	}
	peers := m.cl.Snapshot().Peers
	if len(peers) == 0 {
		return done, false
	}
	type res struct {
		addr string
		err  error
	}
	ch := make(chan res, len(peers))
	for _, p := range peers {
		go func(p core.ClusterPeer) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			ch <- res{p.Addr, m.cl.Call(ctx, p, "POST", "/cluster/users", msg, nil, 20*time.Second)}
		}(p)
	}
	var bad []string
	for range peers {
		if r := <-ch; r.err != nil {
			var pe *cluster.PeerError
			if errors.As(r.err, &pe) {
				bad = append(bad, r.addr+": "+pe.Msg)
			} else {
				bad = append(bad, r.addr+": not reachable")
			}
		}
	}
	sort.Strings(bad)
	if len(bad) == 0 {
		return fmt.Sprintf("%s On all %d nodes.", done, len(peers)+1), false
	}
	return fmt.Sprintf("%s Applied here and on %d of %d other node(s); NOT applied on: %s", done, len(peers)-len(bad), len(peers), strings.Join(bad, "; ")), true
}

// usersPeer applies a change that another member sent.
func (m *Mgmt) UsersPeer(msg core.UsersMsg, by string) error {
	name := msg.Name
	okName := web.ValidUserName(name)
	if msg.Op == "grant" || msg.Op == "revoke" || msg.Op == "access" {
		okName = web.ValidAccountName(name)
	}
	if !okName || name == "root" {
		return errors.New("invalid user name")
	}
	switch msg.Op {
	case "apply", "password":
		if !web.CryptHashRe.MatchString(msg.Hash) {
			return errors.New("invalid password hash")
		}
		switch {
		case m.memberOf(name):
		case web.UserExists(name):
			return fmt.Errorf("an account called %q exists here and is not in the %s group", name, m.guiGroup())
		case msg.Op == "password":
			return fmt.Errorf("%q is not a member of the %s group here", name, m.guiGroup())
		default:
			if err := m.createUser(name, msg.Expires, msg.RO); err != nil {
				return err
			}
		}
		if out, err := core.UsersRun(name+":"+msg.Hash+"\n", "chpasswd", "-e"); err != nil {
			return fmt.Errorf("chpasswd failed: %s", core.FirstNonEmpty(out, err.Error()))
		}
		if msg.Op == "apply" {
			if err := m.setExpiry(name, msg.Expires); err != nil {
				return err
			}
		}
		m.endUserSessions(name) // a changed password ends the sessions that were signed in with the old one
		core.Infof("users: %s set up account %q here", by, name)
	case "grant":
		switch {
		case m.memberOf(name):
			return nil
		case web.UserExists(name):
			if err := m.addToGroup(name, msg.RO); err != nil {
				return err
			}
		case web.CryptHashRe.MatchString(msg.Hash): // not here yet: made the same as on the node that added it
			if err := m.createUser(name, msg.Expires, msg.RO); err != nil {
				return err
			}
			if out, err := core.UsersRun(name+":"+msg.Hash+"\n", "chpasswd", "-e"); err != nil {
				return fmt.Errorf("chpasswd failed: %s", core.FirstNonEmpty(out, err.Error()))
			}
		default:
			return fmt.Errorf("there is no account %q here, and the one it was added from has no password to copy", name)
		}
		core.Infof("users: %s added %q to the %s group here", by, name, m.guiGroup())
	case "revoke":
		if !m.memberOf(name) {
			return nil // already out
		}
		if m.fullMember(name) && m.countMembers() <= 1 {
			return errors.New("that is the last account that can sign in on this node")
		}
		if err := m.removeFromGroups(name); err != nil {
			return err
		}
		m.endUserSessions(name)
		core.Infof("users: %s removed %q from the %s group here", by, name, m.guiGroup())
	case "access":
		if !m.memberOf(name) {
			return fmt.Errorf("%q is not a member of the %s group here", name, m.guiGroup())
		}
		if m.roMember(name) == msg.RO {
			return nil // already so
		}
		if err := m.setAccess(name, msg.RO); err != nil {
			return err
		}
		m.endUserSessions(name)
		core.Infof("users: %s made %q %s here", by, name, web.AccessWord(msg.RO))
	case "expiry":
		if err := m.requireMember(name); err != nil {
			return err
		}
		if err := m.setExpiry(name, msg.Expires); err != nil {
			return err
		}
		if web.ExpiredNow(msg.Expires) {
			m.endUserSessions(name)
		}
		core.Infof("users: %s changed the expiry of %q here", by, name)
	case "delete":
		if !web.UserExists(name) {
			return nil // already gone
		}
		if err := m.requireMember(name); err != nil {
			return err
		}
		if m.fullMember(name) && m.countMembers() <= 1 {
			return errors.New("that is the last account that can sign in on this node")
		}
		if out, err := core.UsersRun("", "userdel", name); err != nil {
			return fmt.Errorf("userdel failed: %s", core.FirstNonEmpty(out, err.Error()))
		}
		m.endUserSessions(name)
		core.Infof("users: %s deleted account %q here", by, name)
	default:
		return errors.New("unknown request")
	}
	return nil
}

func (m *Mgmt) createUser(name string, expires int64, ro bool) error {
	g := m.guiGroup()
	if ro {
		if g = m.roGroup(); g == "" {
			return errors.New("there is no read-only group: set Read-only groups under Configure ▸ Web first")
		}
	}
	shell := "/bin/false"
	for _, s := range web.NologinShells {
		if _, err := os.Stat(s); err == nil {
			shell = s
			break
		}
	}
	args := []string{"--no-create-home", "--home-dir", "/nonexistent", "--shell", shell, "--gid", g}
	if expires > 0 {
		args = append(args, "--expiredate", web.UserDate(expires))
	}
	args = append(args, name)
	if out, err := core.UsersRun("", "useradd", args...); err != nil {
		return fmt.Errorf("useradd failed: %s", core.FirstNonEmpty(out, err.Error()))
	}
	return nil
}

func (m *Mgmt) addToGroup(name string, ro bool) error {
	g := m.guiGroup()
	if ro {
		if g = m.roGroup(); g == "" {
			return errors.New("there is no read-only group: set Read-only groups under Configure ▸ Web first")
		}
	}
	if !web.LocalAccount(name) { // a directory account: usermod does not know it, gpasswd does
		if out, err := core.UsersRun("", "gpasswd", "-a", name, g); err != nil {
			return fmt.Errorf("gpasswd failed: %s", core.FirstNonEmpty(out, err.Error()))
		}
		return nil
	}
	if out, err := core.UsersRun("", "usermod", "-aG", g, name); err != nil {
		return fmt.Errorf("usermod failed: %s", core.FirstNonEmpty(out, err.Error()))
	}
	return nil
}

// removeFromGroups takes the account out of the login group and the read-only group, whichever it is listed in.
func (m *Mgmt) removeFromGroups(name string) error {
	for _, g := range []string{m.guiGroup(), m.roGroup()} {
		if g == "" || !web.InList(web.GroupMembers(g), name) {
			continue
		}
		if !web.ListedInGroup(g, name) {
			return fmt.Errorf("%q is in the %s group because it is that account's primary group; change that with usermod -g, or delete the account", name, g)
		}
		if out, err := core.UsersRun("", "gpasswd", "-d", name, g); err != nil {
			return fmt.Errorf("gpasswd failed: %s", core.FirstNonEmpty(out, err.Error()))
		}
	}
	return nil
}

// setAccess moves an account between the login group and the read-only group.  An account that has one of them as
// its primary group cannot be moved (gpasswd cannot take it out of that one).
func (m *Mgmt) setAccess(name string, ro bool) error {
	if err := m.removeFromGroups(name); err != nil {
		return err
	}
	if err := m.addToGroup(name, ro); err != nil {
		m.addToGroup(name, !ro) // put it back where it was
		return err
	}
	return nil
}

func (m *Mgmt) setExpiry(name string, expires int64) error {
	arg := ""
	if expires > 0 {
		arg = web.UserDate(expires)
	}
	if out, err := core.UsersRun("", "usermod", "--expiredate", arg, name); err != nil {
		return fmt.Errorf("usermod failed: %s", core.FirstNonEmpty(out, err.Error()))
	}
	return nil
}

// UserAdd creates a sign-in-only account in the GUI group on every node.
// expires is Unix seconds, 0 for none.
func (m *Mgmt) UserAdd(name, password string, expires int64, readOnly bool, actor string) (string, bool, error) {
	if !web.ValidUserName(name) || name == "root" {
		return "", false, errors.New("a user name is 1-32 characters: lower-case letters, digits, _ or -, starting with a letter or _")
	}
	if err := m.checkPassword(password); err != nil {
		return "", false, err
	}
	if web.UserExists(name) {
		return "", false, fmt.Errorf("an account called %q already exists on this machine", name)
	}
	if err := m.createUser(name, expires, readOnly); err != nil {
		return "", false, err
	}
	if err := m.setUserPassword(name, password); err != nil {
		core.UsersRun("", "userdel", name) // do not leave an account without a password
		return "", false, err
	}
	core.Infof("users: %s created account %q in group %q", actor, name, m.guiGroup())
	msg, partial := m.usersFan(core.UsersMsg{Op: "apply", Name: name, Hash: web.ShadowHash(name), Expires: expires, By: actor, RO: readOnly}, "User "+name+" added"+map[bool]string{true: " (read-only)", false: ""}[readOnly]+".")
	return msg, partial, nil
}

// UserGrant puts an account that already exists on this machine into the GUI group, so it can sign in with the
// password it already has.  On the other nodes the account is added to the group when it exists there and created
// with the same password hash when it does not.
func (m *Mgmt) UserGrant(name string, readOnly bool, actor string) (string, bool, error) {
	if !web.ValidAccountName(name) || name == "root" {
		return "", false, errors.New("invalid user name")
	}
	if !web.UserExists(name) {
		return "", false, fmt.Errorf("there is no account called %q on this machine; use Add user to create a local one", name)
	}
	if m.memberOf(name) {
		return "", false, fmt.Errorf("%q is already in the %s group (change its access on its own page)", name, m.guiGroup())
	}
	if err := m.addToGroup(name, readOnly); err != nil {
		return "", false, err
	}
	core.Infof("users: %s added the existing account %q to the %s group", actor, name, m.guiGroup())
	hash := web.ShadowHash(name)
	if !web.CryptHashRe.MatchString(hash) {
		hash = ""
	}
	done := "User " + name + " added to the group."
	if hash == "" {
		done += " It has no password yet: set one with Password."
	}
	msg, partial := m.usersFan(core.UsersMsg{Op: "grant", Name: name, Hash: hash, Expires: web.LocalExpiry(name), By: actor, RO: readOnly}, done)
	return msg, partial, nil
}

// UserRevoke takes an account out of the GUI group without deleting it.  The signed-in user and the last member
// cannot be taken out.
func (m *Mgmt) UserRevoke(name, actor string) (string, bool, error) {
	if err := m.requireMember(name); err != nil {
		return "", false, err
	}
	if name == actor {
		return "", false, errors.New("you cannot remove the account you are signed in as")
	}
	if m.fullMember(name) && m.countMembers() <= 1 {
		return "", false, errors.New("that is the last account that can sign in; add another one first")
	}
	if err := m.removeFromGroups(name); err != nil {
		return "", false, err
	}
	m.endUserSessions(name)
	core.Infof("users: %s removed %q from the %s group", actor, name, m.guiGroup())
	msg, partial := m.usersFan(core.UsersMsg{Op: "revoke", Name: name, By: actor}, "User "+name+" removed from the group; the account is kept.")
	return msg, partial, nil
}

// UserPassword sets a member's password on every node.
func (m *Mgmt) UserPassword(name, password, actor string) (string, bool, error) {
	if err := m.requireLocalMember(name); err != nil {
		return "", false, err
	}
	if err := m.checkPassword(password); err != nil {
		return "", false, err
	}
	if err := m.setUserPassword(name, password); err != nil {
		return "", false, err
	}
	m.endUserSessions(name)
	core.Infof("users: %s changed the password of %q", actor, name)
	msg, partial := m.usersFan(core.UsersMsg{Op: "apply", Name: name, Hash: web.ShadowHash(name), Expires: web.LocalExpiry(name), By: actor}, "Password changed for "+name+".")
	return msg, partial, nil
}

// UserExpiry sets (or, with 0, clears) the date an account stops working, on every node.
func (m *Mgmt) UserExpiry(name string, expires int64, actor string) (string, bool, error) {
	if err := m.requireLocalMember(name); err != nil {
		return "", false, err
	}
	if err := m.setExpiry(name, expires); err != nil {
		return "", false, err
	}
	what := name + " no longer expires."
	if expires > 0 {
		what = name + " expires " + web.UserDate(expires) + "."
	}
	if web.ExpiredNow(expires) {
		m.endUserSessions(name)
	}
	core.Infof("users: %s set the expiry of %q to %s", actor, name, core.FirstNonEmpty(web.UserDate(expires), "never"))
	msg, partial := m.usersFan(core.UsersMsg{Op: "expiry", Name: name, Expires: expires, By: actor}, what)
	return msg, partial, nil
}

// UserDelete removes an account from every node.  The signed-in user and the
// last member of the group cannot be removed (nobody could sign in afterwards).
func (m *Mgmt) UserDelete(name, actor string) (string, bool, error) {
	if web.ValidUserName(name) && name != "root" && !web.UserExists(name) {
		// not here (perhaps a node that was down missed the delete): still tell the others
		msg, partial := m.usersFan(core.UsersMsg{Op: "delete", Name: name, By: actor}, "There is no account "+name+" on this node.")
		return msg, partial, nil
	}
	if err := m.requireLocalMember(name); err != nil {
		return "", false, err
	}
	if name == actor {
		return "", false, errors.New("you cannot delete the account you are signed in as")
	}
	if m.fullMember(name) && m.countMembers() <= 1 {
		return "", false, errors.New("that is the last account that can sign in; add another one first")
	}
	if out, err := core.UsersRun("", "userdel", name); err != nil {
		return "", false, fmt.Errorf("userdel failed: %s", core.FirstNonEmpty(out, err.Error()))
	}
	m.endUserSessions(name)
	core.Infof("users: %s deleted account %q", actor, name)
	msg, partial := m.usersFan(core.UsersMsg{Op: "delete", Name: name, By: actor}, "User "+name+" deleted.")
	return msg, partial, nil
}

// countMembers is the number of listed accounts (root is not one).
func (m *Mgmt) countMembers() int {
	n := 0
	for _, u := range web.GroupMembers(m.guiGroup()) {
		if u != "root" {
			n++
		}
	}
	return n
}

// requireLocalMember is requireMember for a change that only a local account can take: a password or an expiry date, or
// deleting the account.  A directory account's are kept in the directory.
func (m *Mgmt) requireLocalMember(name string) error {
	if err := m.requireMember(name); err != nil {
		return err
	}
	if !web.LocalAccount(name) {
		return fmt.Errorf("%q is a directory account (not in /etc/passwd): its password and expiry are kept in the directory; remove it from the group to stop it signing in", name)
	}
	return nil
}

func (m *Mgmt) requireMember(name string) error {
	if !web.ValidAccountName(name) {
		return errors.New("invalid user name")
	}
	if !m.memberOf(name) {
		return fmt.Errorf("%q is not a member of the %s group", name, m.guiGroup())
	}
	return nil
}

// ── joining a cluster ────────────────────────────────────────────────────────

// usersExport is every account that can sign in here, as the changes that would
// create it elsewhere (accounts with no usable password hash are left out).
func (m *Mgmt) UsersExport() []core.UsersMsg {
	out := []core.UsersMsg{}
	names := web.GroupMembers(m.guiGroup())
	if rg := m.roGroup(); rg != "" {
		names = append(names, web.GroupMembers(rg)...)
	}
	done := map[string]bool{}
	for _, n := range names {
		if n == "root" || !web.ValidUserName(n) || done[n] {
			continue
		}
		done[n] = true
		if h := web.ShadowHash(n); web.CryptHashRe.MatchString(h) {
			out = append(out, core.UsersMsg{Op: "apply", Name: n, Hash: h, Expires: web.LocalExpiry(n), RO: m.roMember(n)})
		}
	}
	return out
}

// usersSeed creates the accounts a cluster already has on a node that has just
// joined.  An account that already exists here, in the group or not, is left
// exactly as it is.  It returns how many were created and how many were skipped.
func (m *Mgmt) usersSeed(list []core.UsersMsg, from string) (added, skipped int) {
	for _, u := range list {
		if u.Op != "apply" || !web.ValidUserName(u.Name) || u.Name == "root" || web.UserExists(u.Name) {
			skipped++
			continue
		}
		if err := m.UsersPeer(u, "the cluster ("+from+") on joining"); err != nil {
			core.Warnf("users: could not create %q from the cluster: %v", u.Name, err)
			skipped++
			continue
		}
		added++
	}
	return added, skipped
}

// usersPull fetches the accounts of a member and seeds them here.  A failure is
// only logged: the node is in the cluster either way, and re-setting a password
// on the Users page sends the account to every node.
func (m *Mgmt) UsersPull(ctx context.Context, from core.ClusterPeer) {
	var res struct {
		Users []core.UsersMsg `json:"users"`
	}
	if err := m.cl.Call(ctx, from, "POST", "/cluster/users", core.UsersMsg{Op: "list"}, &res, 20*time.Second); err != nil {
		core.Warnf("users: could not get the accounts from %s: %v (the users of that cluster were not copied)", from.Addr, err)
		return
	}
	added, skipped := m.usersSeed(res.Users, from.Addr)
	core.Infof("users: copied %d account(s) from %s on joining (%d already existed or were refused)", added, from.Addr, skipped)
}

// UserAccess moves a member between full access and read-only, on every node.  The signed-in user cannot move
// themselves, and the last full-access account cannot be made read-only.
func (m *Mgmt) UserAccess(name string, readOnly bool, actor string) (string, bool, error) {
	if err := m.requireMember(name); err != nil {
		return "", false, err
	}
	if m.roMember(name) == readOnly {
		return "", false, fmt.Errorf("%q already has %s", name, web.AccessWord(readOnly))
	}
	if readOnly {
		if name == actor {
			return "", false, errors.New("you cannot make the account you are signed in as read-only")
		}
		if m.countMembers() <= 1 {
			return "", false, errors.New("that is the last account that can make changes; add another one first")
		}
	}
	if err := m.setAccess(name, readOnly); err != nil {
		return "", false, err
	}
	m.endUserSessions(name)
	core.Infof("users: %s made %q %s", actor, name, web.AccessWord(readOnly))
	msg, partial := m.usersFan(core.UsersMsg{Op: "access", Name: name, By: actor, RO: readOnly}, name+" now has "+web.AccessWord(readOnly)+".")
	return msg, partial, nil
}

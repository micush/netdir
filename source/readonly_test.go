package main

// roAuth: alice is in the login group, bob only in the read-only group "view".
type roAuth struct{ fakeAuth }

func (a *roAuth) InGroup(user, group string) (bool, error) {
	switch group {
	case "netdir,netdir-users":
		return user == "alice", nil
	case "view":
		return user == "bob", nil
	}
	return false, nil
}

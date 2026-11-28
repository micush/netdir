//go:build !(linux && cgo)

package core

import (
	"errors"
)

// Built without cgo (e.g. cross-compiled): there is no PAM backend, so the web
// GUI refuses to start.  It fails closed — it never falls back to "no auth".
const PamAvailable = false

func PamAuthenticate(service, user, password string) error {
	return errors.New("this build has no PAM support (needs a native cgo build with libpam0g-dev)")
}

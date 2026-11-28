package core

import (
	"regexp"
	"strings"
)

var CapNameRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func HostnameShort() (string, error) {
	h := SelfHost()
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return CapNameRe.ReplaceAllString(h, "_"), nil
}

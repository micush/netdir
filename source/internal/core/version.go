package core

import (
	"strings"
)

// embeddedVersion is source/VERSION, the single source of truth, compiled into the binary (embed.go) so `netdir --version`
// reports the build's release.
var EmbeddedVersion string

func Version() string { return strings.TrimSpace(EmbeddedVersion) }

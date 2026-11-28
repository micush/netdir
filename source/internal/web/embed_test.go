package web

import (
	"os"

	"netdir/internal/core"
)

// The binary gets VERSION and webui/ from the main package (embed.go); the tests of this package read them from the source tree.
func init() {
	if b, err := os.ReadFile("../../VERSION"); err == nil {
		core.EmbeddedVersion = string(b)
	}
	WebFS = os.DirFS("../..")
}

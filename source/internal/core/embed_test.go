package core

import (
	"os"
)

// The binary gets VERSION and webui/ from the main package (embed.go); the tests of this package read them from the source tree.
func init() {
	if b, err := os.ReadFile("../../VERSION"); err == nil {
		EmbeddedVersion = string(b)
	}
}

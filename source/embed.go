package main

import (
	"embed"

	"netdir/internal/core"
	"netdir/internal/web"
)

// The files the binary carries, which go:embed can only take from this directory: the GUI (webui/) and the release number
// (VERSION).  They are handed to the code that uses them before anything runs.

//go:embed webui
var embeddedUI embed.FS

//go:embed VERSION
var embeddedVersionFile string

func init() {
	web.WebFS = embeddedUI
	core.EmbeddedVersion = embeddedVersionFile
}

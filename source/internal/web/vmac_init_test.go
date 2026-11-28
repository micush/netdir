package web

import (
	"netdir/internal/core"
)

func init() { core.VmacAutoOff.Store(true) }

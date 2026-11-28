package core

import (
	"strconv"
)

// pauseTestConfig is a one-gateway configuration, for the pause tests.
func pauseTestConfig() *DaemonConfig {
	dc := NewDaemonConfig()
	dc.Groups = []GroupConfig{DefaultGroup()}
	if err := dc.Validate(); err != nil {
		panic(err)
	}
	return dc
}

func fmtN(i int) string { return strconv.Itoa(i) }

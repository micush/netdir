package core

import (
	"testing"
)

func TestPauseScopeEffectiveLiveShared(t *testing.T) {
	dc := pauseTestConfig()
	dc.Groups[0].Paused = true // this node only
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if !dc.Effective().Groups[0].Paused {
		t.Fatal("effective config lost the node-local pause")
	}
	// the node-local pause is never replicated; the shared one is
	if SharedOf(dc).Hash() != SharedOf(pauseTestConfig()).Hash() {
		t.Fatal("a node-local pause changed the shared hash")
	}
	dc.Groups[0].Paused = false
	dc.Groups[0].PausedAll = true
	if SharedOf(dc).Hash() == SharedOf(pauseTestConfig()).Hash() {
		t.Fatal("a pause on every node is not replicated")
	}
	if !dc.Effective().Groups[0].Paused {
		t.Fatal("a pause on every node does not pause this node")
	}
}

package main

import "testing"

func TestPauseScopeEffectiveLiveShared(t *testing.T) {
	dc := pauseTestConfig()
	dc.Groups[0].Paused = true // this node only
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if !dc.effective().Groups[0].Paused {
		t.Fatal("effective config lost the node-local pause")
	}
	// the node-local pause is never replicated; the shared one is
	if sharedOf(dc).hash() != sharedOf(pauseTestConfig()).hash() {
		t.Fatal("a node-local pause changed the shared hash")
	}
	dc.Groups[0].Paused = false
	dc.Groups[0].PausedAll = true
	if sharedOf(dc).hash() == sharedOf(pauseTestConfig()).hash() {
		t.Fatal("a pause on every node is not replicated")
	}
	if !dc.effective().Groups[0].Paused {
		t.Fatal("a pause on every node does not pause this node")
	}
}

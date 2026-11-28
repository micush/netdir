package main

import (
	"strings"
	"testing"
)

func TestTshootTarRoundTrip(t *testing.T) {
	in := map[string][]byte{"a/b.txt": []byte("one"), "README.txt": []byte("two"), "../evil": []byte("x")}
	tgz, err := tarFiles(in, "")
	if err != nil {
		t.Fatal(err)
	}
	out, err := untarFiles(tgz)
	if err != nil || string(out["a/b.txt"]) != "one" || string(out["README.txt"]) != "two" {
		t.Fatalf("%v %v", out, err)
	}
	if _, bad := out["../evil"]; bad || string(out["evil"]) != "x" {
		t.Fatalf("a name above the node's folder must be kept inside it: %v", out)
	}
}

func TestTshootNodeBundle(t *testing.T) {
	n := newTNode(t, "t1")
	tgz, err := n.mg.TshootNode(false, "tester")
	if err != nil {
		t.Fatal(err)
	}
	files, err := untarFiles(tgz)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"README.txt", "netdir/config.json", "netdir/cluster.json", "system/system.txt", "net/ip-addr.txt", "netdir/virtual-mac-tests.json", "netdir/goroutines.txt"} {
		if _, ok := files[want]; !ok {
			t.Errorf("%s is missing; have %d files", want, len(files))
		}
	}
	if g := string(files["netdir/goroutines.txt"]); !strings.Contains(g, "goroutine ") || !strings.Contains(g, "TestTshootNodeBundle") {
		t.Fatalf("the goroutine dump is missing or empty: %.200s", g)
	}
	if c := string(files["netdir/config.json"]); strings.Contains(c, `"key": "dgw"`) {
		t.Errorf("the gateway key is in the bundle: %s", c)
	}
	if !strings.Contains(string(files["README.txt"]), "secrets were removed") {
		t.Error("the README does not say what was removed")
	}
	// the same through the op (what the CLI calls)
	if _, err := n.mg.Op("tshoot.node", nil, "tester"); err != nil {
		t.Fatal(err)
	}
}

// Two clustered nodes: one bundle with a folder per node, and a node that cannot be reached has a note, not a failure.
func TestTshootClusterBundle(t *testing.T) {
	a, b := twoNodeCluster(t)
	withWeb(t, a)
	withWeb(t, b)
	tgz, err := a.mg.TshootCluster(false, "tester")
	if err != nil {
		t.Fatal(err)
	}
	files, err := untarFiles(tgz)
	if err != nil {
		t.Fatal(err)
	}
	var mine, theirs int
	for n := range files {
		switch {
		case strings.Contains(n, "-this-node/netdir/config.json"):
			mine++
		case strings.HasSuffix(n, "/netdir/config.json"):
			theirs++
		}
	}
	if mine != 1 || theirs != 1 || !strings.Contains(string(files["README.txt"]), "collected") {
		t.Fatalf("one folder per node expected: %d %d, files %d", mine, theirs, len(files))
	}
	// the other node answers 503 to the relay: noted, and this node's own bundle is still there
	b.mg.webH = nil
	tgz, err = a.mg.TshootCluster(false, "tester")
	if err != nil {
		t.Fatal(err)
	}
	files, _ = untarFiles(tgz)
	lost := false
	for n := range files {
		if strings.HasSuffix(n, "/NOT-COLLECTED.txt") {
			lost = true
		}
	}
	if !lost || !strings.Contains(string(files["README.txt"]), "NOT COLLECTED") {
		t.Fatalf("an unreachable node must be noted: %s", files["README.txt"])
	}
}

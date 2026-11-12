package device

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Entra: who a name is, as the directory said it, is kept for a short while, and a caller that changes the answer does not change the kept one.
func TestEntraLookupsAreKept(t *testing.T) {
	CacheFlush()
	st := &entraState{}
	drv := openEntra(t, entraStub(t, st), "S3CRET")
	l := bareDriver(drv).(DeviceUsers2)
	ctx := context.Background()
	a, err := l.DeviceUsers(ctx, "LAPTOP-ALICE")
	if err != nil || len(a) != 2 {
		t.Fatalf("%v %+v", err, a)
	}
	n := len(st.calls)
	a[0]["id"] = "changed"
	b, err := l.DeviceUsers(ctx, "laptop-alice")
	if err != nil || len(st.calls) != n || b[0]["id"] != aliceID {
		t.Errorf("the repeat went to Graph (%d new calls) or got the caller's change: %v %v", len(st.calls)-n, err, b[0]["id"])
	}
	CacheFlush()
	if _, err := l.DeviceUsers(ctx, "LAPTOP-ALICE"); err != nil || len(st.calls) == n {
		t.Errorf("after a flush Graph was not asked: %v", err)
	}
	// an error is not kept
	n = len(st.calls)
	for i := 0; i < 2; i++ {
		_, _ = l.DeviceUsers(ctx, "a'b")
	}
	if len(st.calls) != n {
		t.Error("a refused name reached Graph")
	}
}

type DeviceUsers2 interface {
	DeviceUsers(context.Context, string) ([]map[string]any, error)
}

// Meraki: the list of networks is kept, and a machine that was found is looked for in the networks it was found in first.
func TestMerakiClientMemory(t *testing.T) {
	merakiWait = 1
	CacheFlush()
	d, seen := merakiClientStub(t)
	drv, err := Open(d, Credential{Name: "k", Token: "KEY"})
	if err != nil {
		t.Fatal(err)
	}
	cr := bareDriver(drv).(ClientReporter)
	count := func(sub string) (n int) {
		for _, p := range *seen {
			if p == sub {
				n++
			}
		}
		return
	}
	q := ClientQuery{Users: []string{"jsmith"}}
	if _, err := cr.ClientReport(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if count("/organizations/1/networks") != 1 || count("/networks/L_2/clients") != 1 || count("/networks/L_4/clients") != 1 {
		t.Fatalf("the first search: %v", *seen)
	}
	rep, err := cr.ClientReport(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if count("/organizations/1/networks") != 1 || count("/networks/L_2/clients") != 1 || count("/networks/L_4/clients") != 1 || count("/networks/L_1/clients") != 2 {
		t.Errorf("the repeat asked more than the network it was seen in: %v", *seen)
	}
	notes, _ := rep["notes"].([]string)
	if !strings.Contains(strings.Join(notes, " "), "searched the 1 network(s) it was seen in") || rep["networks_searched"] != 1 {
		t.Errorf("the answer does not say it searched less: %v %v", notes, rep["networks_searched"])
	}
	// what was remembered is wrong now (the machine is not there): every network is asked, and the answer does not claim less
	lookups.Put(bareDriver(drv).(*meraki).ckey+"|seen|||jsmith", []string{"L_2"}, time.Minute)
	rep, err = cr.ClientReport(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	notes, _ = rep["notes"].([]string)
	ms, _ := rep["matches"].([]map[string]any)
	if len(ms) != 1 || strings.Contains(strings.Join(notes, " "), "searched the 1 network") || rep["networks_searched"] != 2 {
		t.Errorf("a wrong memory: %v %v %v", len(ms), notes, rep["networks_searched"])
	}
	// asking for one network, or with the cache off, never uses the memory
	q.Network = "L_1"
	if rep, err = cr.ClientReport(context.Background(), q); err != nil || rep["networks_searched"] != 1 {
		t.Errorf("a named network: %v %v", err, rep["networks_searched"])
	}
}

// The Meraki cache key names the login, never the API key: the key is not hashed, and two logins do not share entries.
func TestMerakiCacheKeyDoesNotUseTheKey(t *testing.T) {
	d := Device{Name: "m1", Platform: "meraki"}
	mk := func(name, key string) string {
		drv, err := newMeraki(d, Credential{Name: name, Token: key})
		if err != nil {
			t.Fatal(err)
		}
		return bareDriver(drv).(*meraki).ckey
	}
	if mk("a", "key-one") != mk("a", "key-two") {
		t.Error("the cache key depends on the API key")
	}
	if mk("a", "key-one") == mk("b", "key-one") {
		t.Error("two logins share a cache key")
	}
}

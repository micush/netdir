package device

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const smaxTok = "tok-smax-7f3k"

type smaxState struct {
	mu        sync.Mutex
	calls     []string
	logins    int
	expire    bool // answer 401 once to the first entity read
	badLayout bool // refuse any layout longer than the short one with 400
}

func smaxStub(t *testing.T, st *smaxState) Device {
	d := tlsDevice(t, "smax", "smax", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		st.calls = append(st.calls, r.Method+" "+r.URL.RequestURI())
		if r.URL.Path == "/auth/authentication-endpoint/authenticate/login" {
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if r.Method != http.MethodPost || r.URL.Query().Get("TENANTID") != "223939732" || b["Login"] != "ro" || b["Password"] != "pw-smax" {
				w.WriteHeader(401)
				return
			}
			st.logins++
			w.Write([]byte(smaxTok))
			return
		}
		if r.Header.Get("Cookie") != "LWSSO_COOKIE_KEY="+smaxTok || r.Method != http.MethodGet {
			w.WriteHeader(401)
			return
		}
		if st.expire {
			st.expire = false
			w.WriteHeader(401)
			return
		}
		q := r.URL.Query()
		if st.badLayout && q.Get("layout") != smaxMinLayout {
			jout(w, 400, map[string]any{"error": "unknown property"})
			return
		}
		ent := func(id, label, phase string) map[string]any {
			return map[string]any{"entity_type": "Request", "properties": map[string]any{"Id": id, "DisplayLabel": label, "Phase": phase, "Description": "read-only account in Centreon, password: hunter2"}}
		}
		switch r.URL.Path {
		case "/rest/223939732/ems/Request":
			all := []any{ent("5013940", "PROD and Lab server : Support", "Validation"), ent("4995175", "Read access to Entra ID", "Approval")}
			if f := q.Get("filter"); f == "Phase='Approval'" {
				all = all[1:]
			}
			if q.Get("skip") != "0" && q.Get("skip") != "" {
				all = nil
			}
			jout(w, 200, map[string]any{"entities": all, "meta": map[string]any{"completion_status": "OK"}})
		case "/rest/223939732/ems/Request/5013940":
			jout(w, 200, map[string]any{"entities": []any{ent("5013940", "PROD and Lab server : Support", "Validation")}, "meta": map[string]any{"completion_status": "OK"}})
		default:
			jout(w, 404, map[string]any{"error": "no"})
		}
	}))
	d.Options = map[string]string{"tenant": "223939732"}
	return d
}

func smaxOpen(t *testing.T, st *smaxState) Driver {
	drv, err := Open(smaxStub(t, st), Credential{Username: "ro", Password: "pw-smax"})
	if err != nil {
		t.Fatal(err)
	}
	return drv
}

func TestSMAXFactsAndShow(t *testing.T) {
	st := &smaxState{}
	drv := smaxOpen(t, st)
	ctx := context.Background()
	f, err := drv.Facts(ctx)
	if err != nil || f.Vendor != "Micro Focus" || !strings.Contains(f.Model, "223939732") {
		t.Fatalf("%+v %v", f, err)
	}
	out, err := drv.Show(ctx, "show requests")
	if err != nil || !strings.Contains(out, "5013940") || !strings.Contains(out, `"matching": 2`) {
		t.Fatalf("%s %v", out, err)
	}
	if out, err = drv.Show(ctx, "show requests phase=Approval"); err != nil || !strings.Contains(out, `"matching": 1`) || strings.Contains(out, "5013940") {
		t.Fatalf("%s %v", out, err)
	}
	if out, err = drv.Show(ctx, "show requests search=entra"); err != nil || !strings.Contains(out, `"matching": 1`) {
		t.Fatalf("%s %v", out, err)
	}
	out, err = drv.Show(ctx, "show request 5013940")
	if err != nil || !strings.Contains(out, "Centreon") || strings.Contains(out, "hunter2") {
		t.Fatalf("a secret in the text must be hidden: %s %v", out, err)
	}
	for _, bad := range []string{"show", "show persons", "show request abc", "show request", "show requests limit=0", "show requests phase=a'b c", "show requests foo=1"} {
		if _, err := drv.Show(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if st.logins != 1 {
		t.Fatalf("%d sign-ins, want 1 (the session is kept)", st.logins)
	}
}

func TestSMAXRenewsExpiredSessionOnce(t *testing.T) {
	st := &smaxState{}
	drv := smaxOpen(t, st)
	ctx := context.Background()
	if _, err := drv.Show(ctx, "show requests"); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.expire = true
	st.mu.Unlock()
	if _, err := drv.Show(ctx, "show requests"); err != nil {
		t.Fatal(err)
	}
	if st.logins != 2 {
		t.Fatalf("%d sign-ins, want 2", st.logins)
	}
}

func TestSMAXFallsBackToShortLayout(t *testing.T) {
	st := &smaxState{badLayout: true}
	drv := smaxOpen(t, st)
	out, err := drv.Show(context.Background(), "show requests")
	if err != nil || !strings.Contains(out, "5013940") {
		t.Fatalf("%s %v", out, err)
	}
}

func TestSMAXAPIGetRules(t *testing.T) {
	st := &smaxState{}
	drv := smaxOpen(t, st)
	g := drv.(APIer)
	ctx := context.Background()
	for _, ok := range []string{"/ems/Request?size=20", "ems/request", "/rest/223939732/ems/Request/5013940", "/Request?layout=Id,DisplayLabel&filter=Phase%3D'Approval'"} {
		if _, _, err := g.APIGet(ctx, ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"/ems/Person", "/ems/Request/abc", "/ems/Request/1/2", "/ems/Request?size=9999", "/ems/Request?layout=*", "/ems/Request?x=1", "/auth/authentication-endpoint/authenticate/login", "/ems/Request?filter=a%0Ab"} {
		if _, _, err := g.APIGet(ctx, bad); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
	for _, c := range st.calls {
		if strings.Contains(c, "Person") || (strings.HasPrefix(c, "POST") && !strings.Contains(c, "authenticate/login")) {
			t.Fatalf("a call that must not be sent: %s", c)
		}
	}
}

func TestSMAXWrites(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	d := tlsDevice(t, "smax", "smax", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/auth/authentication-endpoint/authenticate/login" {
			w.Write([]byte(smaxTok))
			return
		}
		if r.Header.Get("Cookie") != "LWSSO_COOKIE_KEY="+smaxTok {
			w.WriteHeader(401)
			return
		}
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			sent = append(sent, r.URL.Path+" "+string(b))
			jout(w, 200, map[string]any{"meta": map[string]any{"completion_status": "OK"}})
			return
		}
		jout(w, 200, map[string]any{"entities": []any{}, "meta": map[string]any{"completion_status": "OK"}})
	}))
	d.Options = map[string]string{"tenant": "223939732"}
	drv, err := Open(d, Credential{Username: "rw", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	rc := drv.(RawChanger)
	ctx := context.Background()
	ok := `{"operation":"CREATE","entities":[{"entity_type":"Request","properties":{"DisplayLabel":"test"}}]}`
	if res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/ems/bulk", Body: ok}, false); err != nil || !res.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	if res, err := rc.RawChange(ctx, Raw{Method: "POST", Path: "/rest/223939732/ems/bulk", Body: strings.Replace(ok, "CREATE", "update", 1)}, true); err != nil || res.Applied {
		t.Fatalf("dry: %+v %v", res, err)
	}
	for name, bad := range map[string]Raw{
		"delete op":   {Method: "POST", Path: "/ems/bulk", Body: strings.Replace(ok, "CREATE", "DELETE", 1)},
		"person":      {Method: "POST", Path: "/ems/bulk", Body: strings.Replace(ok, "Request", "Person", 1)},
		"no entities": {Method: "POST", Path: "/ems/bulk", Body: `{"operation":"CREATE","entities":[]}`},
		"other path":  {Method: "POST", Path: "/ems/Request", Body: ok},
		"put":         {Method: "PUT", Path: "/ems/bulk", Body: ok},
		"not json":    {Method: "POST", Path: "/ems/bulk", Body: "x"},
	} {
		if _, err := rc.RawChange(ctx, bad, false); err == nil {
			t.Errorf("%s was sent", name)
		}
	}
	if len(sent) != 1 || !strings.HasPrefix(sent[0], "/rest/223939732/ems/bulk ") {
		t.Fatalf("sent %v", sent)
	}
}

func TestSMAXSetup(t *testing.T) {
	d := smaxStub(t, &smaxState{})
	for _, o := range []map[string]string{nil, {"tenant": "abc"}, {"tenant": "1"}} {
		d2 := d
		d2.Options = o
		if _, err := Open(d2, Credential{Username: "ro", Password: "pw-smax"}); err == nil {
			t.Errorf("options %v accepted", o)
		}
	}
	if _, err := Open(d, Credential{Username: "ro"}); err == nil {
		t.Error("no password accepted")
	}
	bad := smaxStub(t, &smaxState{})
	drv2, _ := Open(bad, Credential{Username: "ro", Password: "wrong"})
	if _, err := drv2.Facts(context.Background()); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("expected an error without the password: %v", err)
	}
}

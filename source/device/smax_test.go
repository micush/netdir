package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	failed200 bool // answer any layout longer than the short one with HTTP 200 and completion_status FAILED (a property the tenant does not know)
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
		if st.failed200 && q.Get("layout") != smaxMinLayout {
			jout(w, 200, map[string]any{"entities": []any{}, "meta": map[string]any{"completion_status": "FAILED", "total_count": 3180,
				"errorDetails": map[string]any{"httpStatus": 500, "message": "Illegal query structure: DQL exception encountered"}}})
			return
		}
		ent := func(id, label, phase string) map[string]any {
			return map[string]any{"entity_type": "Request", "properties": map[string]any{"Id": id, "DisplayLabel": label, "Phase": phase, "Description": "read-only account in Centreon, password: hunter2"}}
		}
		switch r.URL.Path {
		case "/rest/223939732/ems/Request":
			all := []any{ent("5013940", "PROD and Lab server : Support", "Validation"), ent("4995175", "Read access to Entra ID", "Approval")}
			if f := q.Get("filter"); strings.HasPrefix(f, "(PhaseId='Approval') and (LastUpdateTime gt ") {
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

// A tenant with more than 10,000 records refuses an unfiltered list (HTTP 400): every list carries a recent-activity window, the
// option days sets it and 0 turns it off, and a filter of the caller's own is left alone.
func TestSMAXListWindow(t *testing.T) {
	ctx := context.Background()
	st := &smaxState{}
	drv := smaxOpen(t, st)
	g := drv.(APIer)
	if _, err := drv.Facts(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.APIGet(ctx, "/ems/Request?size=20"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.APIGet(ctx, "/ems/Request?filter=Phase%3D%27Approval%27"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.APIGet(ctx, "/ems/Request/5013940"); err != nil {
		t.Fatal(err)
	}
	var facts, inc, own, one string
	for _, c := range st.calls {
		switch {
		case strings.Contains(c, "/Request?") && strings.HasSuffix(c, "size=1"):
			facts = c
		case strings.Contains(c, "/Request?") && strings.Contains(c, "size=20"):
			inc = c
		case strings.Contains(c, "/Request?") && strings.Contains(c, "Approval"):
			own = c
		case strings.Contains(c, "/Request/5013940"):
			one = c
		}
	}
	if !strings.Contains(facts, "filter=LastUpdateTime+gt+") || !strings.Contains(inc, "filter=LastUpdateTime+gt+") {
		t.Errorf("no window on a list: %q %q", facts, inc)
	}
	if strings.Contains(own, "LastUpdateTime+gt") || strings.Contains(one, "filter=") {
		t.Errorf("a caller's filter or a single record was changed: %q %q", own, one)
	}
	d := smaxStub(t, &smaxState{})
	for _, bad := range []string{"-1", "x", "99999"} {
		d.Options = map[string]string{"tenant": "223939732", "days": bad}
		if _, err := Open(d, Credential{Username: "ro", Password: "pw-smax"}); err == nil {
			t.Errorf("days=%s accepted", bad)
		}
	}
	st2 := &smaxState{}
	d2 := smaxStub(t, st2)
	d2.Options = map[string]string{"tenant": "223939732", "days": "0"}
	drv2, err := Open(d2, Credential{Username: "ro", Password: "pw-smax"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drv2.Facts(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range st2.calls {
		if strings.Contains(c, "LastUpdateTime+gt") {
			t.Errorf("days=0 still filtered: %s", c)
		}
	}
}

// SMAX reports an unknown property of a layout as HTTP 200 with completion_status FAILED: that is an error (so the short layout
// is tried), not an empty list.
func TestSMAXFailedAnswerInsideHTTP200(t *testing.T) {
	st := &smaxState{failed200: true}
	drv := smaxOpen(t, st)
	ctx := context.Background()
	out, err := drv.Show(ctx, "show requests")
	if err != nil || !strings.Contains(out, "5013940") {
		t.Fatalf("the short layout was not tried: %s %v", out, err)
	}
	g := drv.(APIer)
	if _, _, err := g.APIGet(ctx, "/ems/Request?layout=Id,Nope"); err != nil {
		t.Fatalf("a layout the tenant refuses falls back to the short one: %v", err)
	}
	var sawFull, sawMin bool
	for _, c := range st.calls {
		sawFull = sawFull || strings.Contains(c, "PhaseId")
		sawMin = sawMin || strings.Contains(c, "layout=Id%2CDisplayLabel%2CCreateTime&")
	}
	if !sawFull || !sawMin {
		t.Errorf("full layout %v, short layout %v: %v", sawFull, sawMin, st.calls)
	}
	if v := smaxFailed(map[string]any{"meta": map[string]any{"completion_status": "OK"}}); v != nil {
		t.Errorf("OK taken as a failure: %v", v)
	}
	err = smaxFailed(map[string]any{"meta": map[string]any{"completion_status": "FAILED", "errorDetails": map[string]any{"httpStatus": float64(500), "message": "DQL"}}})
	var se *statusError
	if !errors.As(err, &se) || se.Code != 500 || !strings.Contains(err.Error(), "DQL") {
		t.Errorf("a failed answer: %v", err)
	}
}

// The tickets of a person: the person is found by sign-in name, then e-mail, then name (exact matches); the newest requests and
// incidents they asked for come back newest first.
func TestSMAXUserTickets(t *testing.T) {
	var persons, tickets []string
	d := tlsDevice(t, "smax", "smax", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/authentication-endpoint/authenticate/login" {
			w.Write([]byte(smaxTok))
			return
		}
		q := r.URL.Query()
		ent := func(typ, id, label string, created float64) map[string]any {
			return map[string]any{"entity_type": typ, "properties": map[string]any{"Id": id, "DisplayLabel": label, "CreateTime": created, "Description": "password: hunter2"}}
		}
		ok := func(es ...any) {
			jout(w, 200, map[string]any{"entities": es, "meta": map[string]any{"completion_status": "OK"}})
		}
		switch r.URL.Path {
		case "/rest/223939732/ems/Person":
			f := q.Get("filter")
			persons = append(persons, f)
			if f == "Email='joe@contoso.com'" {
				ok(map[string]any{"entity_type": "Person", "properties": map[string]any{"Id": "1001", "Name": "Joe Smith"}})
				return
			}
			if strings.HasPrefix(f, "Upn=") { // a tenant without that property
				jout(w, 200, map[string]any{"entities": []any{}, "meta": map[string]any{"completion_status": "FAILED", "errorDetails": map[string]any{"httpStatus": 500, "message": "DQL exception"}}})
				return
			}
			ok()
		case "/rest/223939732/ems/Request":
			tickets = append(tickets, "Request "+q.Get("filter")+" "+q.Get("order")+" "+q.Get("size"))
			ok(ent("Request", "11", "VPN does not connect", 1700000003000), ent("Request", "10", "New laptop", 1700000001000))
		case "/rest/223939732/ems/Incident":
			tickets = append(tickets, "Incident "+q.Get("filter"))
			ok(ent("Incident", "12", "Outlook crashes", 1700000002000))
		default:
			jout(w, 404, map[string]any{})
		}
	}))
	d.Options = map[string]string{"tenant": "223939732"}
	drv, err := Open(d, Credential{Username: "ro", Password: "pw-smax"})
	if err != nil {
		t.Fatal(err)
	}
	tl, isTL := drv.(TicketLooker)
	if !isTL {
		t.Fatal("smax is not a TicketLooker")
	}
	who, ts, err := tl.UserTickets(context.Background(), []string{"joe@contoso.com", "joe", "Joe Smith"}, 3)
	if err != nil || who != "Joe Smith" || len(ts) != 3 {
		t.Fatalf("%q %v %v", who, ts, err)
	}
	if ts[0]["Id"] != "11" || ts[1]["Id"] != "12" || ts[2]["Id"] != "10" || ts[0]["type"] != "Request" || ts[1]["type"] != "Incident" || ts[0]["created"] != "2023-11-14T22:13:23Z" {
		t.Errorf("newest first, with the type and the time: %v", ts)
	}
	if strings.Contains(fmt.Sprint(ts), "hunter2") {
		t.Errorf("a secret in a ticket was not hidden: %v", ts)
	}
	if len(persons) != 3 || persons[0] != "Upn='joe@contoso.com'" || persons[1] != persons[0] /* the retry with the short layout */ || persons[2] != "Email='joe@contoso.com'" {
		t.Errorf("the person is looked up by sign-in name, then e-mail address, and the search stops at the first found: %v", persons)
	}
	if len(tickets) != 2 || !strings.Contains(tickets[0], "RequestedByPerson='1001' CreateTime desc 3") || !strings.Contains(tickets[1], "RequestedByPerson='1001'") {
		t.Errorf("the tickets are asked for by the person's number, newest first: %v", tickets)
	}
	if _, _, err := tl.UserTickets(context.Background(), []string{"nobody@contoso.com", "a'b"}, 3); !errors.Is(err, ErrNoRequester) {
		t.Errorf("an unknown person: %v", err)
	}
	if _, _, err := tl.UserTickets(context.Background(), []string{"x\"*y"}, 3); !errors.Is(err, ErrNoRequester) {
		t.Errorf("a name with a wildcard or a quote was searched: %v", err)
	}
}

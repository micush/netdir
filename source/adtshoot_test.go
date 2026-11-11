package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"netdir/device"
)

// a few bytes of BER for a directory that answers one fixed user or computer, whatever the filter
func berT(tag byte, parts ...[]byte) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, p...)
	}
	l := []byte{byte(len(c))}
	if len(c) >= 0x80 {
		l = []byte{0x82, byte(len(c) >> 8), byte(len(c))}
	}
	return append(append([]byte{tag}, l...), c...)
}

func berRead(r *bufio.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[1])
	pre := hdr[:]
	if n&0x80 != 0 {
		k := n & 0x7f
		lb := make([]byte, k)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		n = 0
		for _, b := range lb {
			n = n<<8 | int(b)
		}
		pre = append(append([]byte{}, hdr[:]...), lb...)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(pre, body...), nil
}

func adTsStub(t *testing.T) (string, int) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dc"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	oct := func(s string) []byte { return berT(0x04, []byte(s)) }
	attr := func(n string, v ...string) []byte {
		var vs [][]byte
		for _, x := range v {
			vs = append(vs, oct(x))
		}
		return berT(0x30, oct(n), berT(0x31, vs...))
	}
	res := func() [][]byte { return [][]byte{{0x0a, 0x01, 0x00}, oct(""), oct("")} }
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					m, err := berRead(r)
					if err != nil {
						return
					}
					body := m[2:]
					if m[1]&0x80 != 0 {
						body = m[2+int(m[1]&0x7f):]
					}
					id := body[:3] // INTEGER, one byte
					op := body[3]
					send := func(o byte, parts ...[]byte) {
						_, _ = c.Write(berT(0x30, id, berT(o, parts...)))
					}
					switch op {
					case 0x60:
						send(0x61, res()...)
					case 0x63:
						switch {
						case bytes.Contains(m, []byte("computer")):
							send(0x64, oct("CN=JSMITH-LAPTOP,OU=PCs,DC=corp,DC=example,DC=com"), berT(0x30, attr("name", "JSMITH-LAPTOP"), attr("dNSHostName", "jsmith-laptop.corp.example.com"),
								attr("operatingSystem", "Windows 11 Enterprise"), attr("userAccountControl", "4096")))
						case bytes.Contains(m, []byte("defaultNamingContext")):
							send(0x64, oct(""), berT(0x30, attr("defaultNamingContext", "DC=corp,DC=example,DC=com")))
						default:
							send(0x64, oct("CN=Joe Smith,CN=Users,DC=corp,DC=example,DC=com"), berT(0x30, attr("sAMAccountName", "jsmith"), attr("displayName", "Joe Smith"),
								attr("userAccountControl", "514"), attr("lockoutTime", "133740000000000000"), attr("memberOf", "CN=VPN Users,OU=Groups,DC=corp,DC=example,DC=com")))
						}
						send(0x65, res()...)
					case 0x42:
						return
					}
				}
			}()
		}
	}()
	h, p, _ := net.SplitHostPort(l.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

// With an Active Directory device the troubleshooting adds the account's state; without one nothing changes.
func TestTroubleshootWithActiveDirectory(t *testing.T) {
	e, _ := troubleEnvWith(t, false)
	_, m := tsAnswer(t, e, `{"user":"joe@contoso.com"}`)
	if m["directory"] != nil || m["directory_device"] != nil {
		t.Fatalf("a directory without a device: %v", m)
	}
	h, pn := adTsStub(t)
	dc, _, _ := e.mg.LiveConfig()
	dc.Settings.DeviceCredentials = append(dc.Settings.DeviceCredentials, device.Credential{Name: "adc", Username: "svc@corp.example.com", Password: "S3CRET"})
	dc.Settings.Devices = append(dc.Settings.Devices, device.Device{Name: "ad", Platform: "ad", Address: h, Port: pn, Credential: "adc", Insecure: true})
	if err := e.mg.PutConfig(dc, "test", "ad"); err != nil {
		t.Fatal(err)
	}
	txt, m := tsAnswer(t, e, `{"user":"joe@contoso.com"}`)
	recs, _ := m["directory"].([]any)
	if m["directory_device"] != "ad" || len(recs) != 1 {
		t.Fatalf("the directory: %s", txt)
	}
	r := recs[0].(map[string]any)
	if r["account"] != "jsmith" || r["enabled"] != false || r["locked_out"] == nil || r["groups"] != "VPN Users" {
		t.Errorf("the account: %v", r)
	}
	if m["entra_device"] != "entra" || m["meraki_device"] != "mer" {
		t.Errorf("the other systems are still asked: %s", txt)
	}
	_, m = tsAnswer(t, e, `{"host":"JSMITH-LAPTOP"}`)
	recs, _ = m["directory"].([]any)
	if len(recs) != 1 || recs[0].(map[string]any)["dns_name"] != "jsmith-laptop.corp.example.com" {
		t.Errorf("a host: %v", m["directory"])
	}
	if _, err := e.mg.Op("device.troubleshoot", []byte(`{"user":"joe@contoso.com","ad":"nosuch"}`), "alice"); err == nil {
		t.Error("a named Active Directory device that is not there was ignored")
	}
}

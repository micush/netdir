package device

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// maxAnswer is the most a device's answer may be (a full running configuration of a big chassis fits easily).
const maxAnswer = 32 << 20

// apiClient is the HTTPS client a REST driver uses: the device's certificate checked against the system's roots, the
// device's own CA, or not at all (Insecure); a cookie jar for the platforms that log in to a session; no redirects
// (a device that sends one elsewhere is not followed with the credentials).
type apiClient struct {
	base string // "https://host:port"
	hc   *http.Client
	hdr  http.Header // sent with every request
	clog *contentLog // the content log of the device (contentlog.go); nil when it is off
}

func newAPIClient(d Device, defPort int) (*apiClient, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case d.Insecure:
		tc.InsecureSkipVerify = true
	case d.CAPEM != "":
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(d.CAPEM)) {
			return nil, fmt.Errorf("device %s: ca_pem holds no PEM certificate", d.Name)
		}
		tc.RootCAs = pool
	}
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 60 * time.Second}
	return &apiClient{
		base: "https://" + hostPort(d, defPort),
		hc: &http.Client{Transport: tr, Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		hdr:  http.Header{},
		clog: contentLogFor(d),
	}, nil
}

// statusError is a device's answer that was not a success.
type statusError struct {
	Code int
	Body string
}

func (e *statusError) Error() string {
	b := strings.TrimSpace(e.Body)
	if len(b) > 300 {
		b = b[:300] + "…"
	}
	if b == "" {
		return fmt.Sprintf("the device answered HTTP %d", e.Code)
	}
	return fmt.Sprintf("the device answered HTTP %d: %s", e.Code, b)
}

// do sends one request and returns the body of a 2xx answer.  body is sent as is when it is []byte or string, else as
// JSON.
func (c *apiClient) do(ctx context.Context, method, path string, body any, hdr http.Header) ([]byte, error) {
	if c.clog == nil {
		out, _, err := c.send(ctx, method, path, body, hdr)
		return out, err
	}
	start := time.Now()
	out, st, err := c.send(ctx, method, path, body, hdr)
	var req []byte
	switch b := body.(type) {
	case nil:
	case []byte:
		req = b
	case string:
		req = []byte(b)
	default:
		req, _ = json.Marshal(b)
	}
	reply := out
	var se *statusError
	if errors.As(err, &se) {
		st, reply = se.Code, []byte(se.Body)
	}
	c.clog.record(start, method, path, req, st, reply, err)
	return out, err
}

// send is do without the content log: the answer, its HTTP status (0 when there was none) and the error.
func (c *apiClient) send(ctx context.Context, method, path string, body any, hdr http.Header) ([]byte, int, error) {
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			return nil, 0, err
		}
		rd, ct = bytes.NewReader(j), "application/json"
	}
	// The request goes to the device's own address (c.base) whatever the path is: the path and the query are put into the
	// request's URL as such, never joined to the address as text (a path such as "@other.example/x" cannot change the host).
	if path != "" && path[0] != '/' {
		return nil, 0, fmt.Errorf("the path of a request to the device starts with /, not %q", path)
	}
	p, q, _ := strings.Cut(path, "?")
	p, _, _ = strings.Cut(p, "#")
	q, _, _ = strings.Cut(q, "#")
	dec, err := url.PathUnescape(p)
	if err != nil {
		return nil, 0, fmt.Errorf("the path of a request to the device is not valid: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base, rd)
	if err != nil {
		return nil, 0, err
	}
	req.URL.Path, req.URL.RawPath, req.URL.RawQuery = dec, p, q
	for k, v := range c.hdr {
		req.Header[k] = v
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if ct != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", ct)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer+1))
	if err != nil {
		return nil, 0, err
	}
	if len(out) > maxAnswer {
		return nil, 0, errors.New("the device's answer is larger than 32 MB")
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, res.StatusCode, &statusError{res.StatusCode, string(out)}
	}
	return out, res.StatusCode, nil
}

func (c *apiClient) getJSON(ctx context.Context, path string, v any) error {
	b, err := c.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("GET %s: the answer is not the JSON expected: %v", path, err)
	}
	return nil
}

func (c *apiClient) close() { c.hc.CloseIdleConnections() }

// rows reads a value that a device sends as one object when there is one and as a list when there are more (NX-API's
// TABLE_x / ROW_x).
func rows(v any) []map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return []map[string]any{t}
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// str is the text of a JSON value: a string as is, a number without a needless ".0", anything else "".
func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprint(int64(t))
		}
		return fmt.Sprint(t)
	case json.Number:
		return t.String()
	case bool:
		return fmt.Sprint(t)
	}
	return ""
}

func num(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case string:
		var n int64
		if _, err := fmt.Sscan(strings.TrimSpace(t), &n); err == nil {
			return n
		}
	}
	return 0
}

func boolp(b bool) *bool { return &b }

func firstOf(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// nowUnix is the time now; a variable so tests can fix it.
var nowUnix = func() int64 { return time.Now().Unix() }

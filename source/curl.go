package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// curl from this node (the node a gateway runs on, over MCP: net_curl): one request with fixed options.  The caller chooses the URL
// (http or https only), whether to ask for the headers alone (HEAD, the default) or to fetch the page (the first 16 KB are shown),
// whether to follow up to three redirects and whether to skip the certificate check.  Run through exec with no shell; the URL is checked
// before it gets near the command line, and curl is told to speak http and https only, also after a redirect.
const (
	curlTimeout = 20 * time.Second
	curlTextMax = 16384
)

func curlCheckURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2000 || strings.ContainsAny(raw, " \t\r\n\x00") {
		return "", errors.New("url: an http or https address")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("url: an http or https address, e.g. https://example.com/")
	}
	if u.User != nil || u.Host == "" {
		return "", errors.New("url: no user name or password in the address, and a host is needed")
	}
	h := u.Hostname()
	if a, err := netip.ParseAddr(h); err != nil || a.Zone() != "" {
		for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
			if !digLabelRe.MatchString(l) {
				return "", fmt.Errorf("url: %q is not a host name or an IP address", h)
			}
		}
	}
	if p := u.Port(); p != "" {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 1 || n > 65535 {
			return "", errors.New("url: the port is 1 to 65535")
		}
	}
	return u.String(), nil
}

func curlRun(rawURL, method string, follow, insecure bool) (map[string]any, error) {
	u, err := curlCheckURL(rawURL)
	if err != nil {
		return nil, err
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "HEAD"
	}
	if method != "HEAD" && method != "GET" {
		return nil, errors.New("method: HEAD (the headers; the default) or GET (the page too)")
	}
	path, err := exec.LookPath("curl")
	if err != nil {
		return nil, errors.New("curl is not installed on this node (install the curl package)")
	}
	args := []string{"-sS", "--proto", "=http,https", "--proto-redir", "=http,https", "--max-time", "15", "--max-filesize", "1048576", "--user-agent", "netdir",
		"-w", "\n--\nhttp_code=%{http_code} remote_ip=%{remote_ip} time_connect=%{time_connect}s time_tls=%{time_appconnect}s time_first_byte=%{time_starttransfer}s time_total=%{time_total}s redirects=%{num_redirects}\n"}
	if method == "HEAD" {
		args = append(args, "-I")
	} else {
		args = append(args, "-i")
	}
	if follow {
		args = append(args, "-L", "--max-redirs", "3")
	}
	if insecure {
		args = append(args, "-k")
	}
	args = append(args, "--", u)
	ctx, cancel := context.WithTimeout(context.Background(), curlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	b, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(b))
	if len(text) > curlTextMax {
		text = text[:curlTextMax] + "\n…"
	}
	if err != nil && text == "" {
		if ctx.Err() != nil {
			return nil, errors.New("curl did not finish in " + curlTimeout.String())
		}
		return nil, fmt.Errorf("curl failed: %v", err)
	}
	return map[string]any{"url": u, "method": method, "text": text, "failed": err != nil}, nil
}

package sitegoose

// First-party proxy: serving the tracker from the site's own domain, so ad
// blockers don't hide visitors. Blockers recognise the address a script comes
// from and what it is called; this app is already a server on the site's
// domain, so the package serves both itself:
//
//	<prefix>/js/<rest>   ->  <endpoint>/<rest>                  (tracker files)
//	<prefix>/api/<rest>  ->  <endpoint>/collectanalytics/<rest> (the collector)
//
// The prefix comes from the site secret: not guessable from the page, and the
// same every time, so a browser's cache and a CDN in front stay valid. It
// answers before every other module but the firewall's address lists: a
// visitor's beacon is our own traffic, not a page of the site, so it isn't
// counted, timed, rate-limited or sent the browser check.
//
// The site never waits on the collector for long: a tracker file held is
// served at once and refreshed behind it (one fetch however many ask), and
// beacons get a short timeout and a breaker that answers straight away
// while the collector keeps failing.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The tracker files, by name: anything else is refused rather than forwarded.
var trackerFiles = map[string]bool{
	"track.js": true, "s.js": true, "snapshot.js": true, "replay.js": true, "survey.js": true, "banner.js": true,
	"leadform.js": true, "notice.js": true, "editor.js": true, "picker.js": true, "feedback.js": true, "shield.js": true,
	"widget.js": true, "share.js": true,
}

const (
	// A pinned version never changes; /v<major>/ follows new releases, so it
	// is held for an hour, as the collector serves it.
	ttlPinned    = 7 * 24 * time.Hour
	ttlMajor     = time.Hour
	maxProxyBody = 6 << 20
)

// The collector reads these; everything else, cookies above all, stays here.
var passHeaders = []string{"Content-Type", "User-Agent", "Accept-Language", "Referer", "Origin",
	"Sec-Fetch-Site", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform"}

var (
	safeProxyPath = regexp.MustCompile(`^[A-Za-z0-9/_.-]{1,120}$`)
	trackerPath   = regexp.MustCompile(`^v(\d+(?:\.\d+\.\d+)?)/([a-z]+\.js)$`)
	prefixChars   = regexp.MustCompile(`[^A-Za-z0-9_-]`)
	answerHeaders = []string{"Cache-Control", "Retry-After"}
)

// answerTypes are what a collector answer may be served as from the site's
// own domain. Its type comes from the collector, so anything else becomes
// plain text, and nosniff stops a browser guessing: a server that is no
// longer ours still can't answer <prefix>/api/... with a page that runs as
// the customer's own site. Shared cases: sdk/protocols/proxy-answer-cases.json.
var answerTypes = map[string]bool{"application/json": true, "text/plain": true, "image/webp": true}

func answerType(value string) string {
	kind, _, _ := strings.Cut(value, ";")
	if !answerTypes[strings.ToLower(strings.TrimSpace(kind))] {
		return "text/plain; charset=utf-8"
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return "text/plain; charset=utf-8"
		}
	}
	return value
}

func proxyPrefixFor(secret string) string {
	sum := sha256.Sum256([]byte("proxy|" + secret))
	return hex.EncodeToString(sum[:])[:8]
}

// proxyKeyFor is sent as X-Proxy-Key, so the collector believes the visitor
// addresses this proxy passes on: anyone can write X-Forwarded-For. Worked out
// from the secret as the collector does (expresscollect/utils/proxyKey.js).
func proxyKeyFor(secret string) string {
	sum := sha256.Sum256([]byte("proxykey|" + secret))
	return hex.EncodeToString(sum[:])[:32]
}

// ProxyOptions configure the first-party proxy.
type ProxyOptions struct {
	// Prefix is the path it answers on. Default: eight characters from the secret.
	Prefix string
}

type heldFile struct {
	body []byte
	at   time.Time
}

// Proxy is the first-party proxy; its two addresses go in the page's script tag:
//
//	<script async src="{{.ScriptURL}}" data-siteid="..." data-collect="{{.CollectURL}}"></script>
type Proxy struct {
	core     *core
	prefix   string
	key      string
	client   *http.Client // tracker files
	beacons  *http.Client // the collector, with a shorter timeout
	mu       sync.Mutex
	files    map[string]heldFile
	fetching map[string]chan struct{} // closed when that file's fetch ends
	failures int                      // beacons the collector failed in a row
	openTill time.Time                // the breaker: beacons answered here until then
	now      func() time.Time
}

const (
	beaconTimeout  = 3 * time.Second
	breakerFails   = 5
	breakerOpenFor = 30 * time.Second
)

func newProxy(c *core, o ProxyOptions) *Proxy {
	prefix := o.Prefix
	if prefix == "" {
		prefix = proxyPrefixFor(c.secret)
	}
	p := &Proxy{core: c, prefix: prefixChars.ReplaceAllString(prefix, ""), files: map[string]heldFile{},
		fetching: map[string]chan struct{}{}, now: time.Now}
	if c.secret != "" {
		p.key = proxyKeyFor(c.secret)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	p.client = &http.Client{Timeout: sendTimeout, Transport: transport,
		// The collector's answer goes back as it is, redirects included.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	p.beacons = &http.Client{Timeout: beaconTimeout, Transport: transport, CheckRedirect: p.client.CheckRedirect}
	return p
}

// Enabled: on, and not switched off in the dashboard.
func (p *Proxy) Enabled() bool {
	return p != nil && p.core.valid && p.prefix != "" && p.core.isOn(ModuleProxy)
}

// Prefix is the path the proxy answers on.
func (p *Proxy) Prefix() string {
	if p == nil {
		return ""
	}
	return p.prefix
}

// ScriptURL is the tracker's address on this site ("/3f9a2c1b/js/v1/s.js");
// version "" is "1", the latest 1.x.
func (p *Proxy) ScriptURL(version string) string {
	if p == nil {
		return ""
	}
	return "/" + p.prefix + "/js/v" + firstNonEmpty(version, "1") + "/s.js"
}

// CollectURL is where visits are sent, for the tag's data-collect ("/3f9a2c1b/api/e").
func (p *Proxy) CollectURL() string {
	if p == nil {
		return ""
	}
	return "/" + p.prefix + "/api/e"
}

// match: ("js" | "api", the rest) when the address is ours, ("bad", "") when
// it is under the prefix but nothing we serve, ("", "") when it isn't ours.
func (p *Proxy) match(path string) (string, string) {
	if !p.Enabled() {
		return "", ""
	}
	head := "/" + p.prefix + "/"
	if !strings.HasPrefix(path, head) {
		return "", ""
	}
	rest := path[len(head):]
	for _, kind := range []string{"js", "api"} {
		if strings.HasPrefix(rest, kind+"/") {
			tail := rest[len(kind)+1:]
			if tail != "" && !strings.Contains(tail, "..") && safeProxyPath.MatchString(tail) {
				return kind, tail
			}
			break
		}
	}
	return "bad", ""
}

type proxyAnswer struct {
	status int
	header http.Header
	body   []byte
}

var proxyNotFound = proxyAnswer{status: http.StatusNotFound, header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, body: []byte("Not found")}

func (p *Proxy) handle(kind, rest string, r *http.Request, clientIP string) proxyAnswer {
	switch kind {
	case "js":
		return p.file(r.Context(), rest)
	case "api":
		return p.collector(rest, r, clientIP)
	}
	return proxyNotFound
}

func (p *Proxy) file(ctx context.Context, rest string) proxyAnswer {
	m := trackerPath.FindStringSubmatch(rest)
	if m == nil || !trackerFiles[m[2]] {
		return proxyNotFound
	}
	pinned := strings.Contains(m[1], ".")
	ttl := ttlMajor
	if pinned {
		ttl = ttlPinned
	}
	p.mu.Lock()
	held, have := p.files[rest]
	p.mu.Unlock()
	body := held.body
	switch {
	case have && p.now().Sub(held.at) < ttl:
	case have:
		// Out of date: this copy now, a fresh one for the next visitor.
		go p.fetch(rest)
	default:
		if body = p.fetch(rest); body == nil {
			return proxyAnswer{status: http.StatusBadGateway, header: http.Header{}}
		}
	}
	h := http.Header{}
	h.Set("Content-Type", "application/javascript; charset=utf-8")
	if pinned {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "public, max-age=3600")
	}
	h.Set("X-Content-Type-Options", "nosniff")
	return proxyAnswer{status: http.StatusOK, header: h, body: body}
}

// fetch gets one tracker file from the collector, once however many ask at
// the same time: the others wait for that fetch. The file held (old or new)
// is returned, nil when there is none.
func (p *Proxy) fetch(rest string) []byte {
	defer func() { recover() }()
	p.mu.Lock()
	if wait, busy := p.fetching[rest]; busy {
		p.mu.Unlock()
		select {
		case <-wait:
		case <-time.After(sendTimeout + time.Second):
		}
		p.mu.Lock()
		held := p.files[rest]
		p.mu.Unlock()
		return held.body
	}
	done := make(chan struct{})
	p.fetching[rest] = done
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.fetching, rest)
		p.mu.Unlock()
		close(done)
	}()
	// Not the visitor's request context: a fetch others wait on mustn't end
	// because the first visitor left.
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.core.endpoint+"/"+rest, nil)
	if err == nil {
		if res, err := p.client.Do(req); err == nil {
			fetched, _ := io.ReadAll(io.LimitReader(res.Body, maxProxyBody))
			res.Body.Close()
			if res.StatusCode == http.StatusOK && len(fetched) > 500 {
				p.mu.Lock()
				p.files[rest] = heldFile{fetched, p.now()}
				p.mu.Unlock()
				return fetched
			}
		} else {
			p.core.log("proxy", "could not fetch %s: %v", rest, err)
		}
	}
	// Upstream is unreachable: an old copy beats no tracker at all.
	p.mu.Lock()
	held := p.files[rest]
	p.mu.Unlock()
	return held.body
}

func (p *Proxy) collector(rest string, r *http.Request, clientIP string) proxyAnswer {
	method := strings.ToUpper(r.Method)
	if method == http.MethodOptions {
		// Same origin as the page, so a preflight shouldn't happen; answer it
		// cheaply rather than passing it on.
		h := http.Header{}
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type")
		h.Set("Access-Control-Max-Age", "86400")
		return proxyAnswer{status: http.StatusNoContent, header: h}
	}
	if method != http.MethodGet && method != http.MethodPost {
		return proxyNotFound
	}
	p.mu.Lock()
	open := p.now().Before(p.openTill)
	p.mu.Unlock()
	if open {
		// The collector kept failing: answered here rather than holding the
		// visitor's connection for the timeout each time.
		h := http.Header{}
		h.Set("Retry-After", "30")
		return proxyAnswer{status: http.StatusServiceUnavailable, header: h}
	}
	var body io.Reader
	if method == http.MethodPost && r.Body != nil {
		data, err := io.ReadAll(io.LimitReader(r.Body, maxProxyBody+1))
		if err != nil {
			return proxyAnswer{status: http.StatusBadRequest, header: http.Header{}}
		}
		if len(data) > maxProxyBody {
			return proxyAnswer{status: http.StatusRequestEntityTooLarge, header: http.Header{}}
		}
		body = bytes.NewReader(data)
	}
	target := p.core.endpoint + "/collectanalytics/" + rest
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), method, target, body)
	if err != nil {
		return proxyAnswer{status: http.StatusBadGateway, header: http.Header{}}
	}
	// The visitor's address: the collector needs it for the country, the
	// daily visitor ID and the per-visitor rate limit.
	req.Header.Set("X-Forwarded-For", clientIP)
	if p.key != "" {
		req.Header.Set("X-Proxy-Key", p.key)
	}
	for _, name := range passHeaders {
		if v := r.Header.Get(name); v != "" {
			req.Header.Set(name, strings.NewReplacer("\r", "", "\n", "").Replace(v))
		}
	}
	res, err := p.beacons.Do(req)
	p.beaconAnswered(err == nil && res.StatusCode < 500, r.Context().Err() != nil)
	if err != nil {
		// The tracker already treats a failed beacon as lost and carries on.
		p.core.log("proxy", "could not reach the collector: %v", err)
		return proxyAnswer{status: http.StatusBadGateway, header: http.Header{}}
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, maxProxyBody))
	h := http.Header{}
	h.Set("Content-Type", answerType(res.Header.Get("Content-Type")))
	h.Set("X-Content-Type-Options", "nosniff")
	for _, name := range answerHeaders {
		if v := res.Header.Get(name); v != "" {
			h.Set(name, v)
		}
	}
	return proxyAnswer{status: res.StatusCode, header: h, body: data}
}

// beaconAnswered keeps the breaker: breakerFails failures in a row open it
// for breakerOpenFor. A visitor who left isn't the collector failing.
func (p *Proxy) beaconAnswered(ok, visitorLeft bool) {
	if visitorLeft {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok {
		p.failures = 0
		return
	}
	p.failures++
	if p.failures >= breakerFails {
		p.failures = 0
		p.openTill = p.now().Add(breakerOpenFor)
		p.core.log("proxy", "the collector keeps failing; beacons answered here for %s", breakerOpenFor)
	}
}

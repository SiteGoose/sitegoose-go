package sitegoose

// Firewall module: rules from the collector (GET /events/firewall/rules,
// protocol in sdk/protocols/firewall.md) every minute or so; every request is
// checked against them in memory, so the app never waits on the collector.
// What was blocked (or, in monitor mode, would have been) goes back in
// batches, grouped.
//
// Fails open: until rules arrive, and whenever the collector can't be
// reached, requests pass (with the last rules that arrived, if any). The rate
// limit counts in this process: with several processes, pass Counter (Redis,
// say) for one count across them.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	firewallProtocol = 1
	firewallFlush    = 5 * time.Second
	firewallBatch    = 200
	firewallQueueMax = 2000
	counterMax       = 100000
	// The layers this server runs (X-Firewall-Layers): the address firewall and the browser check.
	firewallLayers = "app check"
)

// Decision is what the firewall makes of a request.
type Decision struct {
	// Action is "allow", "block" or "monitor" (matched, but only reported).
	Action string
	// Rule is empty when allowed: "deny", "ban", "list", "shared", "probe",
	// "rate", "challenge", "request:<id>" or "limit:<id>" (a page limit).
	Rule string
	// Status: 200 allowed, 403, 429 for the rate limit and a page limit, 503
	// for the browser check.
	Status int
	// RetryAfter is the seconds a 429 asks the visitor to wait: the window
	// of the rate limit or of the page limit that decided. 0 otherwise.
	RetryAfter int64

	// late: a static file let through, for countStatic after the response.
	late *lateHit
}

// lateHit is a static-looking request Check only compared with the counts
// (firewall.md, `rate`): what countStatic adds after the response when the
// router sent it to a page or it answered an error.
type lateHit struct {
	key  ipKey
	rate bool
	req  *preparedRequest // nil: no page limit to count
}

// CheckInput is one request as the firewall checks it.
type CheckInput struct {
	IP        string
	Method    string
	Target    string // the request target as sent, query string and all
	UserAgent string
	Accept    string
	Cookie    string
	// SecFetchSite is the Sec-Fetch-Site header: "cross-site" or "same-site"
	// is a request another page made the browser send, refused but never
	// banned (crossSite).
	SecFetchSite string
}

// FirewallOptions configure the firewall module.
type FirewallOptions struct {
	// Mode "monitor" or "block" overrides the dashboard.
	Mode string
	// CacheFile keeps the last rules on disk, so they apply straight after a restart.
	CacheFile string
	// TrustProxy overrides Options.TrustProxy for the firewall.
	TrustProxy string
	// Counter counts requests across processes (Redis INCR + EXPIRE): it
	// returns the hits so far for key, which lives ttl. On an error the
	// request is counted in this process instead.
	Counter func(key string, ttl time.Duration) (int64, error)
	// Skip leaves a request unchecked when it returns true.
	Skip func(r *http.Request) bool
	// OnBlock writes your own response for a blocked request (not for the
	// browser check, whose page is what lets a browser through).
	OnBlock func(w http.ResponseWriter, r *http.Request, d Decision)
}

type rateRule struct{ limit, window int64 }
type loginRule struct{ limit, window, ban int64 }
type probeRule struct {
	exact  map[string]bool
	prefix []string
	ban    int64
}
type challengeRule struct {
	skip   []string
	exempt *ipSet
}

type firewallRules struct {
	enabled   bool
	mode      string
	sync      time.Duration
	allow     *ipSet
	goodbots  *ipSet
	deny      *ipSet
	list      *ipSet
	shared    *ipSet
	banned    *ipSet
	rate      *rateRule
	ban       int64
	login     *loginRule
	probes    *probeRule
	requests  []*requestRule
	limits    *pageLimits
	challenge *challengeRule
}

type firewallEvent struct {
	At        string `json:"at"`
	IP        string `json:"ip"`
	Rule      string `json:"rule"`
	Action    string `json:"action"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	UserAgent string `json:"user_agent"`
	Hits      int64  `json:"hits"`
}

type loginCount struct {
	start time.Time
	count int64
}

// Firewall is the firewall module; Platform.Firewall() gives it for checks
// outside the middleware.
type Firewall struct {
	core      *core
	trust     string
	clientFn  func(*http.Request) string
	mode      string
	counter   func(string, time.Duration) (int64, error)
	cacheFile string
	skip      func(*http.Request) bool
	onBlock   func(http.ResponseWriter, *http.Request, Decision)
	passKey   []byte

	rules atomic.Pointer[firewallRules]
	etag  string

	mu     sync.Mutex
	counts map[ipKey]*[2]int64 // window, hits
	queue  map[string]*firewallEvent
	bans   map[ipKey]time.Time
	logins map[ipKey]*loginCount
	// Page limits: "id window who" -> its count. Limits with each: "path"
	// ("id window who path") keep theirs in pathCounts, a table of their own:
	// one entry per address and page fills a table fast, and it mustn't
	// crowd out the login limit's counts.
	limitCounts, pathCounts map[string]*limitCount
	// When each table was last swept of what has run out: at most once a
	// second, so a flood of new addresses can't make every request sweep.
	countsSwept, bansSwept, loginsSwept, limitsSwept, pathsSwept time.Time
	// With a shared counter: the counts this process saw go over (their
	// key, window and all), so a static file asked for after them can be
	// turned away without adding to them (a counter can only add).
	overNoted map[string]bool
	// With a shared counter: the static files being counted off their
	// requests at once (countStatic). Past it, one is counted on its own
	// request, as a page's count is, so a flood can't pile up goroutines.
	lateSlots chan struct{}

	syncJob  *periodic
	flushJob *periodic
	now      func() time.Time
}

func newFirewall(c *core, o FirewallOptions, trust string, clientFn func(*http.Request) string) *Firewall {
	f := &Firewall{
		core:      c,
		trust:     firstNonEmpty(o.TrustProxy, trust),
		clientFn:  clientFn,
		counter:   o.Counter,
		cacheFile: o.CacheFile,
		skip:      o.Skip,
		onBlock:   o.OnBlock,
		// Passes are signed with the site secret, so any of the site's
		// servers accepts one another handed out.
		passKey:   passKey(c.secret),
		counts:    map[ipKey]*[2]int64{},
		overNoted: map[string]bool{},
		lateSlots: make(chan struct{}, lateSlotsMax),
		queue:     map[string]*firewallEvent{},
		bans:      map[ipKey]time.Time{},
		logins:    map[ipKey]*loginCount{},
		now:       time.Now,

		limitCounts: map[string]*limitCount{},
		pathCounts:  map[string]*limitCount{},
	}
	if o.Mode == "monitor" || o.Mode == "block" {
		f.mode = o.Mode
	}
	if f.cacheFile != "" {
		f.loadCache()
	}
	f.syncJob = c.every(0, f.sync)
	f.flushJob = c.every(firewallFlush, func() time.Duration {
		f.flush(context.Background())
		return firewallFlush
	})
	return f
}

func (f *Firewall) loadCache() {
	data, err := os.ReadFile(f.cacheFile)
	if err != nil {
		return
	}
	var cached struct {
		ETag  string         `json:"etag"`
		Rules map[string]any `json:"rules"`
	}
	if json.Unmarshal(data, &cached) != nil {
		return
	}
	if rules, err := compileFirewall(cached.Rules); err == nil {
		f.rules.Store(rules)
		f.etag = cached.ETag
	}
}

func num(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int:
		return int64(n)
	case int64:
		return n
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}

func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

type unknownVersion struct{}

func (unknownVersion) Error() string { return "unknown rules version" }

func compileFirewall(data map[string]any) (*firewallRules, error) {
	if data == nil || num(data["v"]) != firewallProtocol {
		return nil, unknownVersion{}
	}
	r := &firewallRules{
		enabled:  data["enabled"] == true,
		mode:     "monitor",
		sync:     retryWait,
		allow:    newIPSet(stringList(data["allow"])),
		goodbots: newIPSet(stringList(data["goodbots"])),
		deny:     newIPSet(stringList(data["deny"])),
		list:     newIPSet(stringList(data["lists"])),
		shared:   newIPSet(stringList(data["shared"])),
		banned:   newIPSet(stringList(data["banned"])),
		requests: compileRequestRules(data["requests"]),
		// Page limits: caps on one kind of request (absent in older rules).
		limits: compilePageLimits(data["limits"]),
	}
	if data["mode"] == "block" {
		r.mode = "block"
	}
	if s := num(data["sync"]); s > 0 {
		r.sync = time.Duration(s) * time.Second
	}
	if r.sync < minSync {
		r.sync = minSync
	}
	if rate, ok := data["rate"].(map[string]any); ok && num(rate["limit"]) > 0 {
		window := num(rate["window"])
		if window == 0 {
			window = 60
		}
		if window < 1 {
			window = 1
		}
		r.rate = &rateRule{limit: num(rate["limit"]), window: window}
	}
	if ban, ok := data["ban"].(map[string]any); ok {
		r.ban = num(ban["seconds"])
	}
	if login, ok := data["login"].(map[string]any); ok && num(login["limit"]) > 0 {
		l := &loginRule{limit: num(login["limit"]), window: num(login["window"]), ban: num(login["ban"])}
		if l.window <= 0 {
			l.window = 3600
		}
		if l.ban <= 0 {
			l.ban = 3600
		}
		r.login = l
	}
	if probes, ok := data["probes"].(map[string]any); ok {
		p := &probeRule{exact: map[string]bool{}}
		for _, e := range stringList(probes["exact"]) {
			if e != "" {
				p.exact[strings.ToLower(e)] = true
			}
		}
		for _, e := range stringList(probes["prefix"]) {
			if e != "" {
				p.prefix = append(p.prefix, strings.ToLower(e))
			}
		}
		if len(p.exact) > 0 || len(p.prefix) > 0 {
			if b := num(probes["ban"]); b > 0 {
				p.ban = b
			}
			r.probes = p
		}
	}
	// The browser check: present only when the site is to be checked.
	if check, ok := data["challenge"].(map[string]any); ok {
		skip, _ := check["skip"].([]any)
		r.challenge = &challengeRule{skip: compileSkip(skip), exempt: newIPSet(stringList(check["exempt"]))}
	}
	return r, nil
}

var (
	notHostChar     = regexp.MustCompile(`[^\x21-\x7e]`)
	queryOrFragment = regexp.MustCompile(`[?#]`)
)

// serverNameHeader is this machine's host name for X-Server-Name: plain
// ASCII, 100 characters at most.
func serverNameHeader() string {
	return truncate(notHostChar.ReplaceAllString(hostname(), ""), 100)
}

func (f *Firewall) sync() time.Duration {
	headers := map[string]string{"X-Firewall-Layers": firewallLayers}
	if name := serverNameHeader(); name != "" {
		headers["X-Server-Name"] = name
	}
	if f.etag != "" {
		headers["If-None-Match"] = f.etag
	}
	res := f.core.send(context.Background(), "firewall", "/events/firewall/rules?site_id="+url.QueryEscape(f.core.siteID), http.MethodGet, nil, authBearer, headers)
	if res != nil && res.status == http.StatusOK {
		var data map[string]any
		if !res.json(&data) {
			f.core.log("firewall", "rules not used: not JSON")
		} else if rules, err := compileFirewall(data); err != nil {
			f.core.log("firewall", "rules not used: %v", err)
		} else {
			f.rules.Store(rules)
			f.etag = res.header.Get("ETag")
			if f.cacheFile != "" {
				if out, err := json.Marshal(map[string]any{"etag": f.etag, "rules": data}); err == nil {
					if err := os.WriteFile(f.cacheFile, out, 0o600); err != nil {
						f.core.log("firewall", "rules not cached: %v", err)
					}
				}
			}
		}
	}
	if rules := f.rules.Load(); rules != nil {
		return rules.sync
	}
	return retryWait
}

// localKey is what the counts and bans here go by: an IPv4 address, or an
// IPv6 address's /64, which is one machine's (a host picks any address in
// it, so counting each would let it walk past the limit and every ban).
func localKey(k ipKey) ipKey {
	if k.hi == 0 && k.lo>>32 == 0xFFFF {
		return k
	}
	return ipKey{k.hi, 0}
}

// localName is localKey as text, for the shared counter's key:
// "198.51.100.7" or "2001:db8:1:2::/64", the same for every spelling.
func localName(k ipKey) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], k.hi)
	binary.BigEndian.PutUint64(b[8:], k.lo)
	addr := netip.AddrFrom16(b)
	if addr.Is4In6() {
		return addr.Unmap().String()
	}
	return addr.String() + "/64"
}

// room says whether a table at size may take one more entry (f.mu held).
// A full table is swept of what has run out, at most once a second; what
// is still live is never dropped, so a new entry is refused instead.
func (f *Firewall) room(size int, swept *time.Time, sweep func(now time.Time)) bool {
	if size < counterMax {
		return true
	}
	now := f.now()
	if now.Sub(*swept) < time.Second {
		return false
	}
	*swept = now
	sweep(now)
	return false
}

// overRate counts the request toward the rate. peek: only compared with
// the count so far, nothing added (a static file).
func (f *Firewall) overRate(key ipKey, rate *rateRule, peek bool) bool {
	key = localKey(key)
	window := f.now().Unix() / rate.window
	if f.counter != nil {
		name := "afw:" + f.core.siteID + ":" + localName(key) + ":" + strconv.FormatInt(window, 10)
		if peek {
			// Seen over, else the count kept here while the counter failed.
			if f.noted(name) {
				return true
			}
		} else {
			hits, err := f.counter(name, time.Duration(rate.window*2)*time.Second)
			if err == nil {
				return f.noteOver(name, hits > rate.limit)
			}
			f.core.log("firewall", "shared counter failed, counted here: %v", err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := f.counts[key]
	if peek {
		return entry != nil && entry[0] == window && entry[1] > rate.limit
	}
	if entry == nil || entry[0] != window {
		if entry == nil && !f.room(len(f.counts), &f.countsSwept, func(time.Time) {
			for k, e := range f.counts {
				if e[0] != window {
					delete(f.counts, k)
				}
			}
		}) && len(f.counts) >= counterMax {
			return false // full of live counts: this one isn't counted here
		}
		entry = &[2]int64{window, 0}
		f.counts[key] = entry
	}
	entry[1]++
	return entry[1] > rate.limit
}

// noted: whether this process saw the shared count name go over.
func (f *Firewall) noted(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.overNoted[name]
}

// noteOver remembers a shared count seen over, under its key (window and
// all, so an old one never matches again), for a static file's peek.
func (f *Firewall) noteOver(name string, over bool) bool {
	if over {
		f.mu.Lock()
		if !f.overNoted[name] {
			if len(f.overNoted) >= counterMax {
				for k := range f.overNoted {
					delete(f.overNoted, k)
					break
				}
			}
			f.overNoted[name] = true
		}
		f.mu.Unlock()
	}
	return over
}

func (f *Firewall) bannedHere(key ipKey) bool {
	key = localKey(key)
	f.mu.Lock()
	defer f.mu.Unlock()
	until, ok := f.bans[key]
	if !ok {
		return false
	}
	if until.After(f.now()) {
		return true
	}
	delete(f.bans, key)
	return false
}

func (f *Firewall) banHere(key ipKey, seconds int64) {
	if seconds <= 0 {
		return
	}
	key = localKey(key)
	f.mu.Lock()
	defer f.mu.Unlock()
	until := f.now().Add(time.Duration(seconds) * time.Second)
	current, banned := f.bans[key]
	if !banned && !f.room(len(f.bans), &f.bansSwept, func(now time.Time) {
		for k, u := range f.bans {
			if !u.After(now) {
				delete(f.bans, k)
			}
		}
	}) && len(f.bans) >= counterMax {
		f.core.log("firewall", "too many addresses banned here; this one is banned through the report only")
		return
	}
	if until.After(current) {
		f.bans[key] = until
	}
}

// LoginFailed counts a failed login on your site from ip: past the site's
// limit the address is banned here straight away, and it is reported, so it
// counts on the Security page and gets banned on the other servers too.
func (f *Firewall) LoginFailed(ip string) {
	if f == nil {
		return
	}
	key, ok := ipKeyOf(ip)
	rules := f.rules.Load()
	if !ok || (rules != nil && rules.allow.has(key)) {
		return
	}
	if rules != nil && rules.login != nil {
		login := rules.login
		local := localKey(key)
		window := time.Duration(login.window) * time.Second
		now := f.now()
		reached := false
		f.mu.Lock()
		entry := f.logins[local]
		if entry == nil || now.Sub(entry.start) >= window {
			if entry != nil || f.room(len(f.logins), &f.loginsSwept, func(now time.Time) {
				for k, e := range f.logins {
					if now.Sub(e.start) >= window {
						delete(f.logins, k)
					}
				}
			}) || len(f.logins) < counterMax {
				entry = &loginCount{start: now}
				f.logins[local] = entry
			} else {
				entry = nil
			}
		}
		if entry != nil {
			entry.count++
			reached = entry.count >= login.limit
			if reached {
				delete(f.logins, local)
			}
		}
		f.mu.Unlock()
		if reached {
			f.banHere(key, login.ban)
		}
	}
	f.report(firewallEvent{IP: ip, Rule: "login", Action: "monitor"})
}

func (f *Firewall) report(e firewallEvent) {
	key := e.IP + "|" + e.Rule + "|" + e.Action + "|" + e.Method + "|" + e.Path
	f.mu.Lock()
	defer f.mu.Unlock()
	if row := f.queue[key]; row != nil {
		row.Hits++
		return
	}
	if len(f.queue) >= firewallQueueMax {
		return
	}
	e.At = isoNow()
	e.Hits = 1
	f.queue[key] = &e
}

func (f *Firewall) flush(ctx context.Context) {
	f.mu.Lock()
	rows := make([]*firewallEvent, 0, len(f.queue))
	for _, row := range f.queue {
		rows = append(rows, row)
	}
	f.queue = map[string]*firewallEvent{}
	f.mu.Unlock()
	for i := 0; i < len(rows); i += firewallBatch {
		end := i + firewallBatch
		if end > len(rows) {
			end = len(rows)
		}
		f.core.send(ctx, "firewall", "/events/firewall/events", http.MethodPost,
			map[string]any{"site_id": f.core.siteID, "events": rows[i:end]}, authBearer, nil)
	}
}

// staticFile: files a page load asks for by the dozen, not counted against
// the rate or the page limits (the agent's nginx limit leaves the same
// extensions out), so a page with 40 images, scripts and fonts is one hit,
// not 41; and the asset folders, /static/ where a Go app's http.FileServer
// usually sits (firewall.md, `rate`). The extension must follow a name in
// the last segment, not start it: "/login/.css" is no file.
var staticFile = regexp.MustCompile(`/[^/.][^/]*\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf|wasm)$`)

var staticPrefixes = []string{"/static/", "/_next/static/", "/assets/"}

// unsure, in a path decoded once: a "%xx" still there (double encoding,
// which a router that decodes again reads differently), a ";" (a path
// parameter to some servers and proxies, part of the name to others), a
// "\" (a "/" to some), a "?" or "#" that was encoded, or a control character. encodedSlash, in the path as sent: "%2F", a "/" to
// some routers and part of a segment to others.
var (
	unsure       = regexp.MustCompile(`%[0-9a-fA-F]{2}|[;\\?#\x00-\x1f\x7f]`)
	encodedSlash = regexp.MustCompile(`(?i)%2f`)
)

// staticAsset reads the path as r.URL.Path has it (decoded once, lower case,
// "//" as "/"), and only a path every router reads the same way can be a
// file: one with a "." or ".." segment, a ";", a "\", an encoded "/" or a
// "%xx" left after decoding is a page, so "/static/../login",
// "/static%2F..%2Flogin", "/login;x.css" and "/login%3Bx.css" all count. A
// browser asks for its files with none of those. Nor is a path past 2,000
// characters a file: no asset has a name that long. Only GET and HEAD
// fetch a file (no method given is read as GET): a form posts to a page, and
// some routers read /login.css as /login.
func staticAsset(target, method string) bool {
	if method != "" && method != http.MethodGet && method != http.MethodHead {
		return false
	}
	if loc := queryOrFragment.FindStringIndex(target); loc != nil {
		target = target[:loc[0]]
	}
	if len(target) > maxRuleText || !strings.HasPrefix(target, "/") || encodedSlash.MatchString(target) {
		return false
	}
	decoded := decodeOnce(target)
	if unsure.MatchString(decoded) {
		return false
	}
	// A-Z only, as every package: strings.ToLower reads "İ" as "i".
	segments := strings.Split(asciiLower(decoded), "/")
	parts := make([]string, 0, len(segments))
	for _, seg := range segments {
		if seg == "." || seg == ".." {
			return false
		}
		if seg != "" {
			parts = append(parts, seg)
		}
	}
	path := "/" + strings.Join(parts, "/")
	if len(parts) > 0 && segments[len(segments)-1] == "" {
		path += "/" // "/app.css/" isn't a file
	}
	for _, prefix := range staticPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return staticFile.MatchString(path)
}

// asciiLower: A-Z as a-z, nothing else.
func asciiLower(text string) string {
	out := []byte(text)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}
	return string(out)
}

// isProbe: the path (no query, lower-cased, "//" as "/") is a probe, as
// sent or as the router reads it ("/x/..;/.env" is "/.env").
func isProbe(target string, p *probeRule) bool {
	if p == nil {
		return false
	}
	clean := target
	if loc := queryOrFragment.FindStringIndex(clean); loc != nil {
		clean = clean[:loc[0]]
	}
	clean = repeatedSlashes.ReplaceAllString(strings.ToLower(clean), "/")
	for _, text := range []string{clean, normalizeTarget(target)} {
		if p.exact[text] {
			return true
		}
		for _, prefix := range p.prefix {
			if strings.HasPrefix(text, prefix) {
				return true
			}
		}
	}
	return false
}

// crossSite: another site made the browser send this request (an <img> of
// /.env, a no-cors fetch, a link), from the visitor's own address. A probe,
// a request rule or the rate still refuses it, but it bans no one here, and
// it is reported as watched, so the collector bans it nowhere else and
// counts it toward nothing shared (firewall.md, "Checking a request"). A
// client that forges the header only gives up the ban.
func crossSite(secFetchSite string) bool {
	site := strings.TrimSpace(secFetchSite)
	return strings.EqualFold(site, "cross-site") || strings.EqualFold(site, "same-site")
}

// Check decides on one request. Allowed addresses skip every other rule.
// Accept and Cookie (the request's headers) are for the browser check: rule
// "challenge", status 503, answered with the check page.
func (f *Firewall) Check(in CheckInput) Decision {
	return f.check(in, f.now())
}

func (f *Firewall) check(in CheckInput, now time.Time) Decision {
	allow := Decision{Action: "allow", Status: http.StatusOK}
	if f == nil {
		return allow
	}
	rules := f.rules.Load()
	if rules == nil || !rules.enabled {
		return allow
	}
	key, ok := ipKeyOf(in.IP)
	if !ok || rules.allow.has(key) {
		return allow
	}
	mode := rules.mode
	if f.mode != "" {
		mode = f.mode
	}
	action := "monitor"
	if mode == "block" {
		action = "block"
	}
	// Refused as below, but never banned (crossSite).
	bans := !crossSite(in.SecFetchSite)
	rule := f.addressRule(rules, key)
	if rule == "" && isProbe(in.Target, rules.probes) {
		rule = "probe"
		// Asking for a secret file: banned here in block mode; the report
		// bans it on the other servers.
		if action == "block" && bans {
			f.banHere(key, rules.probes.ban)
		}
	}
	var req *preparedRequest
	if rule == "" && (len(rules.requests) > 0 || rules.limits != nil) {
		req = prepareRequest(in.Method, in.Target, in.UserAgent)
	}
	if rule == "" && len(rules.requests) > 0 {
		if matched := matchPrepared(rules.requests, req); matched != nil {
			rule = "request:" + matched.id
			// A rule the dashboard only watches passes even in block mode;
			// one that blocks also bans the address here, as a flood does.
			if !(action == "block" && matched.action == "block") {
				action = "monitor"
			}
			if action == "block" && matched.ban > 0 && bans {
				f.banHere(key, matched.ban)
			}
		}
	}
	event := func(name, act string) firewallEvent {
		path := in.Target
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		// What another site made the browser send is reported as watched,
		// so the report bans it on no other server.
		if !bans && act == "block" && (name == "probe" || name == "rate" || strings.HasPrefix(name, "request:")) {
			act = "monitor"
		}
		return firewallEvent{IP: in.IP, Rule: name, Action: act, Method: truncate(in.Method, 10),
			Path: truncate(path, 300), UserAgent: truncate(in.UserAgent, 300)}
	}
	// A static file isn't counted toward the page limits or the rate, only
	// compared with the counts so far: an address already over them is
	// turned away for its files too. It counts after the response when the
	// router sent it to a page after all ("/search/{q}" took
	// "/search/x.css") or it answered an error (countStatic).
	static := staticAsset(in.Target, in.Method)
	lateRate, lateLimits := false, false
	// Page limits (step 6). Never banned: a shopper who refreshes checkout
	// too often is a customer, and the cap lifts when the window ends.
	var watched *pageLimit
	retryAfter := int64(0)
	if rule == "" && rules.limits != nil && !rules.goodbots.has(key) && !rules.limits.exempt.has(key) {
		lateLimits = static
		for _, limit := range f.overLimits(key, rules.limits.rules, req, static) {
			if action == "block" && limit.action == "block" {
				rule, retryAfter = "limit:"+limit.id, limit.window
				break
			}
			// Only watched: reported, and the check goes on to the rate,
			// so watching the login page doesn't let a flood through it
			// untouched.
			if watched == nil {
				watched = limit
			}
		}
		if rule != "" {
			watched = nil
		}
	}
	if rule == "" && rules.rate != nil && !rules.goodbots.has(key) {
		lateRate = static
	}
	if rule == "" && rules.rate != nil && !rules.goodbots.has(key) && f.overRate(key, rules.rate, static) {
		rule, retryAfter = "rate", rules.rate.window
		// Banned here straight away in block mode, as a probe is; the report
		// bans it on the other servers.
		if action == "block" && bans {
			f.banHere(key, rules.ban)
		}
	}
	if watched != nil {
		if rule == "" {
			rule, action, retryAfter = "limit:"+watched.id, "monitor", watched.window
		} else {
			// The rate decides; the watched limit is reported as well.
			f.report(event("limit:"+watched.id, "monitor"))
		}
	}
	// Not a mode matter: the collector only sends `challenge` when the site
	// is to be checked, and a match only watched (monitor) gets it too
	// (firewall.md, step 8).
	if (rule == "" || action != "block") && f.needsCheck(rules, key, in, now) {
		if rule != "" {
			f.report(event(rule, action))
		}
		rule, action, retryAfter = "challenge", "block", 0
	}
	// What countStatic needs after the response of a static file that goes on to the app.
	var late *lateHit
	if (lateRate || lateLimits) && (rule == "" || action != "block") {
		late = &lateHit{key: key, rate: lateRate}
		if lateLimits {
			late.req = req
		}
	}
	if rule == "" {
		allow.late = late
		return allow
	}
	f.report(event(rule, action))
	status := http.StatusForbidden
	if retryAfter > 0 {
		status = http.StatusTooManyRequests
	} else if rule == "challenge" {
		status = http.StatusServiceUnavailable
	}
	return Decision{Action: action, Rule: rule, Status: status, RetryAfter: retryAfter, late: late}
}

// countStatic: after the response to a static file Check let through (its
// decision's late hit), counted toward the rate and the page limits it
// skipped when it answered 400 or more (a flood of made-up file names) or
// the router sent it to a route that isn't a file's (routed), unless it
// answered 304 (a browser checking a file it keeps). In memory, or one
// call to the shared counter, after the handler has written its answer.
func (f *Firewall) countStatic(late *lateHit, status int, routed bool) {
	if f == nil || late == nil || !countsLate(status, routed) {
		return
	}
	rules := f.rules.Load()
	if rules == nil {
		return
	}
	if late.rate && rules.rate != nil {
		f.overRate(late.key, rules.rate, false)
	}
	if late.req != nil && rules.limits != nil {
		f.overLimits(late.key, rules.limits.rules, late.req, false)
	}
}

// lateSlotsMax: the static files counted in goroutines at once with a
// shared counter.
const lateSlotsMax = 64

// countsLate: whether a static file Check let through counts after its
// response: it answered 400 or more, or a route that isn't a file's took it
// and it didn't answer 304.
func countsLate(status int, routed bool) bool {
	return status >= 400 || (routed && status != http.StatusNotModified)
}

// fileTypes: a response's Content-Type that is a file's (an image, a font,
// a script, a stylesheet, a video, a PDF, a download), what a route
// serving files answers (http.FileServer, gin's Static, echo's Static).
var fileTypes = regexp.MustCompile(`(?i)^(?:image|font|audio|video)/|^text/css|javascript|^application/(?:wasm|pdf|octet-stream|vnd\.ms-fontobject|(?:x-)?font)`)

// routedToPage: whether the router sent a static-looking request to a
// route of its own that isn't a file's. pattern: the route it took
// (ServeMux's "GET /search/{q}", gin's FullPath, chi's RoutePattern, echo's
// Path), "" when none. A pattern that is itself a file's by the static rule
// ("/static/", "/assets/*filepath") is left alone, and so is a route that
// answered a file's Content-Type (a file server under "/" or "/public/").
func routedToPage(pattern, contentType string) bool {
	if pattern == "" || fileTypes.MatchString(strings.TrimSpace(contentType)) {
		return false
	}
	// ServeMux's "[METHOD ][HOST]/path": the path from its first "/".
	if i := strings.IndexByte(pattern, '/'); i > 0 {
		pattern = pattern[i:]
	}
	return !staticAsset(pattern, "")
}

// addressRule is steps 2 to 5: the address alone.
func (f *Firewall) addressRule(rules *firewallRules, key ipKey) string {
	switch {
	case rules.deny.has(key):
		return "deny"
	case rules.banned.has(key) || f.bannedHere(key):
		return "ban"
	case rules.list.has(key):
		return "list"
	case rules.shared.has(key):
		return "shared"
	}
	return ""
}

// checkAddress decides on the address alone, for the proxy's own paths:
// a denied or banned address gets nothing of ours either, but a beacon is
// neither rate limited nor sent the browser check.
func (f *Firewall) checkAddress(in CheckInput) Decision {
	allow := Decision{Action: "allow", Status: http.StatusOK}
	if f == nil {
		return allow
	}
	rules := f.rules.Load()
	if rules == nil || !rules.enabled {
		return allow
	}
	key, ok := ipKeyOf(in.IP)
	if !ok || rules.allow.has(key) {
		return allow
	}
	rule := f.addressRule(rules, key)
	if rule == "" {
		return allow
	}
	mode := rules.mode
	if f.mode != "" {
		mode = f.mode
	}
	action := "monitor"
	if mode == "block" {
		action = "block"
	}
	path := in.Target
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	f.report(firewallEvent{IP: in.IP, Rule: rule, Action: action, Method: truncate(in.Method, 10),
		Path: truncate(path, 300), UserAgent: truncate(in.UserAgent, 300)})
	return Decision{Action: action, Rule: rule, Status: http.StatusForbidden}
}

// needsCheck is step 8: the browser check is on, the request asks for a page
// outside skip, the address is in none of allow (already passed), goodbots
// and exempt, and it has no valid pass.
func (f *Firewall) needsCheck(rules *firewallRules, key ipKey, in CheckInput, now time.Time) bool {
	check := rules.challenge
	if check == nil || !asksForPage(in.Method, in.Target, in.Accept, check.skip) {
		return false
	}
	if rules.goodbots.has(key) || check.exempt.has(key) {
		return false
	}
	return !hasPass(f.passKey, in.IP, in.Cookie, now)
}

func (f *Firewall) retryAfter() string {
	if rules := f.rules.Load(); rules != nil && rules.rate != nil {
		return strconv.FormatInt(rules.rate.window, 10)
	}
	return "60"
}

// ClientIP is the visitor's address for r, as TrustProxy says.
func (f *Firewall) ClientIP(r *http.Request) string {
	if f != nil && f.clientFn != nil {
		if ip := f.clientFn(r); ip != "" {
			return ip
		}
	}
	trust := ""
	if f != nil {
		trust = f.trust
	}
	return clientIPOf(remoteHost(r.RemoteAddr), r.Header, trust)
}

func (f *Firewall) flushNow(ctx context.Context) { f.flush(ctx) }

func (f *Firewall) close(ctx context.Context) {
	f.syncJob.halt(ctx)
	f.flushJob.halt(ctx)
	f.flush(ctx)
}

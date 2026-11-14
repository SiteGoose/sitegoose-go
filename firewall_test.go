package sitegoose

// The firewall: the shared request-rule cases, Cloudflare's ranges against
// sdk/protocols/cloudflare-ranges.json, the client address, and the order of
// the steps in firewall.md.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type sharedRequestRules struct {
	Rules    []any `json:"rules"`
	Requests []struct {
		Why    string  `json:"why"`
		Method string  `json:"method"`
		Target string  `json:"target"`
		UA     string  `json:"ua"`
		Expect *string `json:"expect"`
	} `json:"requests"`
	Patterns struct {
		Refused []string `json:"refused"`
		Allowed []string `json:"allowed"`
	} `json:"patterns"`
}

func TestSharedRequestRules(t *testing.T) {
	var cases sharedRequestRules
	readShared(t, "request-rules-cases.json", &cases)
	rules := compileRequestRules(map[string]any{"rules": cases.Rules})
	for _, c := range cases.Requests {
		got := matchRequest(rules, c.Method, c.Target, c.UA)
		want := ""
		if c.Expect != nil {
			want = *c.Expect
		}
		id := ""
		if got != nil {
			id = got.id
		}
		if id != want {
			t.Errorf("%s: matched %q, want %q", c.Why, id, want)
		}
	}
}

func TestSharedPatterns(t *testing.T) {
	var cases sharedRequestRules
	readShared(t, "request-rules-cases.json", &cases)
	for _, p := range cases.Patterns.Refused {
		if safePattern(p) {
			t.Errorf("%q allowed, should be refused", p)
		}
	}
	for _, p := range cases.Patterns.Allowed {
		if !safePattern(p) {
			t.Errorf("%q refused, should be allowed", p)
		}
	}
}

func TestRequestRulesDropWhatTheyCannotUse(t *testing.T) {
	rules := compileRequestRules(map[string]any{"rules": []any{
		map[string]any{"id": "body", "action": "block", "body": map[string]any{"contains": []any{"x"}}},
		map[string]any{"id": "unsafe", "action": "block", "path": map[string]any{"regex": "(a+)+b"}},
		map[string]any{"id": "empty", "action": "block"},
		map[string]any{"id": "ok", "action": "block", "methods": []any{"post"}, "path": map[string]any{"prefix": []any{"/x"}}},
	}})
	if len(rules) != 1 || rules[0].id != "ok" {
		t.Fatalf("%+v", rules)
	}
	if matchRequest(rules, "GET", "/x", "") != nil || matchRequest(rules, "POST", "/x", "") == nil {
		t.Fatal("methods not applied")
	}
	many := make([]any, 250)
	for i := range many {
		many[i] = map[string]any{"id": "r", "action": "block", "path": map[string]any{"exact": []any{"/a"}}}
	}
	if got := len(compileRequestRules(map[string]any{"rules": many})); got != maxRequestRules {
		t.Fatalf("kept %d", got)
	}
}

func TestRequestTargetIsTheRawTarget(t *testing.T) {
	r := httptest.NewRequest("GET", "/a/..%2fb?q=1", nil)
	if got := requestTarget(r); got != "/a/..%2fb?q=1" {
		t.Fatal(got)
	}
	r.RequestURI = "http://example.com/x?y"
	if got := requestTarget(r); got != "/x?y" {
		t.Fatal(got)
	}
}

// Every target in the shared cases, as net/http routes it: "x:/admin" is
// /admin to ServeMux, so it is /admin to the rules too.
func TestSharedTargets(t *testing.T) {
	var cases struct {
		Targets []struct {
			Target string `json:"target"`
			Origin string `json:"origin"`
		} `json:"targets"`
	}
	readShared(t, "request-rules-cases.json", &cases)
	if len(cases.Targets) == 0 {
		t.Fatal("no targets")
	}
	r := httptest.NewRequest("GET", "/", nil)
	for _, c := range cases.Targets {
		if got := originForm(c.Target); got != c.Origin {
			t.Errorf("%q: %q, want %q", c.Target, got, c.Origin)
		}
		if c.Target == "*" {
			continue
		}
		r.RequestURI = c.Target
		if got := requestTarget(r); got != c.Origin {
			t.Errorf("requestTarget %q: %q, want %q", c.Target, got, c.Origin)
		}
	}
	rules := compileRequestRules(map[string]any{"rules": []any{
		map[string]any{"id": "admin", "action": "block", "path": map[string]any{"prefix": []any{"/admin"}}},
	}})
	r.RequestURI = "x:/admin/export"
	if matchRequest(rules, "GET", requestTarget(r), "") == nil {
		t.Fatal("x:/admin/export got past a rule on /admin")
	}
}

// A regex is searched in windows of 2,000 characters every 1,000; "^" only
// in the first, "$" only in the last. The plain matchers read it all.
func TestRegexWindows(t *testing.T) {
	section := func(pattern string) *ruleSection {
		s := compileSection(map[string]any{"regex": pattern})
		if s == nil {
			t.Fatal(pattern)
		}
		return s
	}
	pad := strings.Repeat("x", 3500)
	for _, c := range []struct {
		pattern, text string
		want          bool
	}{
		{"evil", "evil", true},
		{"evil", pad + "evil" + pad, true},
		{"evil", strings.Repeat("é", 2500) + "evil", true},
		{"^evil", "evil" + pad, true},
		{"^evil", pad + "evil", false},
		{"^evil", "x" + "evil", false},
		{"evil$", pad + "evil", true},
		{"evil$", "evil" + pad, false},
		{`evil\$`, pad + "evil$" + pad, true},
		{"^evil$", "evil", true},
		{"^x+$", pad, false},
		{"^x+$", strings.Repeat("x", 2000), true},
		// A match that spans a window's edge is still inside the next one.
		{"a.{900}b", strings.Repeat("x", 1500) + "a" + strings.Repeat("y", 900) + "b" + pad, true},
	} {
		if got := section(c.pattern).hits(c.text); got != c.want {
			t.Errorf("%q in %d characters: %v, want %v", c.pattern, len([]rune(c.text)), got, c.want)
		}
	}
	plain := compileSection(map[string]any{"exact": []any{pad}, "suffix": []any{".php"}})
	if !plain.hits(pad) || !plain.hits(pad+"/x.php") {
		t.Fatal("a plain matcher stopped at 2,000 characters")
	}
}

// What another site made the browser send is refused, but bans no one and
// is reported as watched (firewall.md, "Checking a request").
func TestCrossSiteRequestsAreRefusedNotBanned(t *testing.T) {
	data := map[string]any{"v": 1, "enabled": true, "mode": "block",
		"probes":   map[string]any{"exact": []any{"/.env"}, "ban": 600},
		"rate":     map[string]any{"limit": 2, "window": 60},
		"ban":      map[string]any{"seconds": 600},
		"requests": map[string]any{"rules": []any{map[string]any{"id": "shell", "action": "block", "ban": 600, "path": map[string]any{"exact": []any{"/shell.php"}}}}},
	}
	actions := func(f *Firewall) map[string]string {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := map[string]string{}
		for _, e := range f.queue {
			out[e.Rule] = e.Action
		}
		return out
	}
	for _, site := range []string{"cross-site", "Same-Site"} {
		f := testFirewall(t, "s", data, FirewallOptions{})
		for _, target := range []string{"/.env", "/shell.php"} {
			if d := f.Check(CheckInput{IP: "6.6.6.6", Method: "GET", Target: target, SecFetchSite: site}); d.Action != "block" || d.Status != 403 {
				t.Fatalf("%s %s: %+v", site, target, d)
			}
		}
		var last Decision
		for i := 0; i < 3; i++ {
			last = f.Check(CheckInput{IP: "6.6.6.7", Method: "GET", Target: "/", SecFetchSite: site})
		}
		if last.Rule != "rate" || last.Action != "block" || last.Status != 429 {
			t.Fatalf("%s: %+v", site, last)
		}
		if f.bannedHere(mustKey(t, "6.6.6.6")) || f.bannedHere(mustKey(t, "6.6.6.7")) {
			t.Fatalf("%s: banned", site)
		}
		got := actions(f)
		if got["probe"] != "monitor" || got["request:shell"] != "monitor" || got["rate"] != "monitor" {
			t.Fatalf("%s: reported %v", site, got)
		}
	}
	// same-origin, none or no header: banned and reported as before.
	for _, site := range []string{"same-origin", "none", ""} {
		f := testFirewall(t, "s", data, FirewallOptions{})
		f.Check(CheckInput{IP: "6.6.6.6", Method: "GET", Target: "/.env", SecFetchSite: site})
		if !f.bannedHere(mustKey(t, "6.6.6.6")) || actions(f)["probe"] != "block" {
			t.Fatalf("%q: not banned, reported %v", site, actions(f))
		}
	}
}

// The middleware hands the firewall the request's Sec-Fetch-Site.
func TestMiddlewareCarriesSecFetchSite(t *testing.T) {
	p := checkPlatform(t, nil, map[string]any{"mode": "block", "probes": map[string]any{"exact": []any{"/.env"}, "ban": 600}})
	defer p.Close(context.Background())
	h := p.Middleware(theSite)
	if res := call(h, "GET", "/.env", "image/*", map[string][]string{"Sec-Fetch-Site": {"cross-site"}}); res.StatusCode != 403 {
		t.Fatal(res.StatusCode)
	}
	if res := call(h, "GET", "/", "text/html", nil); res.StatusCode != 200 {
		t.Fatal("banned by a cross-site request", res.StatusCode)
	}
	call(h, "GET", "/.env", "*/*", nil)
	if res := call(h, "GET", "/", "text/html", nil); res.StatusCode != 403 {
		t.Fatal("a probe of its own wasn't banned", res.StatusCode)
	}
}

func TestCloudflareRangesMatchTheSharedList(t *testing.T) {
	var shared struct {
		Ranges []string `json:"ranges"`
	}
	readShared(t, "cloudflare-ranges.json", &shared)
	if strings.Join(shared.Ranges, " ") != strings.Join(cloudflareRanges, " ") {
		t.Fatalf("Cloudflare's ranges differ from sdk/protocols/cloudflare-ranges.json:\n%v\n%v", shared.Ranges, cloudflareRanges)
	}
}

func TestClientIP(t *testing.T) {
	h := http.Header{}
	h.Add("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	h.Add("X-Forwarded-For", "3.3.3.3")
	h.Set("CF-Connecting-IP", "9.9.9.9")
	for _, c := range []struct{ remote, trust, want string }{
		{"10.0.0.1", "", "10.0.0.1"},
		{"10.0.0.1", "false", "10.0.0.1"},
		{"10.0.0.1", "1", "3.3.3.3"},
		{"10.0.0.1", "true", "3.3.3.3"},
		{"10.0.0.1", "2", "2.2.2.2"},
		{"10.0.0.1", "9", "1.1.1.1"},
		{"10.0.0.1", "cloudflare", "10.0.0.1"},
		{"173.245.48.7", "cloudflare", "9.9.9.9"},
		{"2606:4700::1", "cloudflare", "9.9.9.9"},
		{"::ffff:173.245.48.7", "cloudflare", "9.9.9.9"},
	} {
		if got := clientIPOf(c.remote, h, c.trust); got != c.want {
			t.Errorf("%s trust %q: %s, want %s", c.remote, c.trust, got, c.want)
		}
	}
	if got := clientIPOf("10.0.0.1", http.Header{}, "1"); got != "10.0.0.1" {
		t.Fatal(got)
	}
	if got := remoteHost("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatal(got)
	}
}

func TestIPSets(t *testing.T) {
	set := newIPSet([]string{"10.0.0.0/8", "2001:db8::/32", "::ffff:192.0.2.0/120", "203.0.113.9", "junk", "::/0", "::/64"})
	for ip, want := range map[string]bool{
		"10.2.3.4": true, "11.0.0.1": false, "2001:db8::5": true, "2001:db9::": false,
		"192.0.2.77": true, "::ffff:10.9.9.9": true, "203.0.113.9": true, "203.0.113.10": false,
		"fe80::1%eth0": false, "8.8.8.8": false,
	} {
		key, ok := ipKeyOf(ip)
		if !ok {
			t.Fatalf("%s didn't parse", ip)
		}
		if got := set.has(key); got != want {
			t.Errorf("%s: %v, want %v (an IPv6 range holding all IPv4 is dropped)", ip, got, want)
		}
	}
}

func TestStepsInOrder(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{
		"v": 1, "enabled": true, "mode": "block",
		"allow": []any{"1.1.1.1"}, "deny": []any{"2.2.2.2", "1.1.1.1"}, "banned": []any{"3.3.3.3"},
		"lists": []any{"4.4.4.0/24"}, "shared": []any{"5.5.5.5"},
		"probes": map[string]any{"exact": []any{"/.env"}, "prefix": []any{"/.git/"}, "ban": 600},
	}, FirewallOptions{})
	for _, c := range []struct{ ip, target, rule string }{
		{"1.1.1.1", "/.env", ""}, {"2.2.2.2", "/", "deny"}, {"3.3.3.3", "/", "ban"},
		{"4.4.4.200", "/", "list"}, {"5.5.5.5", "/", "shared"}, {"6.6.6.6", "//.GIT/config", "probe"},
		{"6.6.6.6", "/", "ban"}, {"7.7.7.7", "/", ""},
	} {
		d := f.Check(CheckInput{IP: c.ip, Method: "GET", Target: c.target})
		if d.Rule != c.rule {
			t.Errorf("%s %s: %q, want %q", c.ip, c.target, d.Rule, c.rule)
		}
		if c.rule != "" && (d.Action != "block" || d.Status != 403) {
			t.Errorf("%s: %+v", c.ip, d)
		}
	}
}

func TestDisabledOrNoRulesAllowsEverything(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": false, "deny": []any{"2.2.2.2"}}, FirewallOptions{})
	if d := f.Check(CheckInput{IP: "2.2.2.2"}); d.Action != "allow" {
		t.Fatal(d)
	}
	empty := newFirewall(offlineCore("s"), FirewallOptions{}, "", nil)
	if d := empty.Check(CheckInput{IP: "2.2.2.2"}); d.Action != "allow" {
		t.Fatal(d)
	}
	if _, err := compileFirewall(map[string]any{"v": 2}); err == nil {
		t.Fatal("an unknown version was used")
	}
}

func TestMonitorModeReportsButLetsThrough(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "deny": []any{"2.2.2.2"},
		"probes": map[string]any{"exact": []any{"/.env"}}}, FirewallOptions{})
	if d := f.Check(CheckInput{IP: "2.2.2.2", Method: "GET", Target: "/a?b=1"}); d.Action != "monitor" || d.Rule != "deny" {
		t.Fatal(d)
	}
	f.Check(CheckInput{IP: "6.6.6.6", Target: "/.env"})
	if f.bannedHere(mustKey(t, "6.6.6.6")) {
		t.Fatal("a probe banned in monitor mode")
	}
	// The local option overrides the dashboard's mode.
	strict := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "deny": []any{"2.2.2.2"}}, FirewallOptions{Mode: "block"})
	if d := strict.Check(CheckInput{IP: "2.2.2.2"}); d.Action != "block" {
		t.Fatal(d)
	}
	row := f.queue["2.2.2.2|deny|monitor|GET|/a"]
	if row == nil || row.Hits != 1 {
		t.Fatalf("%v", f.queue)
	}
}

func mustKey(t *testing.T, ip string) ipKey {
	key, ok := ipKeyOf(ip)
	if !ok {
		t.Fatal(ip)
	}
	return key
}

func TestRateLimitBansInBlockMode(t *testing.T) {
	data := map[string]any{"v": 1, "enabled": true, "mode": "block", "rate": map[string]any{"limit": 3, "window": 60},
		"ban": map[string]any{"seconds": 600}, "goodbots": []any{"66.249.66.1"}}
	f := testFirewall(t, "s", data, FirewallOptions{})
	var last Decision
	for i := 0; i < 4; i++ {
		last = f.Check(CheckInput{IP: "8.8.8.8"})
	}
	if last.Rule != "rate" || last.Status != 429 {
		t.Fatal(last)
	}
	if d := f.Check(CheckInput{IP: "8.8.8.8"}); d.Rule != "ban" {
		t.Fatal("not banned after the rate limit", d)
	}
	for i := 0; i < 10; i++ {
		if d := f.Check(CheckInput{IP: "66.249.66.1"}); d.Action != "allow" {
			t.Fatal("a good bot was rate limited")
		}
	}
	if f.retryAfter() != "60" {
		t.Fatal(f.retryAfter())
	}
	// A shared counter counts for every server; one that fails falls back here.
	var keys []string
	shared := testFirewall(t, "s", data, FirewallOptions{Counter: func(key string, ttl time.Duration) (int64, error) {
		keys = append(keys, key)
		if ttl != 120*time.Second {
			t.Errorf("ttl %v", ttl)
		}
		return 99, nil
	}})
	if d := shared.Check(CheckInput{IP: "8.8.4.4"}); d.Rule != "rate" || !strings.HasPrefix(keys[0], "afw:"+testSite+":8.8.4.4:") {
		t.Fatal(d, keys)
	}
	broken := testFirewall(t, "s", data, FirewallOptions{Counter: func(string, time.Duration) (int64, error) { return 0, errors.New("down") }})
	if d := broken.Check(CheckInput{IP: "8.8.4.4"}); d.Action != "allow" {
		t.Fatal(d)
	}
}

func TestMonitorRateDoesNotBan(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "rate": map[string]any{"limit": 1},
		"ban": map[string]any{"seconds": 600}}, FirewallOptions{})
	f.Check(CheckInput{IP: "8.8.8.8"})
	if d := f.Check(CheckInput{IP: "8.8.8.8"}); d.Rule != "rate" || d.Action != "monitor" {
		t.Fatal(d)
	}
	if f.bannedHere(mustKey(t, "8.8.8.8")) {
		t.Fatal("banned in monitor mode")
	}
}

func TestBlockingRequestRuleBans(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "mode": "block", "requests": map[string]any{"rules": []any{
		map[string]any{"id": "sqlmap", "action": "block", "ban": 60, "ua": map[string]any{"contains": []any{"sqlmap"}}},
		map[string]any{"id": "watched", "action": "monitor", "path": map[string]any{"exact": []any{"/w"}}},
	}}}, FirewallOptions{})
	if d := f.Check(CheckInput{IP: "9.9.9.9", Target: "/w"}); d.Rule != "request:watched" || d.Action != "monitor" {
		t.Fatal(d)
	}
	if d := f.Check(CheckInput{IP: "9.9.9.9", Target: "/", UserAgent: "sqlmap/1.7"}); d.Rule != "request:sqlmap" || d.Action != "block" {
		t.Fatal(d)
	}
	if d := f.Check(CheckInput{IP: "9.9.9.9", Target: "/"}); d.Rule != "ban" {
		t.Fatal(d)
	}
}

func TestMappedAddressesAreTheirIPv4(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "mode": "block", "deny": []any{"192.0.2.0/24"}, "allow": []any{"::ffff:198.51.100.1"}}, FirewallOptions{})
	if d := f.Check(CheckInput{IP: "::ffff:192.0.2.4"}); d.Rule != "deny" {
		t.Fatal(d)
	}
	f2 := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "mode": "block", "deny": []any{"198.51.100.0/24"}, "allow": []any{"::ffff:198.51.100.1"}}, FirewallOptions{})
	if d := f2.Check(CheckInput{IP: "198.51.100.1"}); d.Action != "allow" {
		t.Fatal(d)
	}
}

func TestLoginFailures(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "login": map[string]any{"limit": 3, "window": 60, "ban": 600}}, FirewallOptions{})
	for i := 0; i < 2; i++ {
		f.LoginFailed("7.7.7.7")
	}
	if f.bannedHere(mustKey(t, "7.7.7.7")) {
		t.Fatal("banned early")
	}
	f.LoginFailed("7.7.7.7")
	if d := f.Check(CheckInput{IP: "7.7.7.7"}); d.Rule != "ban" {
		t.Fatal(d)
	}
	if row := f.queue["7.7.7.7|login|monitor||"]; row == nil || row.Hits != 3 {
		t.Fatalf("%v", f.queue)
	}
}

func TestRulesAreFetchedWithETagAndCached(t *testing.T) {
	c := newCollector(t)
	calls := 0
	c.handle("/events/firewall/rules", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 1 {
			if r.Header.Get("If-None-Match") != `"v1"` {
				t.Errorf("no ETag sent: %v", r.Header)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(`{"v":1,"enabled":true,"mode":"block","deny":["2.2.2.2"],"sync":45}`))
	})
	cache := filepath.Join(t.TempDir(), "rules.json")
	f := newFirewall(offlineCore("test-secret"), FirewallOptions{CacheFile: cache}, "", nil)
	f.core = testCore(c)
	if wait := f.sync(); wait != 45*time.Second {
		t.Fatal(wait)
	}
	if d := f.Check(CheckInput{IP: "2.2.2.2"}); d.Rule != "deny" {
		t.Fatal(d)
	}
	f.sync()
	got := c.requests("/events/firewall/rules")
	h := got[0].header
	if h.Get("Authorization") != "Bearer test-secret" || h.Get("X-Firewall-Layers") != "app check" ||
		!strings.HasPrefix(h.Get("User-Agent"), "analytics-platform-go/") || got[0].query != "site_id="+testSite {
		t.Fatalf("%v %s", h, got[0].query)
	}
	if d := f.Check(CheckInput{IP: "2.2.2.2"}); d.Rule != "deny" {
		t.Fatal("a 304 dropped the rules")
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatal(err)
	}
	// A restart with the collector away starts from the cache.
	again := newFirewall(offlineCore("test-secret"), FirewallOptions{CacheFile: cache}, "", nil)
	if d := again.Check(CheckInput{IP: "2.2.2.2"}); d.Rule != "deny" || again.etag != `"v1"` {
		t.Fatal(d)
	}
}

func TestReportsAreGroupedAndSentInBatches(t *testing.T) {
	c := newCollector(t)
	f := newFirewall(offlineCore("test-secret"), FirewallOptions{}, "", nil)
	f.core = testCore(c)
	f.rules.Store(rulesFrom(t, map[string]any{"v": 1, "enabled": true, "deny": []any{"0.0.0.0/0"}}))
	for i := 0; i < 250; i++ {
		f.Check(CheckInput{IP: "10.0.0." + strconv.Itoa(i), Method: "GET", Target: "/x"})
	}
	f.Check(CheckInput{IP: "10.0.0.1", Method: "GET", Target: "/x"})
	f.flush(context.Background())
	got := c.requests("/events/firewall/events")
	if len(got) != 2 || len(got[0].body["events"].([]any))+len(got[1].body["events"].([]any)) != 250 {
		t.Fatal(len(got))
	}
	if got[0].body["site_id"] != testSite || got[0].header.Get("Authorization") != "Bearer test-secret" {
		t.Fatal(got[0].body["site_id"])
	}
}

func TestMiddlewareRateLimitAnswers429(t *testing.T) {
	p := checkPlatform(t, nil, map[string]any{"mode": "block", "rate": map[string]any{"limit": 1, "window": 30}})
	h := p.Middleware(theSite)
	call(h, "GET", "/", browserAccept, nil)
	res := call(h, "GET", "/", browserAccept, nil)
	if res.StatusCode != 429 || res.Header.Get("Retry-After") != "30" {
		t.Fatal(res.StatusCode, res.Header)
	}
}

func TestMiddlewareTrustProxy(t *testing.T) {
	p := New(Options{SiteID: testSite, Secret: "s", TrustProxy: "1", Disable: allBut(ModuleFirewall)})
	p.firewall.rules.Store(rulesFrom(t, map[string]any{"v": 1, "enabled": true, "mode": "block", "deny": []any{"198.51.100.7"}}))
	h := p.Middleware(theSite)
	if res := call(h, "GET", "/", browserAccept, map[string][]string{"X-Forwarded-For": {"198.51.100.7"}}); res.StatusCode != 403 {
		t.Fatal(res.StatusCode)
	}
	if res := call(h, "GET", "/", browserAccept, map[string][]string{"X-Forwarded-For": {"198.51.100.8"}}); res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	// OnBlock answers instead.
	p.firewall.onBlock = func(w http.ResponseWriter, r *http.Request, d Decision) { w.WriteHeader(418) }
	if res := call(h, "GET", "/", browserAccept, map[string][]string{"X-Forwarded-For": {"198.51.100.7"}}); res.StatusCode != 418 {
		t.Fatal(res.StatusCode)
	}
}

// allBut is every module's name but keep, for Options.Disable.
func allBut(keep ...string) []string {
	var out []string
	for _, m := range allModules {
		if !containsString(keep, m) {
			out = append(out, m)
		}
	}
	return out
}

func TestRoutedPaths(t *testing.T) {
	for in, want := range map[string]string{
		"/x/..;/actuator/env": "/actuator/env", "/a/./b": "/a/b", "/a;jsessionid=1/b": "/a/b", "/x;y/..;/admin/users": "/admin/users",
		"/..;/..;/admin/x": "/admin/x", "/a/b/": "/a/b/", "/a/b/..": "/a/", "/A/%2e%2e/B": "/b", `\a\\b`: "/a/b", "/": "/",
	} {
		if got := routerPath(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	probes := &probeRule{exact: map[string]bool{"/.env": true}, prefix: []string{"/.git/"}}
	for _, target := range []string{"/x/..;/.env", "/./.git/config", "/.ENV?x=1"} {
		if !isProbe(target, probes) {
			t.Errorf("%s isn't a probe", target)
		}
	}
}

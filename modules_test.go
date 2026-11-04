package sitegoose

// The smaller modules. Expected numbers marked "Python" are the Python
// package's answers for the same input, so the clients agree.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- Check-in, switches, flags, headers, maintenance ----

func configPlatform(t *testing.T, c *collector, config map[string]any, keep ...string) *Platform {
	c.handle("/events/platform/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"c1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"c1"`)
		data, _ := json.Marshal(config)
		w.Write(data)
	})
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, ServerName: "shop-api", Disable: allBut(keep...)})
	t.Cleanup(func() { p.Close(context.Background()) })
	c.waitFor("/events/platform/config", 1)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.core.mu.RLock()
		v := p.core.version
		p.core.mu.RUnlock()
		if v > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return p
}

func TestCheckInAndSwitches(t *testing.T) {
	c := newCollector(t)
	p := configPlatform(t, c, map[string]any{"v": 1, "modules": map[string]any{"crawlers": false, "flags": true}, "sync": 5},
		ModuleFlags, ModuleCrawlers, ModuleHeaders)
	got := c.requests("/events/platform/config")[0]
	if got.header.Get("Authorization") != "Bearer test-secret" || got.header.Get("X-Platform-Modules") != "crawlers,headers,flags" {
		t.Fatalf("%v", got.header)
	}
	app, err := url.ParseQuery(got.header.Get("X-Platform-App"))
	if err != nil || app.Get("server") != "shop-api" || app.Get("kind") != "process" || !strings.HasPrefix(app.Get("runtime"), "Go ") ||
		app.Get("pid") == "" || app.Get("up_s") == "" {
		t.Fatalf("%v", app)
	}
	if p.core.isOn(ModuleCrawlers) || !p.core.isOn(ModuleFlags) || !p.core.isOn(ModuleErrors) {
		t.Fatal("switches not applied")
	}
	// Unchanged (304): asked again after the retry wait, as the Python package does.
	if wait := p.core.syncSwitches(); wait != retryWait {
		t.Fatal(wait)
	}
	all := c.requests("/events/platform/config")
	if all[len(all)-1].header.Get("If-None-Match") != `"c1"` {
		t.Fatal("no ETag")
	}
	// Turned off, crawlers count nothing.
	p.RecordCrawler("Googlebot/2.1", "/", 200, time.Millisecond, 10, "66.249.66.1")
	if len(p.crawlers.rows) != 0 {
		t.Fatal("a switched-off module counted")
	}
}

func TestFlags(t *testing.T) {
	for user, want := range map[string]uint32{"u1": 76, "u2": 33, "alice": 2, "42": 32, "émile": 11} { // Python
		if got := flagBucket("new-checkout", user); got != want {
			t.Errorf("bucket(%s) = %d, want %d", user, got, want)
		}
	}
	c := newCollector(t)
	p := configPlatform(t, c, map[string]any{"v": 1, "modules": map[string]any{}, "flags": map[string]any{
		"all": map[string]any{"on": true}, "off": map[string]any{"on": false, "users": []any{"u1"}},
		"half": map[string]any{"on": true, "rollout": 50, "users": []any{"vip"}},
		"none": map[string]any{"on": true, "rollout": 0},
	}}, ModuleFlags)
	if !p.IsEnabled("all", "") || p.IsEnabled("off", "u1") || !p.IsEnabled("half", "vip") || p.IsEnabled("none", "u1") {
		t.Fatal("flags")
	}
	// alice is in bucket 2 of "half", so in; u1's bucket for "half" decides the other way round.
	if p.IsEnabled("half", "alice") != (flagBucket("half", "alice") < 50) || p.IsEnabled("half", "") {
		t.Fatal("rollout")
	}
	if !p.IsEnabledOr("unknown", "u1", true) || p.IsEnabled("unknown", "u1") {
		t.Fatal("fallback")
	}
}

func TestSecurityHeadersAreAddedUnlessTheAppSetsThem(t *testing.T) {
	c := newCollector(t)
	p := configPlatform(t, c, map[string]any{"v": 1, "modules": map[string]any{}, "headers": []any{
		[]any{"X-Frame-Options", "DENY"}, []any{"Referrer-Policy", "strict-origin"}, []any{"Bad\nName", "x"}, []any{"X-Evil", "a\r\nSet-Cookie: x"},
	}}, ModuleHeaders)
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Write([]byte("ok"))
	}))
	res := call(h, "GET", "/", browserAccept, nil)
	if res.Header.Get("X-Frame-Options") != "SAMEORIGIN" || res.Header.Get("Referrer-Policy") != "strict-origin" || res.Header.Get("X-Evil") != "" {
		t.Fatal(res.Header)
	}
}

func TestMaintenanceMode(t *testing.T) {
	c := newCollector(t)
	p := configPlatform(t, c, map[string]any{"v": 1, "modules": map[string]any{}, "maintenance": map[string]any{
		"on": true, "allow": []any{"198.51.100.0/24"}, "bypass": "letmein", "message": "Moving <servers>",
	}}, ModuleMaintenance)
	p.maint.skip = func(r *http.Request) bool { return r.URL.Path == "/healthz" }
	h := p.Middleware(theSite)
	res := call(h, "GET", "/", browserAccept, nil)
	if body := bodyOf(res); res.StatusCode != 503 || res.Header.Get("Retry-After") != "600" || !strings.Contains(body, "Moving &lt;servers&gt;") {
		t.Fatal(res.StatusCode, body)
	}
	if bodyOf(call(h, "GET", "/healthz", browserAccept, nil)) != "the site" {
		t.Fatal("skip")
	}
	preview := call(h, "GET", "/?site_preview=letmein", browserAccept, nil)
	if bodyOf(preview) != "the site" || !strings.HasPrefix(preview.Header.Get("Set-Cookie"), "site_preview=letmein;") {
		t.Fatal(preview.Header)
	}
	if bodyOf(call(h, "GET", "/", browserAccept, map[string][]string{"Cookie": {"site_preview=letmein"}})) != "the site" {
		t.Fatal("cookie")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.9:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Body.String() != "the site" {
		t.Fatal("allowed address")
	}
}

// ---- Server speed ----

func TestRoutes(t *testing.T) {
	for in, want := range map[string]string{
		"/orders/123/items/9f8e7d6c5b4a39281706":  "/orders/:id/items/:id",
		"/u/550e8400-e29b-41d4-a716-446655440000": "/u/:id",
		"/blog/hello-world?page=2":                "/blog/hello-world",
		"":                                        "/",
		"/a/abcdefghij0123456789x":                "/a/:id",
	} {
		if got := normalizeRoute(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"GET /orders/{id}": "/orders/{id}", "example.com/x/": "/x/", "POST example.com/a/{b...}": "/a/{b...}", "/": "/", "": "",
	} {
		if got := patternRoute(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if bucketOf(5) != 0 || bucketOf(5.1) != 1 || bucketOf(20000) != len(bucketEdgesMS) {
		t.Fatal("buckets")
	}
}

func TestServerRequestRows(t *testing.T) {
	c := newCollector(t)
	p := newPerformance(testCore(c), PerformanceOptions{ServerName: "api"})
	p.job.halt(context.Background())
	p.record("GET", "", 404, 1, "/nope")
	for i := 0; i < maxRouteKeys+5; i++ {
		p.record("get", "", 200, 12, "/page-"+strconv.Itoa(i)+"x")
	}
	p.flush(context.Background(), false)
	if len(c.requests("/events/server-requests")) != 0 {
		t.Fatal("this minute was sent before it ended")
	}
	p.flush(context.Background(), true)
	got := c.requests("/events/server-requests")
	if len(got) != 1 || got[0].body["server_name"] != "api" || !strings.HasPrefix(got[0].body["runtime"].(string), "Go ") || got[0].body["sitesecret"] != "test-secret" {
		t.Fatal(got)
	}
	routes := map[string]bool{}
	for _, row := range got[0].body["rows"].([]any) {
		r := row.(map[string]any)
		routes[r["route"].(string)] = true
		if r["method"] != "GET" || len(r["buckets"].([]any)) != len(bucketEdgesMS)+1 || !strings.HasSuffix(r["minute"].(string), ":00.000Z") {
			t.Fatal(r)
		}
	}
	if !routes["(other)"] || !routes["/(not found)"] || len(routes) != maxRouteKeys+1 {
		t.Fatal(len(routes))
	}
}

// ---- Crawlers ----

func TestDetectCrawler(t *testing.T) {
	for ua, want := range map[string]string{ // Python
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                               "Googlebot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)": "GPTBot",
		"curl/8.1": "Other bot", "Mozilla/5.0 (Windows NT 10.0) Chrome/120": "", "Go-http-client/1.1": "Other bot",
		"Mozilla/5.0 (compatible; bingbot/2.0)": "bingbot", "ClaudeBot/1.0": "ClaudeBot", "meta-externalagent/1.1": "Meta-ExternalAgent", "": "",
	} {
		if got := DetectCrawler(ua); got != want {
			t.Errorf("%q: %q, want %q", ua, got, want)
		}
	}
}

func TestCrawlerRows(t *testing.T) {
	c := newCollector(t)
	k := newCrawlers(testCore(c), CrawlersOptions{ServerName: "web"})
	k.job.halt(context.Background())
	for i := 0; i < 8; i++ {
		k.record("Googlebot", "/p?x=1", 200, 10, 100, "66.249.66."+string(rune('0'+i)))
	}
	k.record("GPTBot", "", 404, 5, 0, "20.1.1.1")
	k.flush(context.Background(), true)
	got := c.requests("/events/crawlers")
	if len(got) != 1 {
		t.Fatal(got)
	}
	body := got[0].body
	rows, agents := body["rows"].([]any), body["agents"].([]any)
	if len(rows) != 2 || len(agents) != 2 || body["server_name"] != "web" {
		t.Fatal(body)
	}
	first := agents[0].(map[string]any)
	if first["bot"] != "Googlebot" || len(first["ips"].([]any)) != maxIPsPerBot {
		t.Fatal(first)
	}
	for _, r := range rows {
		row := r.(map[string]any)
		if row["bot"] == "Googlebot" && (row["path"] != "/p" || row["count"] != float64(8) || row["bytes"] != float64(800) || row["sum_ms"] != float64(80)) {
			t.Fatal(row)
		}
		if row["bot"] == "GPTBot" && row["path"] != "/" {
			t.Fatal(row)
		}
	}
}

// ---- Resources ----

func TestResourceParsers(t *testing.T) {
	f1 := cpuFields("cpu  100 5 50 1000 20 3 7 9 0 0\ncpu0 1 2 3 4\n")
	f2 := cpuFields("cpu  160 5 80 1100 40 3 7 15 0 0\ncpu0 1 2 3 4\ncpu1 1 1 1 1\n")
	if pct, ok := cpuPercent(f1, f2); !ok || pct != 44.4 { // Python
		t.Fatal(pct)
	}
	if _, ok := cpuPercent(f2, f1); ok {
		t.Fatal("a counter reset gave a figure")
	}
	shares := cpuShares(f1, f2)
	if shares["cpu_user_pct"] != 27.8 || shares["cpu_system_pct"] != 13.9 || shares["cpu_iowait_pct"] != 9.3 || shares["cpu_steal_pct"] != 2.8 { // Python
		t.Fatal(shares)
	}
	if n := machineCores("cpu  1\ncpu0 1\ncpu1 1\nintr 5\n"); n != 2 {
		t.Fatal(n)
	}
	disk := "   8       0 sda 100 0 2048 0 50 0 4096 0 0 0 0\n   8       1 sda1 100 0 2048 0 50 0 4096 0 0 0 0\n 259 0 nvme0n1 10 0 1000 0 10 0 2000 0 0 0 0\n   7 0 loop0 5 0 999 0 0 0 0 0 0 0 0\n 253 0 dm-0 1 0 8 0 1 0 8 0 0 0 0\n"
	if r, w, ok := diskCounters(disk); !ok || r != 1560576 || w != 3121152 { // Python
		t.Fatal(r, w)
	}
	net := "Inter-|   Receive\n face |bytes    packets\n    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n  eth0: 5000 10 0 0 0 0 0 0 7000 20 0 0 0 0 0 0\n docker0: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n  veth12: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n"
	if rx, tx, ok := netCounters(net); !ok || rx != 5000 || tx != 7000 { // Python
		t.Fatal(rx, tx)
	}
	mem := memoryMB("MemTotal:        8000000 kB\nMemFree:         1000000 kB\nMemAvailable:    3000000 kB\nBuffers:          100000 kB\nCached:          2000000 kB\nSwapTotal:       2048000 kB\nSwapFree:        1024000 kB\n")
	if mem["mem_total_mb"] != 7812 || mem["mem_used_mb"] != 4883 || mem["swap_total_mb"] != 2000 || mem["swap_used_mb"] != 1000 { // Python
		t.Fatal(mem)
	}
	mounts := "/dev/sda1 / ext4 rw 0 0\nproc /proc proc rw 0 0\n/dev/sda2 /home ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/sda1 /var/lib/docker/overlay ext4 rw 0 0\n/dev/sdb1 /mnt/data\\040disk xfs rw 0 0\n/dev/loop0 /snap/core/1 squashfs ro 0 0\n"
	if got := strings.Join(mountPoints(mounts, func(string) bool { return true }), "|"); got != "/|/home|/mnt/data disk" { // Python
		t.Fatal(got)
	}
	if up, ok := hostUptime("12345.67 999.0\n"); !ok || up != 12345 {
		t.Fatal(up)
	}
	if rss, ok := processRSS("Name: x\nVmRSS:\t  204800 kB\n"); !ok || rss != 200 {
		t.Fatal(rss)
	}
	if load := loadAverage("0.52 0.40 0.31 1/123 4567\n"); load["load1"] != 0.52 || load["load15"] != 0.31 {
		t.Fatal(load)
	}
	stat := func(m string) (fsStat, bool) {
		switch m {
		case "/":
			return fsStat{block: 4096, blocks: 2621440, free: 1310720, avail: 1048576, files: 100, filesFree: 40}, true
		case "/same":
			return fsStat{block: 4096, blocks: 2621440, free: 1310720, avail: 1048576}, true
		case "/tiny":
			return fsStat{block: 4096, blocks: 10, free: 5, avail: 5}, true
		}
		return fsStat{}, false
	}
	rows := diskRows([]string{"/", "/same", "/tiny", "/gone"}, stat)
	if len(rows) != 1 || rows[0]["total_mb"] != uint64(9216) || rows[0]["used_mb"] != uint64(5120) || rows[0]["inodes_used"] != uint64(60) {
		t.Fatal(rows)
	}
}

func TestResourcesAreSentAndTheAnswerHeeded(t *testing.T) {
	c := newCollector(t)
	c.json("/events/resources", 200, map[string]any{"enabled": false, "every": 900})
	r := newResources(testCore(c), ResourcesOptions{ServerName: "box"})
	r.sampler.halt(context.Background())
	r.job.halt(context.Background())
	r.mu.Lock()
	r.rows["2026-11-03T10:00:00.000Z"] = map[string]any{"minute": "2026-11-03T10:00:00.000Z", "cpu_pct": 12.5}
	r.mu.Unlock()
	if wait := r.report(); wait != 900*time.Second {
		t.Fatal(wait)
	}
	got := c.requests("/events/resources")
	if len(got) != 1 || got[0].header.Get("Authorization") != "Bearer test-secret" || got[0].body["server_name"] != "box" || len(got[0].body["rows"].([]any)) != 1 {
		t.Fatal(got)
	}
	if len(r.rows) != 0 || r.enabled {
		t.Fatal("answer not heeded")
	}
}

// ---- Inventory and posture ----

func TestInventoryPackages(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Path: "example.com/shop", Version: "(devel)"},
		Deps: []*debug.Module{
			{Path: "github.com/gin-gonic/gin", Version: "v1.10.0"},
			{Path: "github.com/old/lib", Version: "v1.0.0", Replace: &debug.Module{Path: "github.com/fork/lib", Version: "v1.0.1"}},
			{Path: "golang.org/x/net", Version: "v0.0.0-20240101000000-abcdef123456"},
		},
	}
	got := buildPackages(info, "1.23.4")
	var names []string
	for _, p := range got {
		if p.Ecosystem != "Go" {
			t.Fatal(p)
		}
		names = append(names, p.Name+"@"+p.Version)
	}
	if strings.Join(names, " ") != "github.com/fork/lib@1.0.1 github.com/gin-gonic/gin@1.10.0 golang.org/x/net@0.0.0-20240101000000-abcdef123456 stdlib@1.23.4" {
		t.Fatal(names)
	}
	c := newCollector(t)
	c.json("/events/inventory", 200, map[string]any{"every": 7200})
	i := newInventory(testCore(c), InventoryOptions{Host: "web 1/a"})
	i.job.halt(context.Background())
	if wait := i.report(); wait != 7200*time.Second {
		t.Fatal(wait)
	}
	sent := c.requests("/events/inventory")[0]
	if sent.body["host"] != "web-1-a" || sent.body["runtime"].(map[string]any)["go"] == "" || sent.header.Get("Authorization") != "Bearer test-secret" {
		t.Fatal(sent.body)
	}
}

func TestPostureReport(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=1"), 0o644)
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<p>"), 0o644)
	os.Mkdir(filepath.Join(dir, ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, "app.go"), []byte("package main"), 0o666)
	os.Chmod(filepath.Join(dir, "app.go"), 0o666)
	p := newPosture(offlineCore("s"), PostureOptions{Roots: []Root{{Dir: dir}}, Host: "web",
		Checks: func() []Check {
			return []Check{{ID: "app.debug", State: "fail"}, {ID: "bad id!", State: "pass"}, {ID: "x.y", State: "maybe"}}
		}})
	report := p.report()
	checks := map[string]Check{}
	for _, c := range report["checks"].([]Check) {
		checks[c.ID] = c
	}
	if checks["server.code_writable"].State != "fail" || !strings.Contains(checks["server.code_writable"].Value, "app.go") {
		t.Fatal(checks)
	}
	if checks["app.go_pprof"].State != "pass" || checks["app.debug"].State != "fail" || len(checks) > 5 {
		t.Fatal(checks)
	}
	exposure, _ := json.Marshal(report["exposure"])
	if !strings.Contains(string(exposure), ".env") || !strings.Contains(string(exposure), ".git") || strings.Contains(string(exposure), "index.html") {
		t.Fatal(string(exposure))
	}
	if report["facts"].(map[string]string)["agent"] == "" {
		t.Fatal(report["facts"])
	}
	// No folder to walk: no exposure at all, rather than an empty one.
	if _, has := newPosture(offlineCore("s"), PostureOptions{Roots: []Root{{Dir: filepath.Join(dir, "missing")}}}).report()["exposure"]; has {
		t.Fatal("exposure without a folder")
	}
}

// ---- Proxy ----

func TestProxyNamesMatchTheOtherClients(t *testing.T) {
	if proxyPrefixFor("s3cret") != "d17f9571" || proxyKeyFor("s3cret") != "e30f556c6d211a44134afbcf1bad8986" { // Python
		t.Fatal(proxyPrefixFor("s3cret"), proxyKeyFor("s3cret"))
	}
}

func TestProxyServesTheTrackerAndForwardsVisits(t *testing.T) {
	c := newCollector(t)
	script := strings.Repeat("/* tracker */", 100)
	c.handle("/v1/s.js", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(script)) })
	c.handle("/collectanalytics/e", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "tracking=1")
		w.Write([]byte(`{"ok":true}`))
	})
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, Disable: allBut(ModuleProxy)})
	defer p.Close(context.Background())
	px := p.Proxy()
	if !px.Enabled() || px.ScriptURL("") != "/"+proxyPrefixFor("test-secret")+"/js/v1/s.js" || px.CollectURL() != "/"+px.Prefix()+"/api/e" {
		t.Fatal(px.ScriptURL(""))
	}
	h := p.Middleware(theSite)
	res := call(h, "GET", px.ScriptURL(""), "*/*", nil)
	if res.StatusCode != 200 || bodyOf(res) != script || res.Header.Get("Cache-Control") != "public, max-age=3600" {
		t.Fatal(res.StatusCode, res.Header)
	}
	call(h, "GET", px.ScriptURL(""), "*/*", nil)
	if n := len(c.requests("/v1/s.js")); n != 1 {
		t.Fatalf("fetched %d times", n)
	}
	r := httptest.NewRequest("POST", px.CollectURL()+"?v=2", strings.NewReader(`{"e":"pageview"}`))
	r.RemoteAddr = "203.0.113.5:4000"
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Cookie", "session=private")
	r.Header.Set("Referer", "https://shop.example/")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != `{"ok":true}` || w.Header().Get("Set-Cookie") != "" {
		t.Fatal(w.Code, w.Header())
	}
	sent := c.requests("/collectanalytics/e")[0]
	if sent.query != "v=2" || sent.header.Get("X-Forwarded-For") != "203.0.113.5" || sent.header.Get("X-Proxy-Key") != proxyKeyFor("test-secret") ||
		sent.header.Get("Cookie") != "" || sent.header.Get("Referer") != "https://shop.example/" || sent.body["e"] != "pageview" {
		t.Fatal(sent)
	}
	for _, bad := range []string{"/" + px.Prefix() + "/js/v1/evil.js", "/" + px.Prefix() + "/js/../x", "/" + px.Prefix() + "/other"} {
		if res := call(h, "GET", bad, "*/*", nil); res.StatusCode != 404 {
			t.Errorf("%s: %d", bad, res.StatusCode)
		}
	}
	if res := call(h, "OPTIONS", px.CollectURL(), "*/*", nil); res.StatusCode != 204 {
		t.Fatal(res.StatusCode)
	}
	if bodyOf(call(h, "GET", "/pricing", browserAccept, nil)) != "the site" {
		t.Fatal("the site's own pages")
	}
}

// ---- Server analytics, audit, forms ----

func TestTrackIdentifyLead(t *testing.T) {
	c := newCollector(t)
	c.json("/events/identify", 200, map[string]any{"ok": true})
	c.json("/events/lead", 201, map[string]any{"status": "created", "lead_id": "L1"})
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, Disable: allBut(ModuleAnalytics)})
	defer p.Close(context.Background())
	var uid string
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid = p.Track(r.Context(), "purchase", map[string]any{"numeric_value": 49.5, "currency": "EUR"})
		if !p.Identify(r.Context(), "user-7", "") {
			t.Error("identify")
		}
		if lead := p.Lead(r.Context(), map[string]any{"email": "a@b.c"}); lead == nil || lead.LeadID != "L1" || lead.Status != "created" {
			t.Error("lead", lead)
		}
	}))
	call(h, "GET", "/checkout", browserAccept, map[string][]string{SessionHeader: {"visit-9"}})
	if len(uid) != 36 || p.Track(context.Background(), "", nil) != "" {
		t.Fatal(uid)
	}
	p.Flush(context.Background())
	events := c.requests("/events/server-events")[0].body["events"].([]any)
	ev := events[0].(map[string]any)
	if ev["event_name"] != "purchase" || ev["numeric_value"] != "49.5" || ev["session_id"] != "visit-9" || ev["event_uid"] != uid {
		t.Fatal(ev)
	}
	id := c.requests("/events/identify")[0].body
	if id["user_id"] != "user-7" || id["session_id"] != "visit-9" || id["sitesecret"] != "test-secret" {
		t.Fatal(id)
	}
	if c.requests("/events/lead")[0].body["session_id"] != "visit-9" {
		t.Fatal("lead session")
	}
}

func TestAudit(t *testing.T) {
	c := newCollector(t)
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, Disable: allBut(ModuleAudit)})
	defer p.Close(context.Background())
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.Audit(r.Context(), "user.role_changed", AuditEntry{Actor: "admin@shop", Target: "user:7", Details: map[string]any{"to": "editor"}})
	}))
	call(h, "POST", "/admin", browserAccept, map[string][]string{SessionHeader: {"v"}})
	p.Flush(context.Background())
	entry := c.requests("/events/audit")[0].body["entries"].([]any)[0].(map[string]any)
	if entry["action"] != "user.role_changed" || entry["actor_ip"] != "203.0.113.5" || entry["session_id"] != "v" || entry["details"].(map[string]any)["to"] != "editor" {
		t.Fatal(entry)
	}
}

func TestForms(t *testing.T) {
	c := newCollector(t)
	c.json("/collectanalytics/shield/verify", 200, map[string]any{"success": false, "reasons": []any{"honeypot"}})
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, Disable: allBut(ModuleForms)})
	defer p.Close(context.Background())
	h := p.ProtectForm(FormOptions{Form: "contact"}, nil)(theSite)
	r := httptest.NewRequest("POST", "/contact", strings.NewReader("name=Bot&password=hunter2&analytics-shield=tok&msg=hi"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.5:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 422 {
		t.Fatal(w.Code)
	}
	body := c.requests("/collectanalytics/shield/verify")[0].body
	fields := body["fields"].(map[string]any)
	if body["token"] != "tok" || body["ip"] != "203.0.113.5" || body["form"] != "contact" || fields["password"] != nil || fields["analytics-shield"] != nil || fields["msg"] != "hi" {
		t.Fatal(body)
	}
	// The check can't be made: the form goes through.
	c.json("/collectanalytics/shield/verify", 503, map[string]any{})
	if res := p.CheckForm(nil, FormOptions{Fields: map[string][]string{"a": {"b"}}}); !res.OK || res.Checked || res.Reasons[0] != "unchecked" {
		t.Fatal(res)
	}
}

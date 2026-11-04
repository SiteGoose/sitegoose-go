package sitegoose

// The review's findings, each pinned by a test, and a stress run of every
// module at once for -race.

import (
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeaderAddressesAreCheckedOrIgnored(t *testing.T) {
	for _, c := range []struct{ header, want string }{
		{"198.51.100.7:5555", "198.51.100.7"}, // Azure sends the port
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"::ffff:198.51.100.7", "198.51.100.7"},
		{"unknown", "10.0.0.1"},
		{"<script>", "10.0.0.1"},
		{"", "10.0.0.1"},
	} {
		h := http.Header{"X-Forwarded-For": {c.header}}
		if got := clientIPOf("10.0.0.1", h, "1"); got != c.want {
			t.Errorf("X-Forwarded-For %q: %q, want %q", c.header, got, c.want)
		}
	}
	h := http.Header{"Cf-Connecting-Ip": {"junk"}}
	if got := clientIPOf("173.245.48.7", h, "cloudflare"); got != "173.245.48.7" {
		t.Fatal(got)
	}
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "mode": "block", "deny": []any{"198.51.100.7"}}, FirewallOptions{TrustProxy: "1"})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.7:5555")
	if d := f.Check(CheckInput{IP: f.ClientIP(r), Method: "GET", Target: "/"}); d.Rule != "deny" {
		t.Fatal("an address with a port got through", d)
	}
}

func TestIPv6IsCountedAndBannedByItsSlash64(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "mode": "block", "rate": map[string]any{"limit": 3, "window": 60},
		"ban": map[string]any{"seconds": 600}}, FirewallOptions{})
	var last Decision
	for i := 1; i <= 4; i++ {
		last = f.Check(CheckInput{IP: "2001:db8:1:2::" + strconv.Itoa(i)})
	}
	if last.Rule != "rate" {
		t.Fatal("one machine walked its /64 past the limit", last)
	}
	if d := f.Check(CheckInput{IP: "2001:db8:1:2:ffff::9"}); d.Rule != "ban" {
		t.Fatal("the ban missed the rest of the /64", d)
	}
	if d := f.Check(CheckInput{IP: "2001:db8:1:3::1"}); d.Action != "allow" {
		t.Fatal("the next /64 was banned", d)
	}
	if localName(mustKey(t, "::ffff:198.51.100.7")) != "198.51.100.7" || localName(localKey(mustKey(t, "2001:db8:1:2:aa::1"))) != "2001:db8:1:2::/64" {
		t.Fatal(localName(localKey(mustKey(t, "2001:db8:1:2:aa::1"))))
	}
	var keys []string
	shared := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "rate": map[string]any{"limit": 9}}, FirewallOptions{
		Counter: func(key string, _ time.Duration) (int64, error) { keys = append(keys, key); return 1, nil }})
	shared.Check(CheckInput{IP: "::ffff:198.51.100.7"})
	shared.Check(CheckInput{IP: "2001:db8:1:2::77"})
	if !strings.Contains(keys[0], ":198.51.100.7:") || !strings.Contains(keys[1], ":2001:db8:1:2::/64:") {
		t.Fatal(keys)
	}
}

func TestAFullTableKeepsItsLiveBans(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "mode": "block"}, FirewallOptions{})
	now := time.Unix(1_800_000_000, 0)
	f.now = func() time.Time { return now }
	for i := 0; i < counterMax; i++ {
		f.bans[ipKey{0, 0xFFFF<<32 | uint64(i)}] = now.Add(time.Hour)
	}
	newcomer := mustKey(t, "203.0.113.200")
	f.banHere(newcomer, 60)
	if len(f.bans) != counterMax || f.bannedHere(newcomer) || !f.bannedHere(ipKey{0, 0xFFFF<<32 | 5}) {
		t.Fatal("a live ban was dropped, or the table grew")
	}
	// Once they run out, a sweep makes room (at most once a second).
	now = now.Add(2 * time.Hour)
	f.banHere(newcomer, 60)
	f.banHere(newcomer, 60)
	if !f.bannedHere(newcomer) || len(f.bans) != 1 {
		t.Fatal(len(f.bans))
	}
}

func TestStaticFilesDontCountTowardsTheRate(t *testing.T) {
	f := testFirewall(t, "s", map[string]any{"v": 1, "enabled": true, "rate": map[string]any{"limit": 2}}, FirewallOptions{})
	for _, target := range []string{"/app.css", "/img/a.PNG?v=2", "/f.woff2", "/x.js", "/y.svg"} {
		if d := f.Check(CheckInput{IP: "8.8.8.8", Target: target}); d.Action != "allow" {
			t.Fatal(target, d)
		}
	}
	f.Check(CheckInput{IP: "8.8.8.8", Target: "/"})
	f.Check(CheckInput{IP: "8.8.8.8", Target: "/a"})
	if d := f.Check(CheckInput{IP: "8.8.8.8", Target: "/b.php"}); d.Rule != "rate" {
		t.Fatal(d)
	}
}

func errorsAndSpeed(t *testing.T, c *collector) *Platform {
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, Disable: allBut(ModuleErrors, ModulePerformance),
		Errors: ErrorsOptions{SpoolDir: t.TempDir(), DisableCrashCapture: true}})
	t.Cleanup(func() { p.Close(context.Background()) })
	return p
}

func TestAnAbortedAnswerIsNeitherAnErrorNorTimed(t *testing.T) {
	c := newCollector(t)
	p := errorsAndSpeed(t, c)
	srv := httptest.NewServer(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		panic(http.ErrAbortHandler)
	})))
	defer srv.Close()
	if res, err := http.Get(srv.URL + "/stream"); err == nil {
		res.Body.Close()
	}
	p.Flush(context.Background())
	if n := len(c.requests("/events/server-errors")) + len(c.requests("/events/server-requests")); n != 0 {
		t.Fatalf("%d sent", n)
	}
}

func TestAVisitorWhoLeftIsNotAnError(t *testing.T) {
	c := newCollector(t)
	p := errorsAndSpeed(t, c)
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "context canceled", 500)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil).WithContext(ctx))
	p.Flush(context.Background())
	if len(c.requests("/events/server-errors")) != 0 {
		t.Fatal("sent")
	}
}

func TestMadeUpMethodsCantGrowTheTable(t *testing.T) {
	pf := newPerformance(offlineCore("x"), PerformanceOptions{})
	for i := 0; i < 5000; i++ {
		pf.record("M"+strconv.Itoa(i), "/x"+strconv.Itoa(i), 200+i%400, 1, "/")
	}
	if n := len(pf.rows); n > maxRouteKeys+maxFoldedKeys+10 {
		t.Fatal(n)
	}
	for k := range pf.rows {
		if !knownMethods[k.method] && k.method != "OTHER" {
			t.Fatal(k.method)
		}
	}
}

func TestAnEventJSONCantTakeIsDroppedAlone(t *testing.T) {
	c := newCollector(t)
	a := newAnalytics(testCore(c))
	a.job.halt(context.Background())
	if a.track(context.Background(), "bad", map[string]any{"value": math.NaN()}) != "" || a.track(context.Background(), "chan", map[string]any{"x": make(chan int)}) != "" {
		t.Fatal("queued")
	}
	a.track(context.Background(), "good", nil)
	if !a.flush(context.Background()) || len(a.queue) != 0 {
		t.Fatal("not sent")
	}
	if got := c.requests("/events/server-events"); len(got) != 1 || len(got[0].body["events"].([]any)) != 1 {
		t.Fatal(got)
	}
	au := newAudit(testCore(c))
	au.job.halt(context.Background())
	au.record("bad", AuditEntry{Details: map[string]any{"f": func() {}}}, "", "")
	au.record("good", AuditEntry{}, "", "")
	au.flush(context.Background())
	if got := c.requests("/events/audit"); len(got) != 1 || len(got[0].body["entries"].([]any)) != 1 {
		t.Fatal(got)
	}
	// A body that can't be encoded is an answer, not a failure to retry.
	if res := testCore(c).send(context.Background(), "x", "/y", "POST", map[string]any{"n": math.Inf(1)}, authBody, nil); failed(res) {
		t.Fatal("would be retried")
	}
}

func TestStreamingThroughTheMiddleware(t *testing.T) {
	p := New(Options{})
	var notified <-chan bool
	srv := httptest.NewServer(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notified = w.(http.CloseNotifier).CloseNotify() //nolint:staticcheck
		io.WriteString(w, "data: hi\n\n")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
		w.(interface{ FlushError() error }).FlushError()
	})))
	defer srv.Close()
	res, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "data: hi\n\n" {
		t.Fatal(string(body))
	}
	if notified == nil {
		t.Fatal("no CloseNotify channel")
	}
	// Under a writer without one of its own, it fires when the request ends.
	ctx, cancel := context.WithCancel(context.Background())
	var fallback <-chan bool
	p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallback = w.(http.CloseNotifier).CloseNotify() //nolint:staticcheck
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil).WithContext(ctx))
	cancel()
	select {
	case <-fallback:
	case <-time.After(5 * time.Second):
		t.Fatal("CloseNotify never fired")
	}
}

func TestOrphanedSpoolFilesAreResent(t *testing.T) {
	c := newCollector(t)
	e := testErrors(t, c, ErrorsOptions{})
	e.spool([]*ErrorEvent{{Message: "from a process that died sending"}})
	// 4194311: no such process.
	orphan := e.spoolFile + ".4194311.abc.sending"
	if err := os.Rename(e.spoolFile, orphan); err != nil {
		t.Fatal(err)
	}
	e.resend(context.Background())
	if events := sentErrors(c); len(events) != 1 || events[0]["message"] != "from a process that died sending" {
		t.Fatal(events)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("left")
	}
}

func TestAFailedResendKeepsTheErrors(t *testing.T) {
	c := newCollector(t)
	c.json("/events/server-errors", 503, map[string]any{})
	old := errorsRetryAfter
	errorsRetryAfter = 0
	defer func() { errorsRetryAfter = old }()
	e := testErrors(t, c, ErrorsOptions{})
	e.spool([]*ErrorEvent{{Message: "a"}, {Message: "b"}})
	e.resend(context.Background())
	if got := readSpool(e.spoolFile); len(got) != 2 {
		t.Fatal(len(got))
	}
}

func TestACrashRecoverSentIsntSentAgain(t *testing.T) {
	c := newCollector(t)
	e := testErrors(t, c, ErrorsOptions{})
	e.crashFile = strings.TrimSuffix(strings.Replace(e.spoolFile, "analytics-errors-", "analytics-crash-", 1), ".jsonl")
	dead := e.crashFile + "-4194311.log"
	os.WriteFile(dead, []byte("panic: worker died [recovered]\n\tpanic: worker died\n\ngoroutine 9 [running]:\nmain.work()\n"), 0o600)
	os.WriteFile(sentMarker(dead), []byte("worker died"), 0o600)
	stale := e.crashFile + "-4194313.log.sending"
	os.WriteFile(stale, []byte(crashText), 0o600)
	os.Chtimes(stale, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	e.sendCrashes()
	events := sentErrors(c)
	if len(events) != 1 || events[0]["error_type"] != "runtime.Error" {
		t.Fatal(events)
	}
	for _, f := range []string{dead, sentMarker(dead), stale} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s left", f)
		}
	}
	// Recover notes what it sent for this process.
	e.markSent(panicMessage(errors.New("x")).(string))
	mine := e.crashFile + "-" + strconv.Itoa(os.Getpid()) + ".log"
	if data, _ := os.ReadFile(sentMarker(mine)); string(data) != "x" {
		t.Fatal(string(data))
	}
	os.Remove(sentMarker(mine))
}

func TestProxyChecksTheAddressFirstAndNeverWaitsLong(t *testing.T) {
	c := newCollector(t)
	var fetches atomic.Int32
	release := make(chan struct{})
	script := strings.Repeat("/* tracker */", 100)
	c.handle("/v1/s.js", func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		<-release
		w.Write([]byte(script))
	})
	c.json("/collectanalytics/e", 502, map[string]any{})
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, Disable: allBut(ModuleProxy, ModuleFirewall)})
	defer p.Close(context.Background())
	p.firewall.rules.Store(rulesFrom(t, map[string]any{"v": 1, "enabled": true, "mode": "block", "deny": []any{"198.51.100.7"},
		"rate": map[string]any{"limit": 1}, "challenge": map[string]any{}}))
	px := p.Proxy()
	h := p.Middleware(theSite)
	denied := httptest.NewRequest("GET", px.ScriptURL(""), nil)
	denied.RemoteAddr = "198.51.100.7:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, denied)
	if w.Code != 403 || fetches.Load() != 0 {
		t.Fatal("a denied address reached the proxy", w.Code)
	}
	// Ten visitors at once: one fetch.
	var wg sync.WaitGroup
	codes := make(chan int, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- call(h, "GET", px.ScriptURL(""), browserAccept, nil).StatusCode
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 {
			t.Fatal("a beacon path got the rate limit or the check:", code)
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetched %d times", n)
	}
	// Out of date: served at once, refreshed behind it.
	px.mu.Lock()
	px.files["v1/s.js"] = heldFile{[]byte(script), time.Now().Add(-2 * ttlMajor)}
	px.mu.Unlock()
	start := time.Now()
	if res := call(h, "GET", px.ScriptURL(""), "*/*", nil); res.StatusCode != 200 || time.Since(start) > time.Second {
		t.Fatal(res.StatusCode, time.Since(start))
	}
	// The collector failing beacons opens the breaker: answered here at once.
	for i := 0; i < breakerFails; i++ {
		call(h, "POST", px.CollectURL(), "*/*", nil)
	}
	before := len(c.requests("/collectanalytics/e"))
	if res := call(h, "POST", px.CollectURL(), "*/*", nil); res.StatusCode != 503 || len(c.requests("/collectanalytics/e")) != before {
		t.Fatal("the breaker didn't open", res.StatusCode)
	}
}

func TestDashboardHeadersMustBeHarmless(t *testing.T) {
	for _, c := range []struct {
		name, value string
		ok          bool
	}{
		{"X-Frame-Options", "DENY", true}, {"Content-Security-Policy", "default-src 'self';\tframe-ancestors 'none'", true},
		{"Content-Length", "0", false}, {"set-cookie", "a=b", false}, {"Transfer-Encoding", "chunked", false},
		{"Connection", "close", false}, {"X-A", "caf\xc3\xa9", false}, {"X-A", "a\x00b", false}, {"X-A", "a\nb", false},
	} {
		if got := safeHeader(c.name, c.value); got != c.ok {
			t.Errorf("%s: %q = %v", c.name, c.value, got)
		}
	}
}

func TestCloseWithoutADeadlineStillEnds(t *testing.T) {
	stuck := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(20 * time.Second):
		}
	}))
	defer stuck.Close()
	p := New(Options{SiteID: testSite, Secret: "s", Endpoint: stuck.URL, Disable: allBut(ModuleAnalytics)})
	p.Track(context.Background(), "x", nil)
	start := time.Now()
	p.Close(context.Background())
	if d := time.Since(start); d > closeWait+2*time.Second {
		t.Fatal(d)
	}
}

func TestOptionsFromTheEnvironment(t *testing.T) {
	c := newCollector(t)
	t.Setenv("ANALYTICS_SITE_ID", testSite)
	t.Setenv("ANALYTICS_SITE_SECRET", "env-secret")
	t.Setenv("ANALYTICS_ENDPOINT", c.server.URL)
	t.Setenv("ANALYTICS_TRUST_PROXY", "1")
	t.Setenv("ANALYTICS_SERVER_NAME", "env-api")
	p := New(Options{Disable: allBut(ModuleFirewall)})
	defer p.Close(context.Background())
	if !p.core.valid || p.core.secret != "env-secret" || p.core.serverName != "env-api" || p.firewall.trust != "1" {
		t.Fatal(p.core.valid, p.core.serverName, p.firewall.trust)
	}
	// What the code gives wins.
	q := New(Options{SiteID: testSite, Secret: "mine", Endpoint: c.server.URL, Disable: allModules})
	if q.core.secret != "mine" {
		t.Fatal(q.core.secret)
	}
}

// Every module at once from many goroutines, for -race.
func TestStress(t *testing.T) {
	c := newCollector(t)
	c.json("/events/firewall/rules", 200, map[string]any{"v": 1, "enabled": true, "mode": "block", "deny": []string{"198.51.100.7"},
		"rate": map[string]any{"limit": 100000, "window": 60}, "ban": map[string]any{"seconds": 60}, "login": map[string]any{"limit": 3},
		"challenge": map[string]any{"skip": []string{"/api/"}}})
	c.json("/events/platform/config", 200, map[string]any{"v": 1, "modules": map[string]any{}, "headers": [][]string{{"X-Frame-Options", "DENY"}},
		"flags": map[string]any{"f": map[string]any{"on": true, "rollout": 50}}, "maintenance": map[string]any{"on": false}, "sync": 1})
	p := New(Options{SiteID: testSite, Secret: "x", Endpoint: c.server.URL, TrustProxy: "1",
		Disable: []string{ModuleInventory, ModulePosture, ModuleResources},
		Errors:  ErrorsOptions{SpoolDir: t.TempDir(), DisableCrashCapture: true}})
	logger := slog.New(p.SlogHandler(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	mux.HandleFunc("/a/", func(w http.ResponseWriter, r *http.Request) {
		p.Track(r.Context(), "x", map[string]any{"value": 1})
		p.AddBreadcrumb(r.Context(), "hi")
		err := errors.New("boom")
		logger.ErrorContext(r.Context(), "x", "err", err)
		p.CaptureError(r.Context(), err)
		p.LoginFailed(r)
		p.IsEnabled("f", "u")
		p.Audit(r.Context(), "a", AuditEntry{})
		go p.errors.flush(context.Background(), false) // a flush while the request answers
		http.Error(w, "bad", 502)
	})
	mux.HandleFunc("/p", func(w http.ResponseWriter, r *http.Request) { panic("x") })
	mux.HandleFunc("/api/x", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) })
	srv := httptest.NewUnstartedServer(p.Middleware(mux))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the panics are meant
	srv.Start()
	defer srv.Close()
	c.waitFor("/events/firewall/rules", 1)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				path := []string{"/a/1", "/p", "/api/x", "/a/2", "/missing"}[j%5]
				req, _ := http.NewRequest("GET", srv.URL+path, nil)
				if j%2 == 0 {
					req.Header.Set("Accept", "text/html")
				}
				req.Header.Set("X-Forwarded-For", "2001:db8::"+strconv.Itoa(i)+":"+strconv.Itoa(j))
				if res, err := http.DefaultClient.Do(req); err == nil {
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
			}
		}(i)
	}
	go p.Flush(context.Background())
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.Close(ctx)
	if len(c.requests("/events/server-errors")) == 0 || len(c.requests("/events/server-requests")) == 0 {
		t.Fatal("nothing sent")
	}
}

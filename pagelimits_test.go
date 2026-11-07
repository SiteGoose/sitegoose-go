package sitegoose

// Page limits (firewall.md, "Page limits" and step 6 of "Checking a
// request"), against the cases every client shares:
// sdk/protocols/page-limits-cases.json. Then what the shared cases leave to
// each client: a window ending, the shared counter's key, and the 429 the
// middleware answers.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type sharedPageLimits struct {
	Base      map[string]any `json:"base"`
	Scenarios []struct {
		Name     string         `json:"name"`
		Rules    map[string]any `json:"rules"`
		Limits   any            `json:"limits"`
		Requests []struct {
			IP      string          `json:"ip"`
			Method  string          `json:"method"`
			Target  string          `json:"target"`
			Why     string          `json:"why"`
			Expect  json.RawMessage `json:"expect"`
			Reports []string        `json:"reports"`
		} `json:"requests"`
	} `json:"scenarios"`
}

func reportedRules(f *Firewall) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.queue {
		out = append(out, e.Rule)
	}
	sort.Strings(out)
	return out
}

func TestSharedPageLimits(t *testing.T) {
	var cases sharedPageLimits
	readShared(t, "page-limits-cases.json", &cases)
	for _, sc := range cases.Scenarios {
		data := map[string]any{}
		for k, v := range cases.Base {
			data[k] = v
		}
		for k, v := range sc.Rules {
			data[k] = v
		}
		data["limits"] = sc.Limits
		f := testFirewall(t, "s", data, FirewallOptions{})
		for i, r := range sc.Requests {
			f.mu.Lock()
			f.queue = map[string]*firewallEvent{}
			f.mu.Unlock()
			got := f.Check(CheckInput{IP: r.IP, Method: r.Method, Target: r.Target})
			where := sc.Name + ", request " + strconv.Itoa(i+1) + " (" + r.Why + "): " + r.Method + " " + r.Target + " from " + r.IP
			var allow string
			if json.Unmarshal(r.Expect, &allow) == nil {
				if allow != "allow" || got.Action != "allow" || len(reportedRules(f)) != 0 {
					t.Errorf("%s: got %+v, reported %v; want allow, nothing reported", where, got, reportedRules(f))
				}
			} else {
				var want struct {
					Action string `json:"action"`
					Rule   string `json:"rule"`
					Status int    `json:"status"`
				}
				json.Unmarshal(r.Expect, &want)
				if got.Action != want.Action || got.Rule != want.Rule || got.Status != want.Status {
					t.Errorf("%s: got %+v, want %+v", where, got, want)
				}
			}
			if r.Reports != nil {
				want := append([]string(nil), r.Reports...)
				sort.Strings(want)
				if got := reportedRules(f); strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("%s: reported %v, want %v", where, got, want)
				}
			}
		}
	}
}

func loginLimit() map[string]any {
	return map[string]any{"v": 1, "enabled": true, "mode": "block", "limits": map[string]any{"rules": []any{
		map[string]any{"id": "wp.login", "action": "block", "limit": 1, "window": 60,
			"methods": []any{"POST"}, "path": map[string]any{"exact": []any{"/wp-login.php"}}},
	}}}
}

func TestPageLimitWindowEnds(t *testing.T) {
	f := testFirewall(t, "s", loginLimit(), FirewallOptions{})
	start := time.Unix((time.Now().Unix()/60+1)*60, 0)
	f.now = func() time.Time { return start }
	in := CheckInput{IP: "198.51.100.7", Method: "POST", Target: "/wp-login.php"}
	if d := f.Check(in); d.Action != "allow" {
		t.Fatal(d)
	}
	if d := f.Check(in); d.Rule != "limit:wp.login" || d.RetryAfter != 60 {
		t.Fatal(d)
	}
	f.now = func() time.Time { return start.Add(60 * time.Second) }
	if d := f.Check(in); d.Action != "allow" {
		t.Fatal("the count didn't start again with the next window", d)
	}
}

// The "any one page" watcher keeps a count per address and page, which can
// fill a table; it has one of its own, so a full one leaves the login limit
// counting new addresses and keeps the counts it already has.
func TestAFullPerPageTableLeavesOtherLimitsCounting(t *testing.T) {
	data := loginLimit()
	rules := data["limits"].(map[string]any)["rules"].([]any)
	data["limits"].(map[string]any)["rules"] = append(rules, map[string]any{"id": "any.page", "action": "block",
		"limit": 600, "window": 600, "each": "path", "path": map[string]any{"prefix": []any{"/"}}})
	f := testFirewall(t, "s", data, FirewallOptions{})
	now := time.Unix((time.Now().Unix()/600+1)*600, 0)
	f.now = func() time.Time { return now }
	old := CheckInput{IP: "198.51.100.7", Method: "POST", Target: "/wp-login.php"}
	if d := f.Check(old); d.Action != "allow" {
		t.Fatal(d)
	}
	for i := 0; len(f.pathCounts) < counterMax; i++ {
		f.pathCounts["any.page 600 x /"+strconv.Itoa(i)] = &limitCount{window: now.Unix() / 600, ends: now.Add(time.Hour)}
	}
	if d := f.Check(old); d.Rule != "limit:wp.login" {
		t.Fatal("the login count was lost", d)
	}
	newcomer := CheckInput{IP: "203.0.113.9", Method: "POST", Target: "/wp-login.php"}
	if d := f.Check(newcomer); d.Action != "allow" {
		t.Fatal(d)
	}
	if d := f.Check(newcomer); d.Rule != "limit:wp.login" {
		t.Fatal("a new address went uncounted", d)
	}
	if len(f.pathCounts) != counterMax {
		t.Fatal(len(f.pathCounts))
	}
}

func TestPageLimitSharedCounterKey(t *testing.T) {
	data := map[string]any{"v": 1, "enabled": true, "mode": "block", "limits": map[string]any{"rules": []any{
		map[string]any{"id": "login", "action": "block", "limit": 5, "window": 60, "path": map[string]any{"exact": []any{"/login"}}},
		map[string]any{"id": "any", "action": "block", "limit": 5, "window": 60, "each": "path", "path": map[string]any{"prefix": []any{"/"}}},
	}}}
	var keys []string
	f := testFirewall(t, "s", data, FirewallOptions{Counter: func(key string, ttl time.Duration) (int64, error) {
		keys = append(keys, key)
		return 1, nil
	}})
	f.Check(CheckInput{IP: "198.51.100.7", Method: "GET", Target: "/login"})
	// The per-page limit stays here, out of the shared counter.
	if len(keys) != 1 || !strings.HasPrefix(keys[0], "afw:"+testSite+":l:login:198.51.100.7:") {
		t.Fatal(keys)
	}
}

func TestPageLimitsAreThreadSafe(t *testing.T) {
	f := testFirewall(t, "s", loginLimit(), FirewallOptions{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				f.Check(CheckInput{IP: "198.51.100.7", Method: "POST", Target: "/wp-login.php"})
			}
		}()
	}
	wg.Wait()
	if n := len(f.limitCounts); n != 1 {
		t.Fatal(n)
	}
	for _, e := range f.limitCounts {
		if e.hits != 800 {
			t.Fatal(e.hits)
		}
	}
}

func TestMiddlewarePageLimitAnswers429(t *testing.T) {
	data := loginLimit()
	data["rate"] = map[string]any{"limit": 1000, "window": 300}
	p := checkPlatform(t, nil, data)
	h := p.Middleware(theSite)
	post := func() *http.Response {
		r := httptest.NewRequest("POST", "/wp-login.php", nil)
		r.RemoteAddr = "198.51.100.7:5000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result()
	}
	if res := post(); res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	res := post()
	if res.StatusCode != 429 || res.Header.Get("Retry-After") != "60" {
		t.Fatal(res.StatusCode, res.Header)
	}
	if body := bodyOf(res); body != "Too many requests to this page. Please wait a little and try again." {
		t.Fatal(body)
	}
	if p.firewall.bannedHere(mustKey(t, "198.51.100.7")) {
		t.Fatal("a page limit never bans")
	}
}

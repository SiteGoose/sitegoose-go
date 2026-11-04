package sitegoose

// The browser check (rule "challenge"): the shared cases every client runs
// (sdk/protocols/challenge-cases.json), then the check as the middleware answers it.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

const browserAccept = "text/html,application/xhtml+xml,*/*;q=0.8"

type sharedChallenge struct {
	Secret    string         `json:"secret"`
	Challenge map[string]any `json:"challenge"`
	Tokens    []struct {
		IP    string `json:"ip"`
		Who   string `json:"who"`
		Now   int64  `json:"now"`
		Token string `json:"token"`
	} `json:"tokens"`
	Checks []struct {
		IP     string `json:"ip"`
		Now    int64  `json:"now"`
		Cookie string `json:"cookie"`
		Valid  bool   `json:"valid"`
		Why    string `json:"why"`
	} `json:"checks"`
	Decisions []struct {
		Request struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Accept string `json:"accept"`
			IP     string `json:"ip"`
			Cookie string `json:"cookie"`
		} `json:"request"`
		Now        int64  `json:"now"`
		Challenged bool   `json:"challenged"`
		Why        string `json:"why"`
	} `json:"decisions"`
}

func loadChallenge(t *testing.T) sharedChallenge {
	var cases sharedChallenge
	readShared(t, "challenge-cases.json", &cases)
	return cases
}

func challengeRules(check any, more map[string]any) map[string]any {
	data := map[string]any{"v": 1, "enabled": true, "mode": "monitor", "challenge": check}
	for k, v := range more {
		data[k] = v
	}
	return data
}

func TestSharedChallengeTokens(t *testing.T) {
	cases := loadChallenge(t)
	key := passKey(cases.Secret)
	for _, c := range cases.Tokens {
		if got := passWho(c.IP); got != c.Who {
			t.Errorf("who(%s) = %q, want %q", c.IP, got, c.Who)
		}
		if got := makePass(key, c.IP, time.Unix(c.Now, 0)); got != c.Token {
			t.Errorf("pass(%s) = %q, want %q", c.IP, got, c.Token)
		}
	}
}

func TestSharedChallengeChecks(t *testing.T) {
	cases := loadChallenge(t)
	key := passKey(cases.Secret)
	for _, c := range cases.Checks {
		if got := passValid(key, c.IP, c.Cookie, time.Unix(c.Now, 0)); got != c.Valid {
			t.Errorf("%s: valid = %v, want %v", c.Why, got, c.Valid)
		}
	}
}

func TestSharedChallengeDecisions(t *testing.T) {
	cases := loadChallenge(t)
	for _, c := range cases.Decisions {
		f := testFirewall(t, cases.Secret, challengeRules(cases.Challenge, nil), FirewallOptions{})
		cookie := ""
		if c.Request.Cookie != "" {
			cookie = "__sg_pass=" + c.Request.Cookie
		}
		d := f.check(CheckInput{IP: c.Request.IP, Method: c.Request.Method, Target: c.Request.Path, UserAgent: "Mozilla/5.0",
			Accept: c.Request.Accept, Cookie: cookie}, time.Unix(c.Now, 0))
		if (d.Rule == "challenge") != c.Challenged {
			t.Errorf("%s: rule %q", c.Why, d.Rule)
		}
		if c.Challenged && (d.Action != "block" || d.Status != 503) {
			t.Errorf("%s: %+v", c.Why, d)
		}
	}
}

func TestAllowAndGoodbotsAreNeverChecked(t *testing.T) {
	f := testFirewall(t, "s", challengeRules(map[string]any{}, map[string]any{"allow": []string{"198.51.100.9"}, "goodbots": []string{"192.0.2.0/24"}}), FirewallOptions{})
	for ip, want := range map[string]string{"198.51.100.9": "", "192.0.2.5": "", "203.0.113.5": "challenge"} {
		if got := f.Check(CheckInput{IP: ip, Method: "GET", Target: "/", Accept: browserAccept}).Rule; got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
}

func TestChallengeBlocksEvenInMonitorMode(t *testing.T) {
	f := testFirewall(t, "s", challengeRules(map[string]any{}, map[string]any{"mode": "block"}), FirewallOptions{Mode: "monitor"})
	if d := f.Check(CheckInput{IP: "203.0.113.5", Method: "GET", Target: "/", Accept: browserAccept}); d.Action != "block" {
		t.Fatalf("%+v", d)
	}
}

func TestEarlierRulesWinInBlockMode(t *testing.T) {
	f := testFirewall(t, "s", challengeRules(map[string]any{}, map[string]any{"mode": "block", "deny": []string{"203.0.113.0/24"}}), FirewallOptions{})
	if d := f.Check(CheckInput{IP: "203.0.113.5", Method: "GET", Target: "/", Accept: browserAccept}); d.Rule != "deny" {
		t.Fatalf("%+v", d)
	}
	f = testFirewall(t, "s", challengeRules(map[string]any{}, map[string]any{"mode": "block", "rate": map[string]any{"limit": 1, "window": 60}}), FirewallOptions{})
	var got []string
	for i := 0; i < 2; i++ {
		got = append(got, f.Check(CheckInput{IP: "203.0.113.5", Method: "GET", Target: "/", Accept: browserAccept}).Rule)
	}
	if strings.Join(got, ",") != "challenge,rate" {
		t.Fatal(got)
	}
}

func TestAWatchedMatchStillGetsTheCheck(t *testing.T) {
	f := testFirewall(t, "s", challengeRules(map[string]any{}, map[string]any{"deny": []string{"203.0.113.0/24"}}), FirewallOptions{})
	d := f.Check(CheckInput{IP: "203.0.113.5", Method: "GET", Target: "/", Accept: browserAccept})
	if d.Rule != "challenge" || d.Action != "block" || d.Status != 503 {
		t.Fatalf("%+v", d)
	}
	var rows []string
	for _, row := range f.queue {
		rows = append(rows, row.Rule+"/"+row.Action)
	}
	if len(rows) != 2 || !(contains(rows, "challenge/block") && contains(rows, "deny/monitor")) {
		t.Fatal(rows)
	}
	// Not a page load: the watched match passes, as before.
	if d := f.Check(CheckInput{IP: "203.0.113.5", Method: "POST", Target: "/", Accept: browserAccept}); d.Action != "monitor" {
		t.Fatalf("%+v", d)
	}
}

func contains(list []string, s string) bool { return containsString(list, s) }

func TestAPassFromThisServerLetsTheNextRequestThrough(t *testing.T) {
	f := testFirewall(t, "s", challengeRules(map[string]any{}, nil), FirewallOptions{})
	token := makePass(f.passKey, "203.0.113.5", time.Now())
	d := f.Check(CheckInput{IP: "203.0.113.5", Method: "GET", Target: "/", Accept: browserAccept, Cookie: "theme=dark; __sg_pass=" + token})
	if d.Rule != "" {
		t.Fatalf("%+v", d)
	}
}

func TestNoChallengeKeyChangesNothing(t *testing.T) {
	f := testFirewall(t, "s", challengeRules(nil, nil), FirewallOptions{})
	if d := f.Check(CheckInput{IP: "203.0.113.5", Method: "GET", Target: "/", Accept: browserAccept}); d != (Decision{Action: "allow", Status: 200}) {
		t.Fatalf("%+v", d)
	}
}

func TestChallengeIsReportedGrouped(t *testing.T) {
	f := testFirewall(t, "s", challengeRules(map[string]any{}, nil), FirewallOptions{})
	for i := 0; i < 2; i++ {
		f.Check(CheckInput{IP: "203.0.113.5", Method: "GET", Target: "/pricing?x=1", UserAgent: "Mozilla/5.0", Accept: browserAccept})
	}
	if len(f.queue) != 1 {
		t.Fatal(len(f.queue))
	}
	for _, row := range f.queue {
		if row.IP != "203.0.113.5" || row.Rule != "challenge" || row.Action != "block" || row.Method != "GET" || row.Path != "/pricing" || row.Hits != 2 {
			t.Fatalf("%+v", row)
		}
	}
}

func TestThePage(t *testing.T) {
	key := passKey("s")
	status, h, body := challengeResponse(key, "203.0.113.5", "GET", time.Now())
	if status != 503 || h.Get("Content-Type") != "text/html; charset=utf-8" || h.Get("Cache-Control") != "no-store" || h.Get("X-Robots-Tag") != "noindex" {
		t.Fatal(status, h)
	}
	nonce := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(h.Get("Content-Security-Policy"))
	if nonce == nil {
		t.Fatal(h.Get("Content-Security-Policy"))
	}
	text := string(body)
	for _, want := range []string{`<script nonce="` + nonce[1] + `">`, `<style nonce="` + nonce[1] + `">`, makePass(key, "203.0.113.5", time.Now()),
		"Max-Age=86400; Path=/; SameSite=Lax", `s=location.protocol==="https:"`, `(s?"; Secure":"")`, "location.reload()", "<noscript>",
		"sessionStorage.getItem(k)", "r>=3", "Date.now()-x<60000", "address keeps changing", "body{font:16px/1.5 system-ui"} {
		if !strings.Contains(text, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	_, h2, _ := challengeResponse(key, "203.0.113.5", "GET", time.Now())
	if h2.Get("Content-Security-Policy") == h.Get("Content-Security-Policy") {
		t.Error("the nonce is the same twice")
	}
}

// The script, byte for byte the Python client's (and so the Node and PHP ones').
func TestTheScriptIsTheOtherClients(t *testing.T) {
	want := `(function(){var n="__sg_pass",v="20761.0ddc48fd8c38f7a225623a9a27f1d364",m=document.getElementById("m"),s=location.protocol==="https:";` +
		`document.cookie=n+"="+v+"; Max-Age=86400; Path=/; SameSite=Lax"+(s?"; Secure":"");` +
		`if((" "+document.cookie+";").indexOf(" "+n+"="+v+";")<0){m.textContent="Please allow cookies for this site, then reload the page.";return;}` +
		`var k="__sg_tries",r=0,t;try{t=JSON.parse(sessionStorage.getItem(k)||"[]").filter(function(x){return Date.now()-x<60000;});r=t.length;if(r<3){t.push(Date.now());sessionStorage.setItem(k,JSON.stringify(t));}}` +
		`catch(e){t=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie);r=t?+t[1]:0;if(r<3)document.cookie=k+"="+(r+1)+"; Max-Age=60; Path=/; SameSite=Lax"+(s?"; Secure":"");}` +
		`if(r>=3){m.textContent="This page couldn't be opened because your connection's address keeps changing. Please try again in a minute.";return;}location.reload();})();`
	if got := challengeScript("20761.0ddc48fd8c38f7a225623a9a27f1d364"); got != want {
		t.Fatalf("script differs:\n%s", got)
	}
}

func TestHeadGetsNoBody(t *testing.T) {
	status, h, body := challengeResponse(passKey("s"), "203.0.113.5", "HEAD", time.Now())
	if status != 503 || len(body) != 0 || h.Get("Content-Security-Policy") == "" {
		t.Fatal(status, len(body))
	}
}

func TestATenDigitDayIsRead(t *testing.T) {
	key := passKey("s")
	now := time.Unix(1234567890*86400, 0)
	value := makePass(key, "203.0.113.5", now)
	if !strings.HasPrefix(value, "1234567890.") || !passValid(key, "203.0.113.5", value, now) {
		t.Fatal(value)
	}
}

// ---- Through the middleware ----

func checkPlatform(t *testing.T, check any, more map[string]any) *Platform {
	p := New(Options{SiteID: testSite, Secret: "s", Disable: []string{ModuleErrors, ModuleAnalytics, ModulePerformance, ModuleCrawlers,
		ModuleForms, ModuleHeaders, ModuleAudit, ModuleFlags, ModuleMaintenance, ModuleInventory, ModulePosture, ModuleResources, ModuleProxy}})
	p.firewall.rules.Store(rulesFrom(t, challengeRules(check, more)))
	return p
}

var theSite = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("the site")) })

func call(h http.Handler, method, path, accept string, headers map[string][]string) *http.Response {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "203.0.113.5:5000"
	r.Header.Set("Accept", accept)
	for k, v := range headers {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

func bodyOf(res *http.Response) string {
	data, _ := io.ReadAll(res.Body)
	return string(data)
}

func TestMiddlewareABrowserPageGetsTheCheck(t *testing.T) {
	cases := loadChallenge(t)
	h := checkPlatform(t, cases.Challenge, nil).Middleware(theSite)
	res := call(h, "GET", "/pricing", browserAccept, nil)
	if res.StatusCode != 503 || res.Header.Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(bodyOf(res), "__sg_pass") {
		t.Fatal(res.StatusCode, res.Header)
	}
	head := call(h, "HEAD", "/pricing", browserAccept, nil)
	if head.StatusCode != 503 || bodyOf(head) != "" {
		t.Fatal(head.StatusCode)
	}
}

func TestMiddlewarePostJSONAndSkippedPathsReachTheSite(t *testing.T) {
	cases := loadChallenge(t)
	h := checkPlatform(t, cases.Challenge, nil).Middleware(theSite)
	for _, c := range []struct{ method, path, accept string }{
		{"POST", "/pricing", browserAccept}, {"GET", "/pricing", "application/json"}, {"GET", "/api/orders", browserAccept},
	} {
		if got := bodyOf(call(h, c.method, c.path, c.accept, nil)); got != "the site" {
			t.Errorf("%v: %q", c, got)
		}
	}
}

func TestMiddlewareWithAPassTheSiteAnswers(t *testing.T) {
	cases := loadChallenge(t)
	p := checkPlatform(t, cases.Challenge, nil)
	token := makePass(p.firewall.passKey, "203.0.113.5", time.Now())
	h := p.Middleware(theSite)
	if got := bodyOf(call(h, "GET", "/pricing", browserAccept, map[string][]string{"Cookie": {"__sg_pass=" + token}})); got != "the site" {
		t.Fatal(got)
	}
	// HTTP/2 may split the Cookie header over several fields.
	if got := bodyOf(call(h, "GET", "/pricing", browserAccept, map[string][]string{"Cookie": {"theme=dark", "__sg_pass=" + token}})); got != "the site" {
		t.Fatal(got)
	}
}

func TestMiddlewareNoChallengeChangesNothing(t *testing.T) {
	h := checkPlatform(t, nil, nil).Middleware(theSite)
	if got := bodyOf(call(h, "GET", "/pricing", browserAccept, nil)); got != "the site" {
		t.Fatal(got)
	}
}

func TestMiddlewareOtherRefusalsKeepTheirStatus(t *testing.T) {
	cases := loadChallenge(t)
	h := checkPlatform(t, cases.Challenge, map[string]any{"mode": "block", "deny": []string{"203.0.113.5"}}).Middleware(theSite)
	res := call(h, "GET", "/pricing", browserAccept, nil)
	if res.StatusCode != 403 || bodyOf(res) != "Forbidden" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal(res.StatusCode)
	}
}

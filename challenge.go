package sitegoose

// The browser check (rule "challenge", sdk/protocols/firewall.md under "Flood
// protection"): a GET or HEAD that asks for a page, from an address with no
// valid pass, gets a small page instead of the site. Its script sets the pass
// cookie and reloads, which a script that doesn't run JavaScript never does.
//
// The pass is <day>.<first 32 hex digits of HMAC-SHA256(key, "<day>|<who>")>,
// key = HMAC-SHA256 of "sg-challenge-v1" keyed with the site secret, so any of
// the site's servers accepts a pass another one handed out. It counts for its
// own day and the next. sdk/protocols/challenge-cases.json holds the cases
// every client runs; backend/scripts/challenge-cases.mjs is the reference.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	passCookie  = "__sg_pass"
	passMaxAge  = 86400
	passLabel   = "sg-challenge-v1"
	maxSkipRule = 200
)

var passPattern = regexp.MustCompile(`^(\d{1,10})\.([0-9a-f]{32})$`)

// passKey is the key every pass is signed with, from the site secret.
func passKey(secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(passLabel))
	return mac.Sum(nil)
}

// passWho is what a pass is bound to: the IPv4 address (an IPv4-mapped IPv6
// address as IPv4), or an IPv6 address's /64 as four groups of four
// lower-case hex digits. "*" for the agent's nginx (a package never accepts
// it); "" for anything that isn't an address.
func passWho(ip string) string {
	text := strings.TrimSpace(ip)
	if text == "*" {
		return "*"
	}
	addr, ok := parseAddr(text)
	if !ok {
		return ""
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	b := addr.As16()
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7])
}

// dayOf is whole days since 1970-01-01 UTC.
func dayOf(now time.Time) int64 {
	s := now.Unix()
	if s < 0 {
		return (s - 86399) / 86400
	}
	return s / 86400
}

func signPass(key []byte, day int64, bound string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strconv.FormatInt(day, 10) + "|" + bound))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// makePass is today's pass for this address, or "" when it isn't one.
func makePass(key []byte, ip string, now time.Time) string {
	bound := passWho(ip)
	if bound == "" {
		return ""
	}
	day := dayOf(now)
	return strconv.FormatInt(day, 10) + "." + signPass(key, day, bound)
}

// passValid: value is this address's pass for today or yesterday.
func passValid(key []byte, ip, value string, now time.Time) bool {
	m := passPattern.FindStringSubmatch(value)
	bound := passWho(ip)
	if m == nil || bound == "" || bound == "*" {
		return false
	}
	day, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return false
	}
	today := dayOf(now)
	if day != today && day != today-1 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(m[2]), []byte(signPass(key, day, bound))) == 1
}

// cookieValues is every value the Cookie header carries under name (a
// browser can send two, from different paths); at most four, like the Node client.
func cookieValues(header, name string) []string {
	var found []string
	for _, part := range strings.Split(header, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(key) != name {
			continue
		}
		found = append(found, strings.Trim(strings.TrimSpace(value), `"`))
		if len(found) == 4 {
			break
		}
	}
	return found
}

func hasPass(key []byte, ip, cookie string, now time.Time) bool {
	for _, value := range cookieValues(cookie, passCookie) {
		if passValid(key, ip, value, now) {
			return true
		}
	}
	return false
}

// compileSkip: the rules' skip prefixes, lower-cased.
func compileSkip(entries []any) []string {
	var out []string
	for _, entry := range entries {
		if s, ok := entry.(string); ok && s != "" {
			out = append(out, strings.ToLower(s))
			if len(out) == maxSkipRule {
				break
			}
		}
	}
	return out
}

// asksForPage is conditions 1 to 3: a GET or HEAD, whose Accept asks for
// text/html, for a path (lower-cased, no query string) under none of skip.
func asksForPage(method, target, accept string, skip []string) bool {
	method = strings.ToUpper(method)
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	if !strings.Contains(strings.ToLower(accept), "text/html") {
		return false
	}
	path := target
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if i := strings.IndexByte(path, '#'); i >= 0 {
		path = path[:i]
	}
	path = strings.ToLower(path)
	for _, prefix := range skip {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

const challengePage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Just a moment</title>
<style nonce="{nonce}">body{font:16px/1.5 system-ui,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;color:#222;background:#fafafa}main{max-width:28rem;padding:2rem;text-align:center}</style>
</head><body><main><p id="m">Checking your browser before you continue&hellip;</p>
<noscript><p>Please turn on JavaScript to continue to this site.</p></noscript></main>
<script nonce="{nonce}">{script}</script>
</body></html>
`

// challengeScript sets the pass and reloads, but only when reading the cookie
// back shows it was set (with cookies off it says so instead of reloading
// forever), and at most three times a minute, counted in sessionStorage (an
// address that changes on every request, a pool of exit addresses, would
// otherwise never get a pass that holds and reload for ever), or in a
// __sg_tries cookie lasting a minute where storage is blocked or full. Secure
// only when the browser is on https: it knows, where the server behind a
// proxy can only be told. The same script as the Node, PHP and Python clients'.
func challengeScript(value string) string {
	return `(function(){var n="` + passCookie + `",v="` + value + `",m=document.getElementById("m"),` +
		`s=location.protocol==="https:";` +
		`document.cookie=n+"="+v+"; Max-Age=` + strconv.Itoa(passMaxAge) + `; Path=/; SameSite=Lax"+(s?"; Secure":"");` +
		`if((" "+document.cookie+";").indexOf(" "+n+"="+v+";")<0){m.textContent="Please allow cookies for this site, then reload the page.";return;}` +
		`var k="__sg_tries",r=0,t;` +
		`try{t=JSON.parse(sessionStorage.getItem(k)||"[]").filter(function(x){return Date.now()-x<60000;});r=t.length;if(r<3){t.push(Date.now());sessionStorage.setItem(k,JSON.stringify(t));}}` +
		`catch(e){t=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie);r=t?+t[1]:0;if(r<3)document.cookie=k+"="+(r+1)+"; Max-Age=60; Path=/; SameSite=Lax"+(s?"; Secure":"");}` +
		`if(r>=3){m.textContent="This page couldn't be opened because your connection's address keeps changing. Please try again in a minute.";return;}` +
		`location.reload();})();`
}

func newNonce() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		// A nonce nobody can predict is the point; without randomness the
		// time is still unique per page, and the page stays usable.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// challengeResponse is the check page: 503, its own Content-Security-Policy
// with a fresh nonce for its one script, and no body for a HEAD. The script
// marks the cookie Secure when the page itself is https: whatever proxies sit
// in front, that is the one answer that is never wrong.
func challengeResponse(key []byte, ip, method string, now time.Time) (int, http.Header, []byte) {
	nonce := newNonce()
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+
		"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if strings.ToUpper(method) == http.MethodHead {
		return http.StatusServiceUnavailable, h, nil
	}
	body := strings.NewReplacer("{nonce}", nonce, "{script}", challengeScript(makePass(key, ip, now))).Replace(challengePage)
	return http.StatusServiceUnavailable, h, []byte(body)
}

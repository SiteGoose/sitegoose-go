package sitegoose

// Outgoing calls (sdk/protocols/calls.md): the other half of why a route is
// slow, beside its database queries. Every call made through p.Transport is
// timed from being sent to its response's headers arriving and filed by
// call method and host under the request (or p.Job) its context belongs to,
// else as JOB "(background)"; one row per minute, method, route, call
// method and host goes to POST /events/server-calls (queries.go does the
// filing for both). Only the host is kept: a call's path, query string,
// headers and body never leave this server. On with the performance module,
// unless PerformanceOptions.DisableCalls.

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	callHostPattern   = regexp.MustCompile(`^[a-z0-9._\-\[\]:]{1,255}$`)
	callMethodPattern = regexp.MustCompile(`^[A-Z]{1,10}$`)
)

// callHost is the host a call went to as calls.md stores it: lower case,
// with its port only when it isn't the scheme's default. "" when it isn't one.
func callHost(u *url.URL) string {
	if u == nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	if !callHostPattern.MatchString(host) {
		return ""
	}
	return host
}

// recordCall files one call: status 0 is no answer (refused, timed out,
// reset), which fails like a 5xx; a 4xx is the other side's answer.
func (p *Platform) recordCall(ctx context.Context, method, host string, d time.Duration, status int) {
	if p == nil || p.calls == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.core.log("performance", "could not count a call: %v", r)
		}
	}()
	method = strings.ToUpper(firstNonEmpty(method, "GET"))
	if !callMethodPattern.MatchString(method) || host == "" {
		return
	}
	p.calls.record(ctx, p, method, host, float64(d)/float64(time.Millisecond), status <= 0 || status >= 500)
}

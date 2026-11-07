package sitegoose

// Performance & API monitoring module: times every request (from arriving to
// the handler returning) and sends one row per minute, method, route and
// status code (how many, total and slowest time, and a count per time
// bucket) to POST /events/server-requests. Nothing about visitors is sent.
//
// The route is the router's own pattern when it is known (ServeMux's
// r.Pattern, chi, gin and echo through their adapters, or SetRoute);
// otherwise numbers and IDs in the path become ":id", and unmatched 404s are
// one route.

import (
	"context"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Keep in step with the collector (expresscollect/Analytics/serverRequests.js).
var bucketEdgesMS = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

const (
	performanceFlush = 60 * time.Second
	maxRouteKeys     = 300
	maxFoldedKeys    = 100 // (other) rows, by method and status, past maxRouteKeys
	maxRows          = 500
	notFoundRoute    = "/(not found)"
)

var (
	idSegment = regexp.MustCompile(`(?i)^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$`)
	hasDigit  = regexp.MustCompile(`\d`)
)

// normalizeRoute: "/orders/123/items/9f8e..." -> "/orders/:id/items/:id".
func normalizeRoute(path string) string {
	if loc := queryOrFragment.FindStringIndex(path); loc != nil {
		path = path[:loc[0]]
	}
	if path == "" {
		path = "/"
	}
	parts := strings.Split(path, "/")
	for i, s := range parts {
		if idSegment.MatchString(s) || (len([]rune(s)) >= 20 && hasDigit.MatchString(s)) {
			parts[i] = ":id"
		}
	}
	route := strings.Join(parts, "/")
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	return truncate(route, 200)
}

// patternRoute turns a ServeMux pattern ("GET example.com/orders/{id}") into
// the route Server speed shows: the path part, without method or host.
func patternRoute(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return ""
	}
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		pattern = strings.TrimSpace(pattern[i+1:])
	}
	if !strings.HasPrefix(pattern, "/") {
		i := strings.IndexByte(pattern, '/')
		if i < 0 {
			return ""
		}
		pattern = pattern[i:]
	}
	return pattern
}

func bucketOf(ms float64) int {
	for i, edge := range bucketEdgesMS {
		if ms <= edge {
			return i
		}
	}
	return len(bucketEdgesMS)
}

// PerformanceOptions configure Server speed.
type PerformanceOptions struct {
	// ServerName names this service; default Options.ServerName, else the host name.
	ServerName string
	// Route names a request's route your own way ("" falls back to the router's pattern).
	Route func(r *http.Request) string
	// DisableQueries keeps Server speed and leaves database queries out
	// (OpenDB, WrapConnector, the pgx, Mongo and ClickHouse hooks then record nothing).
	DisableQueries bool
	// DisableCalls keeps Server speed and leaves outgoing calls out
	// (p.Transport then only adds breadcrumbs).
	DisableCalls bool
	// DisableQueues keeps Server speed and leaves job queues out
	// (p.WatchQueues and the asynq watcher then read nothing).
	DisableQueues bool
}

type perfKey struct {
	minute int64
	method string
	route  string
	status int
}

type perfRow struct {
	count   int64
	sumMS   float64
	maxMS   float64
	buckets []int64
}

type performance struct {
	core       *core
	serverName string
	route      func(*http.Request) string
	mu         sync.Mutex
	rows       map[perfKey]*perfRow
	job        *periodic
	now        func() time.Time

	// Requests in progress now, and the most at once since the resources
	// module last asked. timed stays false until the middleware first runs,
	// so an app that never installed it reports no peak rather than 0.
	flightMu sync.Mutex
	inflight int64
	peak     int64
	timed    bool
}

// started counts a request the middleware is now handling.
func (p *performance) started() {
	p.flightMu.Lock()
	p.timed = true
	p.inflight++
	if p.inflight > p.peak {
		p.peak = p.inflight
	}
	p.flightMu.Unlock()
}

// ended counts it done.
func (p *performance) ended() {
	p.flightMu.Lock()
	if p.inflight > 0 {
		p.inflight--
	}
	p.flightMu.Unlock()
}

// takeInflightPeak is the most requests in progress at once since the last
// call, and starts the next interval at what is still in progress; false
// until the middleware has seen a request.
func (p *performance) takeInflightPeak() (int64, bool) {
	p.flightMu.Lock()
	defer p.flightMu.Unlock()
	if !p.timed {
		return 0, false
	}
	most := p.peak
	p.peak = p.inflight
	return most, true
}

func newPerformance(c *core, o PerformanceOptions) *performance {
	p := &performance{core: c, serverName: truncate(firstNonEmpty(o.ServerName, hostname()), 100), route: o.Route,
		rows: map[perfKey]*perfRow{}, now: time.Now}
	p.job = c.every(performanceFlush, func() time.Duration {
		p.flush(context.Background(), false)
		return performanceFlush
	})
	return p
}

// perfName is the method and route a request is counted under. route: the
// router's pattern, or "" to work it out from path.
func perfName(method, route string, status int, path string) (string, string) {
	if route == "" {
		if status == http.StatusNotFound {
			route = notFoundRoute
		} else {
			route = normalizeRoute(path)
		}
	}
	return methodName(method), truncate(route, 200)
}

// record counts one finished request, and gives the method and route it was
// counted under ("" when the module is off), which its queries are counted
// under too.
func (p *performance) record(method, route string, status int, ms float64, path string) (string, string) {
	if !p.core.isOn(ModulePerformance) {
		return "", ""
	}
	method, route = perfName(method, route, status, path)
	minute := p.now().Unix() / 60 * 60
	key := perfKey{minute, method, route, statusCode(status)}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.rows[key]; !ok && len(p.rows) >= maxRouteKeys {
		key.route = "(other)"
		// Past even that, method and status fold too: nothing a client
		// sends can make the table grow without end.
		if _, ok := p.rows[key]; !ok && len(p.rows) >= maxRouteKeys+maxFoldedKeys {
			key.method, key.status = "OTHER", key.status/100*100
		}
	}
	row := p.rows[key]
	if row == nil {
		row = &perfRow{buckets: make([]int64, len(bucketEdgesMS)+1)}
		p.rows[key] = row
	}
	row.count++
	row.sumMS += ms
	if ms > row.maxMS {
		row.maxMS = ms
	}
	row.buckets[bucketOf(ms)]++
	return key.method, key.route
}

// knownMethods are the methods kept by name; anything else a client sends
// is OTHER, so made-up methods can't make a row each.
var knownMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"OPTIONS": true, "CONNECT": true, "TRACE": true, "JOB": true}

func methodName(method string) string {
	method = strings.ToUpper(firstNonEmpty(method, "GET"))
	if knownMethods[method] {
		return method
	}
	return "OTHER"
}

// statusCode keeps a status in 100-599; anything else is 0.
func statusCode(status int) int {
	if status < 100 || status > 599 {
		return 0
	}
	return status
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func (p *performance) flush(ctx context.Context, everything bool) {
	current := p.now().Unix() / 60 * 60
	p.mu.Lock()
	var rows []map[string]any
	for k, v := range p.rows {
		if !everything && k.minute >= current {
			continue
		}
		delete(p.rows, k)
		rows = append(rows, map[string]any{
			"minute": isoMinute(time.Unix(k.minute, 0)), "method": k.method, "route": k.route, "status": k.status,
			"count": v.count, "sum_ms": round1(v.sumMS), "max_ms": round1(v.maxMS), "buckets": v.buckets,
		})
	}
	p.mu.Unlock()
	inChunks(rows, func(part []map[string]any) {
		p.core.send(ctx, "performance", "/events/server-requests", http.MethodPost,
			map[string]any{"server_name": p.serverName, "runtime": runtimeName(), "rows": part}, authBody, nil)
	})
}

func (p *performance) close(ctx context.Context) {
	p.job.halt(ctx)
	p.flush(ctx, true)
}

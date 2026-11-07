package sitegoose

// The request or job being handled, carried in its context: its route and
// visit, so an error captured deep in your code still says which request it
// came from, and its trail of breadcrumbs.

import (
	"context"
	"net/http"
	"sync"
	"time"
)

const maxCrumbs = 15

type crumb struct {
	kind   string
	text   string
	status *int
	at     time.Time
}

// Breadcrumb is one step before an error, as the tracker sends them.
type Breadcrumb struct {
	Type   string `json:"type"`
	Text   string `json:"text"`
	Status *int   `json:"status,omitempty"`
	MS     int64  `json:"ms"`
}

type reqState struct {
	platform *Platform
	method   string
	path     string
	session  string
	ip       string
	job      bool
	request  *http.Request // the request as the router sees it: ServeMux sets its Pattern
	mux      *http.ServeMux
	late     *lateHit // a static file the firewall counts after the response

	mu       sync.Mutex
	route    string
	trail    []crumb
	captured []*queuedError
	panicked bool
	errored  bool // an error this request ended with is already captured
	aborted  bool // http.ErrAbortHandler: the handler gave up on the answer
	hijacked bool // the connection was taken over (a WebSocket)

	queries requestQueries // the database queries it ran
	calls   requestQueries // the outgoing HTTP calls it made
}

type stateKey struct{}

func stateFrom(ctx context.Context) *reqState {
	if ctx == nil {
		return nil
	}
	st, _ := ctx.Value(stateKey{}).(*reqState)
	return st
}

func withState(ctx context.Context, st *reqState) context.Context {
	return context.WithValue(ctx, stateKey{}, st)
}

func (st *reqState) addCrumb(kind, text string, status *int) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.trail = append(st.trail, crumb{kind: kind, text: truncate(text, 200), status: status, at: time.Now()})
	if len(st.trail) > maxCrumbs {
		st.trail = st.trail[len(st.trail)-maxCrumbs:]
	}
}

// breadcrumbs is the trail as the tracker sends it: how long before now each step happened.
func (st *reqState) breadcrumbs() []Breadcrumb {
	if st == nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.trail) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]Breadcrumb, len(st.trail))
	for i, c := range st.trail {
		ms := now.Sub(c.at).Milliseconds()
		if ms < 0 {
			ms = 0
		}
		out[i] = Breadcrumb{Type: c.kind, Text: c.text, Status: c.status, MS: ms}
	}
	return out
}

// routeName is the request's route as Server speed names it: one given with
// SetRoute (the chi, gin and echo adapters), the Performance.Route option,
// else ServeMux's pattern. "" when none is known.
func (st *reqState) routeName() string {
	if st == nil {
		return ""
	}
	st.mu.Lock()
	route := st.route
	st.mu.Unlock()
	if route != "" || st.job {
		return route
	}
	p := st.platform
	if p != nil && p.perf != nil && p.perf.route != nil && st.request != nil {
		if r := safeRoute(p.perf.route, st.request); r != "" {
			return r
		}
	}
	if st.request != nil {
		if r := patternRoute(requestPattern(st.request)); r != "" {
			return r
		}
		if st.mux != nil {
			if _, pattern := st.mux.Handler(st.request); pattern != "" {
				return patternRoute(pattern)
			}
		}
	}
	return ""
}

// routePattern is the route the router sent the request to, as it wrote
// it: one given with SetRoute (the chi, gin and echo adapters), else
// ServeMux's pattern ("GET /search/{q}"). "" when none matched.
func (st *reqState) routePattern() string {
	st.mu.Lock()
	route := st.route
	st.mu.Unlock()
	if route != "" || st.request == nil {
		return route
	}
	if pattern := requestPattern(st.request); pattern != "" {
		return pattern
	}
	if st.mux != nil {
		_, pattern := st.mux.Handler(st.request)
		return pattern
	}
	return ""
}

func safeRoute(fn func(*http.Request) string, r *http.Request) (route string) {
	defer func() {
		if recover() != nil {
			route = ""
		}
	}()
	return fn(r)
}

// SetRoute names the route of the request ctx belongs to ("/orders/{id}"),
// for routers this package has no adapter for. Server speed and the errors
// of that request use it.
func SetRoute(ctx context.Context, route string) {
	if st := stateFrom(ctx); st != nil && route != "" {
		st.mu.Lock()
		st.route = truncate(route, 200)
		st.mu.Unlock()
	}
}

// SessionID is the browser's visit, from the X-Analytics-Session header the
// page sends (window.analyticsSession.getId()).
func SessionID(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get(SessionHeader)
}

func sessionFrom(ctx context.Context) string {
	if st := stateFrom(ctx); st != nil {
		return st.session
	}
	return ""
}

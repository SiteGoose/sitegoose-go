package sitegoose

// The request path: the first-party proxy answers its own addresses, the
// firewall turns away what it blocks (and the browser check what it
// checks), maintenance mode answers "back soon", and everything else runs
// with its route, visit and trail in its context, is timed, has the
// dashboard's security headers added, counts as a crawler visit when it is
// one, and is sent as an error when it panics or answers 5xx.
//
// Our own code never stops a request: anything of ours that fails lets the
// request through as if the package weren't there.

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Middleware wraps your handler; put it outermost, so it sees every request
// first:
//
//	http.ListenAndServe(":8080", p.Middleware(mux))
//
// A handler's panic is sent and then panics on, so net/http answers it as it
// always does. With a *http.ServeMux as next, Server speed names each route
// by its pattern ("/orders/{id}").
func (p *Platform) Middleware(next http.Handler) http.Handler {
	mux, _ := next.(*http.ServeMux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ex := p.Begin(w, r)
		if ex == nil {
			return
		}
		if ex.nested {
			next.ServeHTTP(w, ex.Request())
			return
		}
		ex.st.mux = mux
		rw := &responseWriter{ResponseWriter: w, ex: ex}
		defer func() {
			if v := recover(); v != nil {
				ex.Recovered(v)
				ex.Finish(http.StatusInternalServerError, rw.size)
				panic(v)
			}
			ex.finish(rw.code(), rw.size, rw)
		}()
		next.ServeHTTP(rw, ex.Request())
	})
}

// Exchange is one request on its way through: for framework adapters (gin,
// echo) that can't wrap the http.Handler. Begin starts it, Finish ends it.
type Exchange struct {
	p       *Platform
	r       *http.Request
	w       http.ResponseWriter // its Content-Type, read once answered
	st      *reqState
	started time.Time
	ua      string
	nested  bool
	done    bool
	// inFlight: counted as in progress for the resources module's peak,
	// until it finishes or its connection is taken over.
	inFlight atomic.Bool
}

// Begin runs what comes before the handler. nil means the request has been
// answered (the proxy, the firewall, maintenance mode) and the handler must
// not run. Inside Middleware it returns an Exchange that only passes the
// route and errors on, so an adapter can be used with or without it.
func (p *Platform) Begin(w http.ResponseWriter, r *http.Request) (ex *Exchange) {
	if st := stateFrom(r.Context()); st != nil && st.platform == p && !st.job {
		return &Exchange{p: p, r: r, st: st, nested: true}
	}
	started := time.Now()
	answer, ip, remember, late := p.before(r)
	switch {
	case answer != nil && answer.custom != nil:
		answer.custom(w, r)
		p.RecordCrawler(r.UserAgent(), r.URL.Path, answer.status, time.Since(started), 0, ip)
		return nil
	case answer != nil:
		writeAnswer(w, answer)
		if answer.crawler {
			p.RecordCrawler(r.UserAgent(), r.URL.Path, answer.status, time.Since(started), int64(len(answer.body)), ip)
		}
		return nil
	case remember != "":
		w.Header().Add("Set-Cookie", remember)
	}
	st := &reqState{platform: p, method: r.Method, path: r.URL.Path, session: SessionID(r), ip: ip, late: late}
	r2 := r.WithContext(withState(r.Context(), st))
	st.request = r2
	ex = &Exchange{p: p, r: r2, w: w, st: st, started: started, ua: r.UserAgent()}
	if p.perf != nil {
		p.perf.started()
		ex.inFlight.Store(true)
	}
	return ex
}

// landed ends the request's time in flight, once.
func (e *Exchange) landed() {
	if e.inFlight.CompareAndSwap(true, false) {
		e.p.perf.ended()
	}
}

type earlyAnswer struct {
	status  int
	header  http.Header
	body    []byte
	crawler bool // a crawler the firewall turned away is still a crawler
	// custom is FirewallOptions.OnBlock, answering instead.
	custom func(http.ResponseWriter, *http.Request)
}

func writeAnswer(w http.ResponseWriter, a *earlyAnswer) {
	defer func() { recover() }()
	h := w.Header()
	for k, v := range a.header {
		h[k] = v
	}
	if a.status == http.StatusNoContent || len(a.body) == 0 {
		h.Del("Content-Length")
	} else {
		h.Set("Content-Length", strconv.Itoa(len(a.body)))
	}
	w.WriteHeader(a.status)
	if len(a.body) > 0 {
		w.Write(a.body)
	}
}

// before decides on a request before the handler; a failure of ours lets it through.
// late: a static-looking request let through, counted after the response
// if the router sent it to a page (Exchange.countStatic).
func (p *Platform) before(r *http.Request) (answer *earlyAnswer, ip, remember string, late *lateHit) {
	defer func() {
		if rec := recover(); rec != nil {
			p.core.log("core", "request check failed, request passed: %v", rec)
			answer, remember, late = nil, "", nil
		}
	}()
	ip = p.ClientIP(r)
	f := p.firewall
	checked := f != nil && (f.skip == nil || !f.skip(r))
	in := CheckInput{IP: ip, Method: r.Method, Target: requestTarget(r), UserAgent: r.UserAgent(),
		Accept: r.Header.Get("Accept"), Cookie: cookieHeader(r.Header)}
	// The tracker's own addresses, answered before the site: a visitor's
	// beacon is our traffic, not a page of the site. A denied or banned
	// address is turned away first, so it can't use us to reach the collector.
	if p.proxy != nil {
		if kind, rest := p.proxy.match(r.URL.Path); kind != "" {
			if checked {
				if d := f.checkAddress(in); d.Action == "block" {
					return p.blockedAnswer(r, d, ip), ip, "", nil
				}
			}
			a := p.proxy.handle(kind, rest, r, ip)
			return &earlyAnswer{status: a.status, header: a.header, body: a.body}, ip, "", nil
		}
	}
	if checked {
		d := f.Check(in)
		if d.Action == "block" {
			return p.blockedAnswer(r, d, ip), ip, "", nil
		}
		late = d.late
	}
	if p.maint != nil {
		decision := p.maint.decide(r, ip)
		if decision.closed {
			h := http.Header{}
			h.Set("Content-Type", "text/html; charset=utf-8")
			h.Set("Retry-After", "600")
			h.Set("Cache-Control", "no-store")
			return &earlyAnswer{status: http.StatusServiceUnavailable, header: h, body: maintenancePage(p.maint.message())}, ip, "", nil
		}
		remember = decision.setCookie
	}
	return nil, ip, remember, late
}

// blockedAnswer: the check page for rule "challenge", else 403 (429 with
// Retry-After for the rate limit and a page limit), or nothing when OnBlock answered itself.
func (p *Platform) blockedAnswer(r *http.Request, d Decision, ip string) *earlyAnswer {
	f := p.firewall
	if d.Rule == "challenge" {
		status, h, body := challengeResponse(f.passKey, ip, r.Method, time.Now())
		return &earlyAnswer{status: status, header: h, body: body, crawler: true}
	}
	if f.onBlock != nil {
		onBlock := f.onBlock
		return &earlyAnswer{status: d.Status, crawler: true, custom: func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					p.core.log("firewall", "OnBlock failed: %v", rec)
				}
			}()
			onBlock(w, r, d)
		}}
	}
	h := http.Header{}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if d.Status == http.StatusTooManyRequests {
		// A page limit waits out its own window, not the site-wide one.
		retry := f.retryAfter()
		if d.RetryAfter > 0 {
			retry = strconv.FormatInt(d.RetryAfter, 10)
		}
		h.Set("Retry-After", retry)
		body := "Too Many Requests"
		if strings.HasPrefix(d.Rule, "limit:") {
			body = limitBody
		}
		return &earlyAnswer{status: d.Status, header: h, body: []byte(body), crawler: true}
	}
	return &earlyAnswer{status: http.StatusForbidden, header: h, body: []byte("Forbidden"), crawler: true}
}

// requestTarget is the request target as the visitor sent it, query string
// and all, which is what the request rules match (sdk/protocols/firewall.md):
// RequestURI, not the decoded URL.Path, so the rules' one decoding pass is
// the only one.
func requestTarget(r *http.Request) string {
	target := r.RequestURI
	if target == "" || target == "*" {
		if r.URL == nil {
			return "/"
		}
		target = r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		return target
	}
	// An absolute-form target (a request through a forward proxy): the path on.
	if !strings.HasPrefix(target, "/") {
		if i := strings.Index(target, "://"); i >= 0 {
			rest := target[i+3:]
			if j := strings.IndexByte(rest, '/'); j >= 0 {
				return rest[j:]
			}
			return "/"
		}
	}
	return target
}

// Request is the request to hand on: it carries the route, visit and trail.
func (e *Exchange) Request() *http.Request { return e.r }

// SetRoute names the request's route as the router knows it ("/orders/:id").
func (e *Exchange) SetRoute(route string) {
	if e != nil && route != "" {
		e.st.mu.Lock()
		e.st.route = truncate(route, 200)
		e.st.mu.Unlock()
	}
}

// SecurityHeaders sets the dashboard's security headers on h that h doesn't
// already have. Middleware adds them as the response starts; an adapter that
// can't see that calls this before the handler, whose own Set still wins.
func (e *Exchange) SecurityHeaders(h http.Header) {
	if e == nil || e.nested || e.p.headers == false {
		return
	}
	defer func() { recover() }()
	for _, pair := range e.p.core.securityHeaders() {
		if _, present := h[http.CanonicalHeaderKey(pair[0])]; !present {
			h.Set(pair[0], pair[1])
		}
	}
}

// Recovered sends a panic the handler raised; call it from the deferred
// function that recovered it, then panic on (or answer 500).
// http.ErrAbortHandler isn't an error: it is how a handler (httputil's
// ReverseProxy when the client or upstream goes away) drops an answer, so
// that request is neither sent nor timed.
func (e *Exchange) Recovered(v any) {
	if e == nil || v == nil {
		return
	}
	defer func() { recover() }()
	if errors.Is(asError(v), http.ErrAbortHandler) {
		e.st.mu.Lock()
		e.st.aborted = true
		e.st.mu.Unlock()
		return
	}
	e.st.mu.Lock()
	seen := e.st.panicked
	e.st.panicked = true
	e.st.mu.Unlock()
	if seen || e.p.errors == nil {
		return
	}
	e.p.errors.capture(e.r.Context(), panicError{v}, "error", http.StatusInternalServerError, callers(1), true)
}

// Hijacked says the connection was taken over (a WebSocket): its length
// isn't a response time, so it isn't timed. Middleware sees this itself; an
// adapter whose framework hides the Hijack calls it.
func (e *Exchange) Hijacked() {
	if e != nil && e.st != nil {
		e.st.mu.Lock()
		e.st.hijacked = true
		e.st.mu.Unlock()
		// A WebSocket open for an hour isn't a request in progress.
		e.landed()
	}
}

func asError(v any) error {
	if err, ok := v.(error); ok {
		return err
	}
	return nil
}

// Error sends an error the request ended with, at the status it was
// answered with (the framework's own errors: gin's c.Errors, an echo
// handler's returned error). Only when the status is one to capture (5xx by
// default).
func (e *Exchange) Error(err error, status int) {
	if e == nil || err == nil || e.p.errors == nil || !e.capturable(status) || e.clientLeft() {
		return
	}
	defer func() { recover() }()
	e.p.errors.capture(e.r.Context(), err, "error", status, nil, false)
}

// clientLeft: the visitor went away before the answer, so a 5xx (or a
// context.Canceled error) is that, not the app failing.
func (e *Exchange) clientLeft() bool {
	return e.r.Context().Err() != nil
}

func (e *Exchange) capturable(status int) bool {
	if fn := e.p.errors.shouldCapture; fn != nil {
		return safeShould(fn, e.r, status)
	}
	return status >= 500
}

func safeShould(fn func(*http.Request, int) bool, r *http.Request, status int) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return fn(r, status)
}

// Finish ends the request: it is timed, counted when a crawler asked, and
// sent as an error when it answered 5xx and nothing was captured for it.
// status is the status sent, size the body's bytes.
func (e *Exchange) Finish(status int, size int64) { e.finish(status, size, nil) }

func (e *Exchange) finish(status int, size int64, rw *responseWriter) {
	if e == nil || e.nested || e.done {
		return
	}
	e.done = true
	e.landed()
	defer func() {
		if r := recover(); r != nil {
			e.p.core.log("core", "could not finish a request: %v", r)
		}
	}()
	e.countStatic(status)
	e.st.mu.Lock()
	aborted, hijacked := e.st.aborted, e.st.hijacked
	e.st.mu.Unlock()
	if aborted {
		e.p.endQueries(e.st, "", "", status)
		return
	}
	elapsed := time.Since(e.started)
	method, route := "", ""
	if !hijacked && (rw == nil || !rw.hijacked) {
		method, route = e.p.timeRequest(e.st.method, e.st.routeName(), status, elapsed, e.st.path)
	}
	// Its queries, under the method and route the request was counted under.
	e.p.endQueries(e.st, method, route, status)
	e.p.RecordCrawler(e.ua, e.st.path, status, elapsed, size, e.st.ip)
	if e.p.errors == nil || !e.capturable(status) || e.clientLeft() {
		return
	}
	e.st.mu.Lock()
	panicked := e.st.panicked
	e.st.mu.Unlock()
	if panicked || e.p.errors.answered(e.st, status) {
		return
	}
	// Nothing was captured for this request: its answer is the error. The
	// stack is where the handler wrote the status (http.Error's caller), and
	// a plain-text body (what http.Error writes) is its message.
	text, pcs := "", []uintptr(nil)
	if rw != nil {
		text, pcs = rw.errorText(), rw.pcs
	}
	err := &statusError{status: status, text: text, method: e.st.method, route: firstNonEmpty(e.st.routeName(), normalizeRoute(e.st.path))}
	e.p.errors.captureStatus(e.r.Context(), err, pcs)
}

// countStatic: a static-looking request the firewall only compared with
// the counts (firewall.md, `rate`) counts toward the rate and the page
// limits after all when it answered 400 or more, or the router sent it to a
// route that isn't a file's: ServeMux's pattern (r.Pattern, Go 1.23+, which
// ServeMux sets on the request this package handed it; before 1.23 the
// wrapped ServeMux is asked), or the one an adapter or SetRoute gave (gin's
// FullPath, chi's RoutePattern, echo's Path). A file server's answer (its
// Content-Type is a file's) is left alone. A shared counter is called off
// the request (at most lateSlotsMax at once; past them, on it), so the
// answer doesn't wait on it.
func (e *Exchange) countStatic(status int) {
	late := e.st.late
	f := e.p.firewall
	if late == nil || f == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			e.p.core.log("firewall", "could not count a static file: %v", r)
		}
	}()
	contentType := ""
	if e.w != nil {
		contentType = e.w.Header().Get("Content-Type")
	}
	routed := routedToPage(e.st.routePattern(), contentType)
	// A file the visitor's page asked for, most of them: nothing to count.
	if !countsLate(status, routed) {
		return
	}
	if f.counter == nil {
		f.countStatic(late, status, routed)
		return
	}
	select {
	case f.lateSlots <- struct{}{}:
		go func() {
			defer func() {
				recover()
				<-f.lateSlots
			}()
			f.countStatic(late, status, routed)
		}()
	default:
		// As many counting already as there may be: this one waits on the
		// counter here, as a page's request does, rather than pile up.
		f.countStatic(late, status, routed)
	}
}

type statusError struct {
	status int
	text   string
	method string
	route  string
}

func (s *statusError) Error() string {
	if s.text != "" {
		return s.text
	}
	return s.method + " " + s.route + " answered " + strconv.Itoa(s.status) + " " + http.StatusText(s.status)
}

// statusNames are net/http's names for the 5xx statuses: the error type of
// an answer that is the error.
var statusNames = map[int]string{
	500: "StatusInternalServerError", 501: "StatusNotImplemented", 502: "StatusBadGateway",
	503: "StatusServiceUnavailable", 504: "StatusGatewayTimeout", 505: "StatusHTTPVersionNotSupported",
	506: "StatusVariantAlsoNegotiates", 507: "StatusInsufficientStorage", 508: "StatusLoopDetected",
	510: "StatusNotExtended", 511: "StatusNetworkAuthenticationRequired",
}

func (s *statusError) typeName() string {
	if name, ok := statusNames[s.status]; ok {
		return "http." + name
	}
	return "http.Status" + strconv.Itoa(s.status)
}

// ---- The response, as the handler writes it ----

const maxErrorText = 200

type responseWriter struct {
	http.ResponseWriter
	ex          *Exchange
	status      int
	wroteHeader bool
	size        int64
	hijacked    bool
	pcs         []uintptr // where a 5xx was written
	text        []byte    // the start of a 5xx's plain-text body
	sniff       bool
}

func (w *responseWriter) code() int {
	if w.hijacked {
		return http.StatusSwitchingProtocols
	}
	if !w.wroteHeader {
		return http.StatusOK
	}
	return w.status
}

func (w *responseWriter) WriteHeader(code int) {
	if w.wroteHeader || w.hijacked {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	// 1xx informational answers (103 Early Hints) come before the real one.
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.wroteHeader = true
	w.status = code
	w.addHeaders()
	if code >= 500 && w.ex.p.errors != nil {
		w.pcs = callers(1)
		w.sniff = strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain")
	}
	w.ResponseWriter.WriteHeader(code)
}

// addHeaders: the dashboard's security headers the response doesn't set itself.
func (w *responseWriter) addHeaders() {
	if !w.ex.p.headers {
		return
	}
	defer func() { recover() }()
	h := w.Header()
	for _, pair := range w.ex.p.core.securityHeaders() {
		if _, present := h[http.CanonicalHeaderKey(pair[0])]; !present {
			h.Set(pair[0], pair[1])
		}
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader && !w.hijacked {
		w.WriteHeader(http.StatusOK)
	}
	if w.sniff && len(w.text) < maxErrorText {
		room := maxErrorText - len(w.text)
		if room > len(b) {
			room = len(b)
		}
		w.text = append(w.text, b[:room]...)
	}
	n, err := w.ResponseWriter.Write(b)
	w.size += int64(n)
	return n, err
}

func (w *responseWriter) errorText() string {
	text := strings.TrimSpace(string(w.text))
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	return strings.ToValidUTF8(text, "")
}

type writerOnly struct{ io.Writer }

// ReadFrom keeps io.Copy's fast path (sendfile) for http.ServeContent.
func (w *responseWriter) ReadFrom(src io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok && !w.sniff {
		n, err := rf.ReadFrom(src)
		w.size += n
		return n, err
	}
	return io.Copy(writerOnly{w}, src)
}

func (w *responseWriter) Flush() { w.FlushError() }

// FlushError is Flush with its error, as http.ResponseController asks for
// it; the server's writer is reached however many wrappers it is under.
func (w *responseWriter) FlushError() error {
	if !w.wroteHeader && !w.hijacked {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.hijacked = true
		w.ex.landed()
	}
	return conn, rw, err
}

// CloseNotify is for frameworks that still ask (gin's c.Stream): the
// server's own when it has one, else a channel that fires when the request
// ends, which is when the visitor has gone or the answer is done.
func (w *responseWriter) CloseNotify() <-chan bool {
	//lint:ignore SA1019 frameworks call it, so it is passed on
	if cn, ok := w.ResponseWriter.(http.CloseNotifier); ok { //nolint:staticcheck
		return cn.CloseNotify()
	}
	ch := make(chan bool, 1)
	ctx := w.ex.r.Context()
	go func() {
		<-ctx.Done()
		ch <- true
	}()
	return ch
}

func (w *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Unwrap lets http.ResponseController reach the server's own writer.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

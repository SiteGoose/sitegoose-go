// Package sitegoose is one package for a site's Go server, run from the
// analytics dashboard: a firewall, error monitoring and server analytics.
// Each module is separate, one failing never stops the others, and the
// firewall never waits on the network. A loaded module can be switched off in
// the dashboard (Security -> Server package) without a deploy.
//
//	p := sitegoose.New(sitegoose.Options{
//		SiteID:   "YOUR_SITE_ID",
//		Secret:   os.Getenv("ANALYTICS_SITE_SECRET"),
//		Endpoint: "https://YOUR_COLLECTOR_URL",
//	})
//	defer p.Close(context.Background())
//	http.ListenAndServe(":8080", p.Middleware(mux)) // outermost
//
// Standard library only; Go 1.21 or later (1.23 for r.Pattern and crash capture).
package sitegoose

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// The modules, as the dashboard names them. Every one is on unless listed in
// Options.Disable.
const (
	ModuleProxy       = "proxy"
	ModuleFirewall    = "firewall"
	ModuleErrors      = "errors"
	ModuleAnalytics   = "analytics"
	ModulePerformance = "performance"
	ModuleCrawlers    = "crawlers"
	ModuleForms       = "forms"
	ModuleHeaders     = "headers"
	ModuleAudit       = "audit"
	ModuleFlags       = "flags"
	ModuleMaintenance = "maintenance"
	ModuleInventory   = "inventory"
	ModulePosture     = "posture"
	ModuleResources   = "resources"
)

var allModules = []string{ModuleProxy, ModuleFirewall, ModuleErrors, ModuleAnalytics, ModulePerformance, ModuleCrawlers,
	ModuleForms, ModuleHeaders, ModuleAudit, ModuleFlags, ModuleMaintenance, ModuleInventory, ModulePosture, ModuleResources}

// Options configure the platform. SiteID, Secret and Endpoint are required;
// without them nothing is sent and every request passes. Each of SiteID,
// Secret, Endpoint, TrustProxy and ServerName left empty is read from the
// environment: ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET, ANALYTICS_ENDPOINT,
// ANALYTICS_TRUST_PROXY and ANALYTICS_SERVER_NAME.
type Options struct {
	// SiteID is the site's ID (site settings).
	SiteID string
	// Secret is the site secret (site settings). Keep it on the server.
	Secret string
	// Endpoint is the collector's URL.
	Endpoint string
	// TrustProxy says how to find the visitor's address: "" the connection's
	// own; "1" for one proxy or load balancer in front (X-Forwarded-For), "2"
	// for Cloudflare in front of a load balancer; "cloudflare" when every
	// request comes through Cloudflare (CF-Connecting-IP, believed only from
	// Cloudflare's own addresses).
	TrustProxy string
	// ClientIP finds the visitor's address your own way (TrustProxy is then unused).
	ClientIP func(r *http.Request) string
	// ServerName names this service (api, worker...) on its errors,
	// timings, crawlers, resources, packages and set-up. Default: the host name.
	ServerName string
	// Debug logs send problems.
	Debug bool
	// Disable lists modules to leave out: ModuleProxy, ModuleMaintenance...
	Disable []string

	Firewall    FirewallOptions
	Errors      ErrorsOptions
	Performance PerformanceOptions
	Crawlers    CrawlersOptions
	Maintenance MaintenanceOptions
	Inventory   InventoryOptions
	Posture     PostureOptions
	Resources   ResourcesOptions
	Proxy       ProxyOptions
}

// Platform is the package in one value; make it once with New.
type Platform struct {
	core      *core
	modules   []string
	trust     string
	clientFn  func(*http.Request) string
	firewall  *Firewall
	errors    *errorsModule
	analytics *analytics
	perf      *performance
	queries   *queries
	calls     *queries
	queueRead *queueWatch
	crawlers  *crawlers
	audit     *audit
	maint     *maintenance
	inventory *inventory
	posture   *posture
	resources *resources
	proxy     *Proxy
	forms     bool
	headers   bool
	flags     bool
	closeOnce sync.Once
}

// New makes the platform and starts its background work. It never fails: a
// module that can't start is left off, and without credentials every request
// passes and nothing is sent.
func New(o Options) *Platform {
	o.SiteID = firstNonEmpty(o.SiteID, os.Getenv("ANALYTICS_SITE_ID"))
	o.Secret = firstNonEmpty(o.Secret, os.Getenv("ANALYTICS_SITE_SECRET"))
	o.Endpoint = firstNonEmpty(o.Endpoint, os.Getenv("ANALYTICS_ENDPOINT"))
	o.TrustProxy = firstNonEmpty(o.TrustProxy, os.Getenv("ANALYTICS_TRUST_PROXY"))
	o.ServerName = firstNonEmpty(o.ServerName, os.Getenv("ANALYTICS_SERVER_NAME"))
	c := newCore(o.SiteID, o.Secret, o.Endpoint, o.Debug, o.ServerName)
	if !c.valid {
		fmt.Fprintln(os.Stderr, "[analytics-platform] SiteID, Secret and Endpoint are required; nothing is sent and every request passes")
	}
	p := &Platform{core: c, trust: o.TrustProxy, clientFn: o.ClientIP}
	off := map[string]bool{}
	for _, name := range o.Disable {
		name = strings.ToLower(strings.TrimSpace(name))
		known := false
		for _, m := range allModules {
			known = known || m == name
		}
		if !known {
			fmt.Fprintf(os.Stderr, "[analytics-platform] Disable: there is no module %q\n", name)
		}
		off[name] = true
	}
	// ServerName names this service for every module that sends one; a
	// module's own wins.
	o.Errors.ServerName = firstNonEmpty(o.Errors.ServerName, o.ServerName)
	o.Performance.ServerName = firstNonEmpty(o.Performance.ServerName, o.ServerName)
	o.Crawlers.ServerName = firstNonEmpty(o.Crawlers.ServerName, o.ServerName)
	o.Resources.ServerName = firstNonEmpty(o.Resources.ServerName, o.ServerName)
	// Inventory and posture call it host, and are stored one per site and
	// host: without it two services on one machine overwrite each other's.
	o.Inventory.Host = firstNonEmpty(o.Inventory.Host, o.ServerName)
	o.Posture.Host = firstNonEmpty(o.Posture.Host, o.ServerName)
	for _, name := range allModules {
		if off[name] {
			continue
		}
		if err := p.load(name, o); err != nil {
			fmt.Fprintf(os.Stderr, "[analytics-platform] the %s module could not start and is off: %v\n", name, err)
			continue
		}
		p.modules = append(p.modules, name)
	}
	c.start(p.modules)
	defaultPlatform.Store(p)
	return p
}

func (p *Platform) load(name string, o Options) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	c := p.core
	switch name {
	case ModuleProxy:
		p.proxy = newProxy(c, o.Proxy)
	case ModuleFirewall:
		p.firewall = newFirewall(c, o.Firewall, o.TrustProxy, o.ClientIP)
	case ModuleErrors:
		p.errors = newErrors(c, o.Errors)
	case ModuleAnalytics:
		p.analytics = newAnalytics(c)
	case ModulePerformance:
		p.perf = newPerformance(c, o.Performance)
		if !o.Performance.DisableQueries {
			p.queries = newTimings(c, p.perf, queriesKind)
		}
		if !o.Performance.DisableCalls {
			p.calls = newTimings(c, p.perf, callsKind)
		}
		if !o.Performance.DisableQueues {
			p.queueRead = newQueueWatch(c, p.perf)
		}
	case ModuleCrawlers:
		p.crawlers = newCrawlers(c, o.Crawlers)
	case ModuleForms:
		p.forms = true
	case ModuleHeaders:
		p.headers = true
	case ModuleAudit:
		p.audit = newAudit(c)
	case ModuleFlags:
		p.flags = true
	case ModuleMaintenance:
		p.maint = &maintenance{core: c, skip: o.Maintenance.Skip}
	case ModuleInventory:
		p.inventory = newInventory(c, o.Inventory)
	case ModulePosture:
		p.posture = newPosture(c, o.Posture)
	case ModuleResources:
		p.resources = newResourcesFor(c, o.Resources, p.perf)
	}
	return nil
}

// Modules are the modules that are on.
func (p *Platform) Modules() []string { return append([]string(nil), p.modules...) }

// Firewall is the firewall module (nil when off), for checks outside the middleware.
func (p *Platform) Firewall() *Firewall { return p.firewall }

// Proxy is the first-party proxy (nil when off): Proxy().ScriptURL("") and
// Proxy().CollectURL() are the two addresses the page's script tag needs, on
// this site's own domain, so ad blockers have nothing of ours to recognise.
func (p *Platform) Proxy() *Proxy { return p.proxy }

// ClientIP is the visitor's address for r, as TrustProxy (or ClientIP) says.
func (p *Platform) ClientIP(r *http.Request) string {
	if p.firewall != nil {
		return p.firewall.ClientIP(r)
	}
	if p.clientFn != nil {
		if ip := p.clientFn(r); ip != "" {
			return ip
		}
	}
	return clientIPOf(remoteHost(r.RemoteAddr), r.Header, p.trust)
}

// ---- Errors ----

// CaptureError sends an error you handled. The request (or job) ctx belongs
// to gives it its route, visit and trail; its stack is where you call this.
func (p *Platform) CaptureError(ctx context.Context, err error) {
	if p != nil && p.errors != nil {
		p.errors.capture(ctx, err, "handled", 0, callers(1), false)
	}
}

// CaptureErrorWith is CaptureError with the status the error ended in, or its kind.
func (p *Platform) CaptureErrorWith(ctx context.Context, err error, o CaptureOptions) {
	if p != nil && p.errors != nil {
		p.errors.capture(ctx, err, o.Kind, o.Status, callers(1), false)
	}
}

// Recover, deferred at the top of a goroutine, sends that goroutine's panic
// (waiting up to two seconds for it to go, else keeping it in the file for
// the next start) and panics on, so the program ends as it would have:
//
//	go func() {
//		defer p.Recover(ctx)
//		work()
//	}()
func (p *Platform) Recover(ctx context.Context) {
	v := recover()
	if v == nil {
		return
	}
	if p != nil && p.errors != nil {
		p.errors.capture(ctx, panicError{v}, "error", 0, callers(0), true)
		wait, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		p.errors.keep(wait)
		cancel()
		// Sent already: noted, so the crash file the runtime writes if this
		// panic ends the process isn't sent again at the next start. Crash
		// capture stays on: something above may recover it and carry on.
		p.errors.markSent(fmt.Sprint(panicMessage(v)))
	}
	panic(v)
}

// panicMessage is what the runtime prints after "panic: " for v.
func panicMessage(v any) any {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	if s, ok := v.(fmt.Stringer); ok {
		return s.String()
	}
	return v
}

// Job runs a background job (a queue consumer, a cron task): its errors are
// sent with "/(job) <name>" as their route, each run is timed (Health ->
// Server speed -> Jobs), and a run that returns an error or panics counts as
// failed and is sent (status 500). The error is returned and a panic panics
// on. A run cancelled through its context isn't a failure, and isn't timed.
func (p *Platform) Job(ctx context.Context, name string, fn func(ctx context.Context) error) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	route := "/(job) " + truncate(firstNonEmpty(name, "job"), 180)
	st := &reqState{platform: p, method: "JOB", path: route, route: route, job: true}
	jctx := withState(ctx, st)
	started := time.Now()
	// Its queries go under the name Server speed counted the run under.
	var qMethod, qRoute string
	defer func() { p.endQueries(st, qMethod, qRoute, 200) }()
	defer func() {
		if v := recover(); v != nil {
			if p.errors != nil {
				p.errors.capture(jctx, panicError{v}, "error", 500, callers(0), true)
			}
			qMethod, qRoute = p.timeRequest("JOB", route, 500, time.Since(started), route)
			panic(v)
		}
	}()
	err = fn(jctx)
	if err != nil && errors.Is(err, context.Canceled) {
		return err
	}
	status := 200
	if err != nil {
		status = 500
		if p.errors != nil {
			p.errors.capture(jctx, err, "error", 500, nil, false)
		}
	}
	qMethod, qRoute = p.timeRequest("JOB", route, status, time.Since(started), route)
	return err
}

// ---- Firewall ----

// LoginFailed counts a failed login from r's address (bot protection): past
// the site's limit the address is banned here straight away and on your
// other servers within a minute or two.
func (p *Platform) LoginFailed(r *http.Request) {
	if p.firewall != nil {
		p.firewall.LoginFailed(p.ClientIP(r))
	}
}

// LoginFailedIP is LoginFailed for an address you already have.
func (p *Platform) LoginFailedIP(ip string) {
	if p.firewall != nil && ip != "" {
		p.firewall.LoginFailed(ip)
	}
}

// ---- Flags, audit, forms ----

// IsEnabled is a feature flag from the dashboard: false until the flag is
// known, or with the module off. user is for rollouts and user lists.
func (p *Platform) IsEnabled(key, user string) bool { return p.IsEnabledOr(key, user, false) }

// IsEnabledOr is IsEnabled with the answer to give until the flag is known.
func (p *Platform) IsEnabledOr(key, user string, fallback bool) bool {
	if !p.flags || !p.core.isOn(ModuleFlags) {
		return fallback
	}
	p.core.mu.RLock()
	rule, ok := p.core.flags[key]
	p.core.mu.RUnlock()
	if !ok {
		return fallback
	}
	return rule.evaluate(key, user)
}

// Audit records who did what (Security -> Audit log). action is e.g.
// "user.role_changed"; the request ctx belongs to adds the actor's address
// and visit.
func (p *Platform) Audit(ctx context.Context, action string, e AuditEntry) {
	if p.audit == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.core.log("audit", "could not record: %v", r)
		}
	}()
	ip, session := "", ""
	if st := stateFrom(ctx); st != nil {
		ip, session = st.ip, st.session
	}
	p.audit.record(action, e, ip, session)
}

// CheckForm checks a form before you accept it (form protection): the
// request's form unless o.Fields is given. Spam goes to Leads -> Spam. When
// the check can't be made the form is accepted (Checked false).
func (p *Platform) CheckForm(r *http.Request, o FormOptions) (result FormResult) {
	if !p.forms {
		return FormResult{OK: true, Reasons: []string{}}
	}
	defer func() {
		if rec := recover(); rec != nil {
			p.core.log("forms", "could not check a form: %v", rec)
			result = FormResult{OK: true, Reasons: []string{"unchecked"}}
		}
	}()
	fields := o.Fields
	ctx := context.Background()
	ip := ""
	if r != nil {
		ctx = r.Context()
		ip = p.ClientIP(r)
		if fields == nil {
			if err := r.ParseForm(); err == nil {
				fields = r.PostForm
				if len(fields) == 0 {
					fields = r.Form
				}
			}
		}
	}
	return checkForm(ctx, p.core, fields, ip, o)
}

// ProtectForm checks the form of every request through it; spam gets a 422
// (or onSpam's answer) and never reaches next.
func (p *Platform) ProtectForm(o FormOptions, onSpam func(w http.ResponseWriter, r *http.Request, result FormResult)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := p.CheckForm(r, o)
			if !result.Spam {
				next.ServeHTTP(w, r)
				return
			}
			if onSpam != nil {
				onSpam(w, r, result)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte("Your message looks automated, so it wasn't sent. Please try again."))
		})
	}
}

// ---- Server analytics ----

// Track sends an event in the background (fields: value, numeric_value,
// currency, url, event_label, variant, id, timestamp, event_uid; see the
// server events docs). The visit is the request ctx belongs to, unless
// fields has session_id. Returns the event_uid, "" when not queued.
func (p *Platform) Track(ctx context.Context, name string, fields map[string]any) string {
	if p.analytics == nil {
		return ""
	}
	return p.analytics.track(ctx, name, fields)
}

// Identify links the visit (sessionID, else the request ctx belongs to) to
// your user ID; true when stored. Waits for the answer, up to 5 seconds.
func (p *Platform) Identify(ctx context.Context, userID, sessionID string) bool {
	if p.analytics == nil {
		return false
	}
	return p.analytics.identify(ctx, userID, sessionID)
}

// Lead adds or updates a lead (fields: email or phone, and name, status,
// tags, note, deal fields...). Waits for the answer, up to 5 seconds; nil
// when it wasn't stored.
func (p *Platform) Lead(ctx context.Context, fields map[string]any) *LeadResult {
	if p.analytics == nil {
		return nil
	}
	return p.analytics.lead(ctx, fields)
}

// ---- Timings, for integrations of your own ----

// TimeRequest records a finished request for Server speed. route is the
// router's pattern ("" to work it out from path).
func (p *Platform) TimeRequest(method, route string, status int, d time.Duration, path string) {
	p.timeRequest(method, route, status, d, path)
}

// timeRequest is TimeRequest giving the method and route the request was
// counted under, "" when it wasn't.
func (p *Platform) timeRequest(method, route string, status int, d time.Duration, path string) (m, r string) {
	if p.perf == nil {
		return "", ""
	}
	defer func() {
		if rec := recover(); rec != nil {
			p.core.log("performance", "could not time a request: %v", rec)
			m, r = "", ""
		}
	}()
	return p.perf.record(method, route, status, float64(d)/float64(time.Millisecond), path)
}

// RecordCrawler records a finished request when it came from a crawler or
// AI bot (Health -> Crawlers); anything else is left alone.
func (p *Platform) RecordCrawler(userAgent, path string, status int, d time.Duration, size int64, ip string) {
	if p.crawlers == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.core.log("crawlers", "could not count a crawler request: %v", r)
		}
	}()
	p.crawlers.record(DetectCrawler(userAgent), path, status, float64(d)/float64(time.Millisecond), size, ip)
}

// ---- Shutting down ----

// Flush sends everything waiting (serverless: before returning), Server
// speed's current minute included.
func (p *Platform) Flush(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p.flushAll(ctx, false)
	return ctx.Err()
}

func (p *Platform) flushAll(ctx context.Context, closing bool) {
	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { recover() }()
			fn()
		}()
	}
	if p.firewall != nil {
		run(func() {
			if closing {
				p.firewall.close(ctx)
			} else {
				p.firewall.flushNow(ctx)
			}
		})
	}
	if p.errors != nil {
		run(func() {
			if closing {
				p.errors.close(ctx)
			} else {
				p.errors.flush(ctx, true)
			}
		})
	}
	if p.analytics != nil {
		run(func() {
			if closing {
				p.analytics.close(ctx)
			} else {
				p.analytics.flush(ctx)
			}
		})
	}
	if p.perf != nil {
		run(func() {
			if closing {
				p.perf.close(ctx)
			} else {
				p.perf.flush(ctx, true)
			}
		})
	}
	if p.queries != nil {
		run(func() {
			if closing {
				p.queries.close(ctx)
			} else {
				p.queries.flush(ctx, true)
			}
		})
	}
	if p.calls != nil {
		run(func() {
			if closing {
				p.calls.close(ctx)
			} else {
				p.calls.flush(ctx, true)
			}
		})
	}
	if p.queueRead != nil && closing {
		run(func() { p.queueRead.close(ctx) })
	}
	if p.crawlers != nil {
		run(func() {
			if closing {
				p.crawlers.close(ctx)
			} else {
				p.crawlers.flush(ctx, true)
			}
		})
	}
	if p.audit != nil {
		run(func() {
			if closing {
				p.audit.close(ctx)
			} else {
				p.audit.flush(ctx)
			}
		})
	}
	if p.resources != nil && closing {
		run(func() { p.resources.close(ctx) })
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Close stops the background work and sends what's waiting, until ctx ends
// (five seconds when ctx has no deadline). Give it the same deadline as your
// server's Shutdown.
func (p *Platform) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, closeWait)
		defer cancel()
	}
	p.closeOnce.Do(func() {
		p.core.job.halt(ctx)
		p.flushAll(ctx, true)
		p.core.stopJobs(ctx)
	})
	return ctx.Err()
}

// closeWait is how long Close sends for when its context gives no deadline.
const closeWait = 5 * time.Second

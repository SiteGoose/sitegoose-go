package sitegoose

// What every module shares: the site's credentials, sending to the
// collector, logging, background jobs, and the dashboard's module switches
// (Site settings -> Server, GET /events/platform/config about once a minute).
//
// A module the dashboard turns off stays loaded but does nothing; until the
// switches arrive, or when they can't be fetched, every loaded module stays
// on. Sending never panics into the app. Background jobs are goroutines that
// recover from anything a job does, so one failing never stops another.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is the package's version, sent in the User-Agent.
const Version = "0.4.0"

const (
	sendTimeout = 5 * time.Second
	minSync     = 30 * time.Second
	retryWait   = 60 * time.Second
	// SessionHeader carries the tracker's visit ID from the page to your
	// server (window.analyticsSession.getId()).
	SessionHeader = "X-Analytics-Session"
	maxAnswer     = 1 << 20
)

var (
	siteIDPattern     = regexp.MustCompile(`^[a-fA-F0-9]{24}$`)
	headerNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
)

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r *response) ok() bool { return r != nil && r.status >= 200 && r.status < 300 }

func (r *response) json(into any) bool {
	if r == nil || len(r.body) == 0 {
		return false
	}
	return json.Unmarshal(r.body, into) == nil
}

// failed: unreachable, rate limited or the collector's own trouble, which a
// retry may get past; a 4xx won't change by being sent again.
// statusUnencodable is send's answer for a body json can't encode: not
// sent, and not worth sending again.
const statusUnencodable = 0

func failed(r *response) bool { return r == nil || r.status == 429 || r.status >= 500 }

// periodic runs job in a goroutine; job returns the wait until its next run.
type periodic struct {
	job  func() time.Duration
	wake chan struct{}
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func startPeriodic(first time.Duration, job func() time.Duration) *periodic {
	p := &periodic{job: job, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go p.run(first)
	return p
}

func (p *periodic) run(wait time.Duration) {
	defer close(p.done)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-timer.C:
		case <-p.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		select {
		case <-p.stop:
			return
		default:
		}
		wait = p.safely()
		timer.Reset(wait)
	}
}

// safely runs the job once; a job that panics is tried again later, never
// allowed to take the app down.
func (p *periodic) safely() (wait time.Duration) {
	defer func() {
		if recover() != nil {
			wait = retryWait
		}
	}()
	wait = p.job()
	if wait <= 0 {
		wait = retryWait
	}
	return wait
}

// runNow wakes the job early (a queue filled up).
func (p *periodic) runNow() {
	if p == nil {
		return
	}
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// halt stops the job and waits for a run in progress, at most until ctx ends.
func (p *periodic) halt(ctx context.Context) {
	if p == nil {
		return
	}
	p.once.Do(func() { close(p.stop) })
	select {
	case <-p.done:
	case <-ctx.Done():
	}
}

type core struct {
	siteID     string
	secret     string
	endpoint   string
	valid      bool
	debug      bool
	userAgent  string
	serverName string
	started    time.Time
	client     *http.Client
	ownHost    string // the collector's host, as calls.go names hosts

	mu          sync.RWMutex
	switches    map[string]bool
	headers     [][2]string
	flags       map[string]flagRule
	maintenance maintenanceConfig
	version     uint64 // goes up with every new config, so modules can rebuild what they derive from it
	etag        string
	loaded      []string
	job         *periodic

	// Every background job, stopped by Close.
	jobsMu sync.Mutex
	jobs   []*periodic
	closed bool
}

func newCore(siteID, secret, endpoint string, debug bool, serverName string) *core {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	c := &core{
		siteID:     strings.TrimSpace(siteID),
		secret:     secret,
		endpoint:   endpoint,
		debug:      debug,
		userAgent:  "analytics-platform-go/" + Version,
		serverName: truncate(firstNonEmpty(serverName, hostname()), 100),
		started:    time.Now(),
		switches:   map[string]bool{},
		flags:      map[string]flagRule{},
	}
	c.valid = siteIDPattern.MatchString(c.siteID) && c.secret != "" && c.endpoint != ""
	if u, err := url.Parse(endpoint); err == nil {
		c.ownHost = callHost(u)
	}
	// Our own client: an app's instrumented DefaultTransport (or our
	// breadcrumb Transport) never sees, or slows, the package's own calls.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 4
	c.client = &http.Client{Timeout: sendTimeout, Transport: transport}
	return c
}

func (c *core) log(module string, format string, args ...any) {
	if c.debug {
		log.Printf("[analytics-platform:%s] %s", module, fmt.Sprintf(format, args...))
	}
}

// every starts a background job, stopped by Close. Nothing runs when the
// credentials are missing: there is nowhere to send to.
func (c *core) every(first time.Duration, job func() time.Duration) *periodic {
	if !c.valid {
		return nil
	}
	c.jobsMu.Lock()
	defer c.jobsMu.Unlock()
	if c.closed {
		return nil
	}
	p := startPeriodic(first, job)
	c.jobs = append(c.jobs, p)
	return p
}

func (c *core) stopJobs(ctx context.Context) {
	c.jobsMu.Lock()
	jobs := c.jobs
	c.jobs = nil
	c.closed = true
	c.jobsMu.Unlock()
	for _, job := range jobs {
		job.halt(ctx)
	}
}

const (
	authBody   = "body"
	authBearer = "bearer"
)

// send posts JSON to the collector (body nil: no body). auth "body" puts
// site_id and sitesecret in the body (the event endpoints), "bearer" sends the
// secret as a header (firewall, switches, inventory). nil when it couldn't be
// sent; never panics.
func (c *core) send(ctx context.Context, module, path, method string, body map[string]any, auth string, headers map[string]string) (res *response) {
	if !c.valid {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			c.log(module, "could not send to %s: %v", path, r)
			res = nil
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		if auth == authBody {
			copied := make(map[string]any, len(body)+2)
			for k, v := range body {
				copied[k] = v
			}
			copied["site_id"] = c.siteID
			copied["sitesecret"] = c.secret
			body = copied
		}
		data, err := json.Marshal(body)
		if err != nil {
			// Sending again can't help (a NaN, a channel): reported as an
			// answer that isn't a failure, so nothing retries it for ever.
			c.log(module, "could not encode a body for %s, dropped: %v", path, err)
			return &response{status: statusUnencodable}
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, reader)
	if err != nil {
		c.log(module, "bad request to %s: %v", path, err)
		return nil
	}
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth == authBearer {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	answer, err := c.client.Do(req)
	if err != nil {
		c.log(module, "could not reach the collector (%s): %v", path, err)
		return nil
	}
	defer answer.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(answer.Body, maxAnswer))
	if answer.StatusCode >= 300 && answer.StatusCode != http.StatusNotModified {
		c.log(module, "collector answered %d to %s", answer.StatusCode, path)
	}
	return &response{status: answer.StatusCode, header: answer.Header, body: data}
}

// ---- Module switches ----

// isOn is false only when the dashboard turned the module off.
func (c *core) isOn(name string) bool {
	c.mu.RLock()
	on, known := c.switches[name]
	c.mu.RUnlock()
	return !known || on
}

// checkIn is this service's check-in (sdk/protocols/checkin.md), form-encoded
// so any name is plain ASCII: Health -> All systems shows it running and when
// it was last heard from. "" when it can't be built: the switches still sync.
func (c *core) checkIn() (out string) {
	defer func() {
		if recover() != nil {
			out = ""
		}
	}()
	if c.serverName == "" {
		return ""
	}
	fields := url.Values{}
	fields.Set("server", c.serverName)
	fields.Set("kind", "process")
	fields.Set("pid", strconv.Itoa(os.Getpid()))
	fields.Set("up_s", strconv.FormatInt(int64(time.Since(c.started)/time.Second), 10))
	fields.Set("runtime", runtimeName())
	if rss, ok := rssMB(); ok {
		fields.Set("rss_mb", strconv.FormatInt(rss, 10))
	}
	return fields.Encode()
}

type platformConfig struct {
	V           int                        `json:"v"`
	Modules     map[string]any             `json:"modules"`
	Flags       map[string]json.RawMessage `json:"flags"`
	Maintenance json.RawMessage            `json:"maintenance"`
	Headers     []json.RawMessage          `json:"headers"`
	Sync        float64                    `json:"sync"`
}

func (c *core) syncSwitches() time.Duration {
	headers := map[string]string{"X-Platform-Modules": strings.Join(c.loaded, ",")}
	if app := c.checkIn(); app != "" {
		headers["X-Platform-App"] = app
	}
	c.mu.RLock()
	etag := c.etag
	c.mu.RUnlock()
	if etag != "" {
		headers["If-None-Match"] = etag
	}
	res := c.send(context.Background(), "core", "/events/platform/config?site_id="+url.QueryEscape(c.siteID), http.MethodGet, nil, authBearer, headers)
	if res == nil || res.status != http.StatusOK {
		return retryWait
	}
	var data platformConfig
	if !res.json(&data) {
		return retryWait
	}
	if data.V == 1 && data.Modules != nil {
		switches := map[string]bool{}
		for name, value := range data.Modules {
			on, isBool := value.(bool)
			switches[name] = !isBool || on
		}
		flags := map[string]flagRule{}
		for key, raw := range data.Flags {
			if rule, ok := parseFlag(raw); ok {
				flags[key] = rule
			}
		}
		var safe [][2]string
		for _, raw := range data.Headers {
			var pair []any
			if json.Unmarshal(raw, &pair) != nil || len(pair) != 2 {
				continue
			}
			name, ok1 := pair[0].(string)
			value, ok2 := pair[1].(string)
			// Only well-formed headers (no line breaks can get through).
			if !ok1 || !ok2 || !safeHeader(name, value) {
				continue
			}
			safe = append(safe, [2]string{name, value})
		}
		c.mu.Lock()
		c.switches = switches
		c.flags = flags
		c.maintenance = parseMaintenance(data.Maintenance)
		c.headers = safe
		c.etag = res.header.Get("ETag")
		c.version++
		c.mu.Unlock()
	}
	wait := retryWait
	if data.Sync > 0 {
		wait = time.Duration(data.Sync) * time.Second
	}
	if wait < minSync {
		wait = minSync
	}
	return wait
}

// framingHeaders say how the answer is sent or who it is for: never set
// from the dashboard, whatever it sends.
var framingHeaders = map[string]bool{"Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Keep-Alive": true, "Upgrade": true, "Te": true, "Trailer": true, "Proxy-Connection": true, "Set-Cookie": true,
	"Host": true, "Content-Type": true, "Content-Encoding": true, "Location": true, "Date": true, "Status": true}

// safeHeader: a well-formed name that isn't a framing header, and a value
// of visible ASCII, spaces and tabs only (no line breaks, nothing else).
func safeHeader(name, value string) bool {
	if !headerNamePattern.MatchString(name) || framingHeaders[http.CanonicalHeaderKey(name)] || len(value) > 4000 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

// securityHeaders are the headers picked on the dashboard, when the module is on.
func (c *core) securityHeaders() [][2]string {
	if !c.isOn(ModuleHeaders) {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.headers
}

func (c *core) start(names []string) {
	c.loaded = names
	c.job = c.every(0, c.syncSwitches)
}

// ---- Small helpers ----

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// truncate cuts s to at most n characters (runes), never mid-character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// goVersion is the Go release the binary was built with: "1.23.4".
func goVersion() string {
	v := runtime.Version()
	if i := strings.Index(v, "go"); i >= 0 {
		v = v[i+2:]
	}
	if i := strings.IndexAny(v, " -"); i >= 0 {
		v = v[:i]
	}
	return v
}

// runtimeName names the runtime as the dashboard shows it: "Go 1.23.4".
func runtimeName() string { return truncate("Go "+goVersion(), 32) }

// inChunks hands rows to send maxRows at a time, the most the collector
// takes in one request.
func inChunks(rows []map[string]any, send func(part []map[string]any)) {
	for len(rows) > 0 {
		n := len(rows)
		if n > maxRows {
			n = maxRows
		}
		send(rows[:n])
		rows = rows[n:]
	}
}

func isoMinute(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func isoNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }

// remoteHost is the address of r.RemoteAddr without its port.
func remoteHost(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return strings.Trim(remote, "[]")
}

// cookieHeader is every Cookie field of the request as one header: HTTP/2
// may split cookies over several fields (RFC 9113 8.2.3).
func cookieHeader(h http.Header) string {
	return strings.Join(h.Values("Cookie"), "; ")
}

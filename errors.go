package sitegoose

// Error monitoring module: the server's errors go to the collector (POST
// /events/server-errors), where they join the browser's errors in the Errors
// report. The middleware captures a handler's panic and a 5xx answer;
// CaptureError captures errors you handle; SlogHandler sends the errors your
// code logs; Recover captures a goroutine's panic; and with Go 1.23 a panic
// that crashes the process is written to a file and sent on the next start.
// An error is sent once however many of those see it. Errors are sent in
// small batches, a batch the collector couldn't take is tried once more, and
// sending never panics. What still can't be sent waits in a file and is sent
// once it can be, after a restart too; each error carries when it happened,
// and the trail of its request or job.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	errorsBatch    = 10
	errorsQueueMax = 100
	errorsFlush    = 2 * time.Second
	resendEvery    = 60 * time.Second
	spoolBytes     = 1 << 20
	recentMax      = 256
)

// errorsRetryAfter is how long a batch the collector couldn't take waits
// before it is sent once more (a variable so the tests needn't wait).
var errorsRetryAfter = 2 * time.Second

// ErrorEvent is one error as it is sent; BeforeSend can change it.
type ErrorEvent struct {
	Message        string       `json:"message"`
	ErrorType      string       `json:"error_type"`
	Stack          string       `json:"stack"`
	Kind           string       `json:"kind"`
	StatusCode     int          `json:"status_code"`
	Runtime        string       `json:"runtime"`
	RuntimeVersion string       `json:"runtime_version"`
	OS             string       `json:"os"`
	ServerName     string       `json:"server_name"`
	Release        string       `json:"release"`
	At             string       `json:"at"`
	Breadcrumbs    []Breadcrumb `json:"breadcrumbs,omitempty"`
	Method         string       `json:"method,omitempty"`
	Path           string       `json:"path,omitempty"`
	Route          string       `json:"route,omitempty"`
	SessionID      string       `json:"session_id,omitempty"`
}

// ErrorsOptions configure error monitoring.
type ErrorsOptions struct {
	// ServerName names this service; default Options.ServerName, else the host name.
	ServerName string
	// Release is which build this is, for "introduced in" in the Errors
	// report. Default: ANALYTICS_RELEASE, else the commit the binary was
	// built from (vcs.revision in its build info).
	Release string
	// Root is cut from the front of the file paths in stacks. Default: the working directory.
	Root string
	// SpoolDir is where errors that couldn't be sent wait. Default: the temp folder.
	SpoolDir string
	// DisableSpool keeps no file of unsent errors.
	DisableSpool bool
	// DisableCrashCapture leaves the process's own crash output alone. Go
	// 1.23 and later: a panic nothing recovers is otherwise written to a file
	// (runtime/debug.SetCrashOutput) as well as stderr, and sent at the next start.
	DisableCrashCapture bool
	// ShouldCapture decides whether an answer of this status is an error to
	// send. Default: 500 and above.
	ShouldCapture func(r *http.Request, status int) bool
	// BeforeSend changes an event, or drops it by returning nil. err is the
	// error, or the panic's value as an error.
	BeforeSend func(event *ErrorEvent, err error) *ErrorEvent
}

// CaptureOptions say more about an error you capture.
type CaptureOptions struct {
	// Status is the HTTP status the error ended in (502, say); 0 when none.
	Status int
	// Kind: "handled" (the default), "error" or "logged".
	Kind string
}

type queuedError struct {
	event *ErrorEvent
	err   error // the error, when it can be compared: an error is sent once
	state *reqState
}

// recentError: an error the handler, the middleware and the log may each
// see. It is one event only within its request (or, outside a request,
// within a second): a sentinel error (sql.ErrNoRows, a panic's string) is
// the same value on every request, and each of those is an event.
type recentError struct {
	err   error
	state *reqState
	at    time.Time
}

const recentOutside = time.Second

type errorsModule struct {
	core          *core
	serverName    string
	root          string
	release       string
	beforeSend    func(*ErrorEvent, error) *ErrorEvent
	shouldCapture func(*http.Request, int) bool
	spoolFile     string
	crashFile     string

	mu       sync.Mutex
	queue    []*queuedError
	recent   []recentError // comparable errors captured lately: one is sent once
	resendMu sync.Mutex
	last     time.Time
	job      *periodic
}

var releaseChars = regexp.MustCompile(`[^A-Za-z0-9_.+\-]`)

func cleanRelease(s string) string {
	return truncate(releaseChars.ReplaceAllString(strings.TrimSpace(s), ""), 64)
}

// buildRevision is the commit the binary was built from, when go build recorded it.
func buildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	revision, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if revision != "" && dirty {
		revision += "+dirty"
	}
	return revision
}

func newErrors(c *core, o ErrorsOptions) *errorsModule {
	root := o.Root
	if root == "" {
		root, _ = os.Getwd()
	}
	release := o.Release
	if release == "" {
		release = os.Getenv("ANALYTICS_RELEASE")
	}
	if release == "" {
		release = buildRevision()
	}
	e := &errorsModule{
		core:          c,
		serverName:    truncate(firstNonEmpty(o.ServerName, hostname()), 100),
		root:          strings.TrimRight(root, `/\`),
		release:       cleanRelease(release),
		beforeSend:    o.BeforeSend,
		shouldCapture: o.ShouldCapture,
	}
	if !o.DisableSpool && c.valid {
		dir := firstNonEmpty(o.SpoolDir, os.TempDir())
		// Named after the site and its secret, not the site id alone, so the
		// folder's listing tells nobody which site it is.
		sum := sha256.Sum256([]byte(c.siteID + "|" + c.secret))
		name := hex.EncodeToString(sum[:])[:16]
		e.spoolFile = filepath.Join(dir, "analytics-errors-"+name+".jsonl")
		if !o.DisableCrashCapture {
			e.crashFile = filepath.Join(dir, "analytics-crash-"+name)
		}
	}
	e.job = c.every(errorsFlush, func() time.Duration {
		e.flush(context.Background(), true)
		return errorsFlush
	})
	if e.crashFile != "" {
		e.watchCrashes()
	}
	return e
}

func (e *errorsModule) relative(file string) string {
	if e.root == "" {
		return file
	}
	return strings.TrimPrefix(file, e.root+"/")
}

func isComparable(err error) bool {
	if err == nil {
		return false
	}
	return reflect.TypeOf(err).Comparable()
}

func sameError(a, b error) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}

// panicError is a panic's value as an error.
type panicError struct{ value any }

func (p panicError) Error() string { return fmt.Sprint(p.value) }

func (e *errorsModule) newEvent(err error, kind string, status int, st *reqState, stack string) *ErrorEvent {
	message := ""
	if err != nil {
		message = err.Error()
	}
	typ := "error"
	if p, ok := err.(panicError); ok {
		if inner, isErr := p.value.(error); isErr {
			typ = errorType(inner)
			message = inner.Error()
		} else {
			typ = "panic"
		}
	} else if s, ok := err.(*statusError); ok {
		typ = s.typeName()
	} else if err != nil {
		typ = errorType(err)
	}
	if message == "" {
		message = firstNonEmpty(typ, "Unknown error")
	}
	event := &ErrorEvent{
		Message:        message,
		ErrorType:      typ,
		Stack:          stack,
		Kind:           kind,
		StatusCode:     status,
		Runtime:        "Go",
		RuntimeVersion: goVersion(),
		OS:             runtime.GOOS,
		ServerName:     e.serverName,
		Release:        e.release,
		// When it happened: a crash sent after a restart keeps its own time.
		At: isoNow(),
	}
	e.fillRequest(event, st)
	return event
}

func (e *errorsModule) fillRequest(event *ErrorEvent, st *reqState) {
	if st == nil {
		return
	}
	event.Breadcrumbs = st.breadcrumbs()
	if event.Method == "" {
		event.Method = st.method
	}
	if event.Path == "" {
		event.Path = st.path
	}
	if event.SessionID == "" {
		event.SessionID = st.session
	}
	if event.Route == "" {
		event.Route = st.routeName()
	}
	if i := strings.IndexByte(event.Path, '?'); i >= 0 {
		event.Path = event.Path[:i]
	}
	// Named as Server speed names the request, so the two match.
	if event.Route == "" && event.Path != "" {
		event.Route = normalizeRoute(event.Path)
	}
}

// capture queues one error; never panics.
func (e *errorsModule) capture(ctx context.Context, err error, kind string, status int, pcs []uintptr, afterPanic bool) {
	if e == nil || err == nil || !e.core.isOn(ModuleErrors) {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			e.core.log("errors", "could not capture an error: %v", r)
		}
	}()
	st := stateFrom(ctx)
	if kind == "" {
		kind = "handled"
	}
	if st != nil && kind != "logged" {
		st.mu.Lock()
		st.errored = true
		st.mu.Unlock()
	}
	key := err
	if p, ok := err.(panicError); ok {
		if inner, isErr := p.value.(error); isErr {
			key = inner
		}
	}
	tracked := isComparable(key)
	// The handler, the middleware and the log can all see one error: sent
	// once, and a later capture fills in the event while it waits.
	if tracked && e.upgrade(key, kind, status, st) {
		return
	}
	if len(pcs) == 0 {
		if carried := carriedStack(key); len(carried) > 0 {
			pcs, afterPanic = carried, false
		}
	}
	event := e.newEvent(err, kind, status, st, formatStack(pcs, e.root, afterPanic))
	if e.beforeSend != nil {
		if event = e.beforeSend(event, key); event == nil {
			return
		}
	}
	q := &queuedError{event: event, state: st}
	if tracked {
		q.err = key
	}
	e.mu.Lock()
	if len(e.queue) >= errorsQueueMax {
		e.mu.Unlock()
		e.core.log("errors", "queue full, error dropped")
		return
	}
	e.queue = append(e.queue, q)
	full := len(e.queue) >= errorsBatch
	if tracked {
		e.recent = append(e.recent, recentError{key, st, time.Now()})
		if len(e.recent) > recentMax {
			e.recent = e.recent[len(e.recent)-recentMax:]
		}
	}
	e.mu.Unlock()
	if st != nil {
		st.mu.Lock()
		st.captured = append(st.captured, q)
		st.mu.Unlock()
	}
	if full {
		e.job.runNow()
	}
}

// captureStatus sends a 5xx answer nothing was captured for.
func (e *errorsModule) captureStatus(ctx context.Context, err *statusError, pcs []uintptr) {
	e.capture(ctx, err, "error", err.status, pcs, false)
}

// upgrade: true when err was captured before. A "logged" capture comes first
// and knows no status; the capture that follows (the handler's, the
// middleware's) knows the status, the kind and the request.
func (e *errorsModule) upgrade(err error, kind string, status int, st *reqState) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := false
	for _, old := range e.recent {
		if old.state != st || (st == nil && time.Since(old.at) > recentOutside) {
			continue
		}
		if sameError(old.err, err) {
			seen = true
			break
		}
	}
	if !seen {
		return false
	}
	if kind == "logged" {
		return true
	}
	for i, q := range e.queue {
		if q.err == nil || q.state != st || !sameError(q.err, err) {
			continue
		}
		event := *q.event
		if event.Kind == "logged" {
			event.Kind = kind
		}
		if event.StatusCode == 0 {
			event.StatusCode = status
		}
		e.fillRequest(&event, st)
		next := &event
		if e.beforeSend != nil {
			next = e.beforeSend(next, err)
		}
		if next == nil {
			e.queue = append(e.queue[:i], e.queue[i+1:]...)
		} else {
			q.event = next
		}
		break
	}
	return true
}

// answered fills in the status of the errors a request captured before it
// answered with it; false when it captured none.
func (e *errorsModule) answered(st *reqState, status int) bool {
	st.mu.Lock()
	captured := append([]*queuedError(nil), st.captured...)
	errored := st.errored
	st.mu.Unlock()
	if len(captured) == 0 {
		return errored
	}
	e.mu.Lock()
	for _, q := range captured {
		if q.event.StatusCode == 0 {
			q.event.StatusCode = status
		}
	}
	e.mu.Unlock()
	return true
}

func (e *errorsModule) post(ctx context.Context, events []*ErrorEvent) *response {
	return e.core.send(ctx, "errors", "/events/server-errors", http.MethodPost, map[string]any{"errors": events}, authBody, nil)
}

// flush sends what's waiting; a batch the collector couldn't take is tried
// once more, then kept in the file.
func (e *errorsModule) flush(ctx context.Context, resend bool) {
	if e == nil {
		return
	}
	// Copied under the lock: a request still finishing fills in the status
	// of its own queued events (answered) while this sends.
	e.mu.Lock()
	waiting := make([]*ErrorEvent, len(e.queue))
	for i, q := range e.queue {
		copied := *q.event
		waiting[i] = &copied
	}
	e.queue = nil
	e.mu.Unlock()
	sent := true
	for i := 0; i < len(waiting); i += errorsBatch {
		end := i + errorsBatch
		if end > len(waiting) {
			end = len(waiting)
		}
		batch := waiting[i:end]
		res := e.post(ctx, batch)
		if failed(res) && ctx.Err() == nil {
			select {
			case <-time.After(errorsRetryAfter):
				res = e.post(ctx, batch)
			case <-ctx.Done():
			}
		}
		if failed(res) {
			sent = false
			e.spool(batch)
		}
	}
	// Not straight after the collector failed this flush: it would only
	// wait out another timeout.
	e.mu.Lock()
	due := time.Since(e.last) >= resendEvery
	e.mu.Unlock()
	if resend && sent && e.spoolFile != "" && due {
		e.resend(ctx)
	}
}

// spool appends events to the file. Credentials are added when sent, never written down.
func (e *errorsModule) spool(events []*ErrorEvent) {
	if e.spoolFile == "" || len(events) == 0 {
		return
	}
	if info, err := os.Stat(e.spoolFile); err == nil && info.Size() > spoolBytes {
		e.core.log("errors", "waiting errors file is full, errors dropped")
		return
	}
	f, err := os.OpenFile(e.spoolFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		e.core.log("errors", "could not keep errors to send later: %v", err)
		return
	}
	defer f.Close()
	var b strings.Builder
	for _, event := range events {
		if line, err := json.Marshal(event); err == nil {
			b.Write(line)
			b.WriteByte('\n')
		}
	}
	if _, err := f.WriteString(b.String()); err != nil {
		e.core.log("errors", "could not keep errors to send later: %v", err)
	}
}

// resend sends what earlier attempts (or an earlier run) couldn't. Taken by
// renaming the file first, so two processes never send the same errors.
func (e *errorsModule) resend(ctx context.Context) {
	e.mu.Lock()
	e.last = time.Now()
	e.mu.Unlock()
	if e.spoolFile == "" || !e.resendMu.TryLock() {
		return
	}
	defer e.resendMu.Unlock()
	// What a process that died while sending had taken goes first.
	taken := orphans(e.spoolFile + ".*.sending")
	mine := e.spoolFile + "." + strconv.Itoa(os.Getpid()) + "." + strconv.FormatInt(time.Now().UnixNano(), 36) + ".sending"
	if os.Rename(e.spoolFile, mine) == nil {
		taken = append(taken, mine)
	}
	for _, file := range taken {
		e.sendFile(ctx, file)
	}
}

// sendFile sends a taken file's errors and removes the file only once
// they are sent or written back to the spool: a process that dies on the
// way leaves the file, for the next start.
func (e *errorsModule) sendFile(ctx context.Context, file string) {
	events := readSpool(file)
	for len(events) > 0 {
		n := errorsBatch
		if n > len(events) {
			n = len(events)
		}
		if failed(e.post(ctx, events[:n])) {
			e.spool(events)
			break
		}
		events = events[n:]
	}
	os.Remove(file)
}

// orphans are the files matching pattern ("<name>.<pid>.<...>.sending")
// whose process is gone.
func orphans(pattern string) []string {
	files, _ := filepath.Glob(pattern)
	var out []string
	for _, file := range files {
		parts := strings.Split(filepath.Base(file), ".")
		if len(parts) < 4 {
			continue
		}
		pid, err := strconv.Atoi(parts[len(parts)-3])
		if err == nil && pid != os.Getpid() && !processAlive(pid) {
			out = append(out, file)
		}
	}
	return out
}

func readSpool(path string) []*ErrorEvent {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var events []*ErrorEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), spoolBytes+1)
	for scanner.Scan() {
		var event ErrorEvent
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Message != "" {
			events = append(events, &event)
		}
	}
	return events
}

// keep writes everything not yet sent to the file: the process is about to
// end (a goroutine's panic on its way up).
func (e *errorsModule) keep(ctx context.Context) {
	e.flush(ctx, false)
}

func (e *errorsModule) close(ctx context.Context) {
	e.job.halt(ctx)
	e.flush(ctx, true)
	e.stopCrashes()
}

// ---- Uncaught panics, from the crash file ----

var (
	crashPanicLine = regexp.MustCompile(`^(panic|fatal error): (.*)$`)
	crashGoroutine = regexp.MustCompile(`^goroutine \d+ \[`)
)

// parseCrash reads what the runtime wrote as the process died: the panic's
// message and the goroutine that panicked.
func parseCrash(text string) (message, kind, stack string, ok bool) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, line := range lines {
		m := crashPanicLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		message = strings.TrimSuffix(strings.TrimSpace(m[2]), " [recovered]")
		// A panic re-raised after recover: the last "panic:" line is the one that killed it.
		for j := i + 1; j < len(lines) && strings.HasPrefix(lines[j], "\tpanic: "); j++ {
			message = strings.TrimSuffix(strings.TrimPrefix(lines[j], "\tpanic: "), " [recovered]")
		}
		kind = "panic"
		if m[1] == "fatal error" {
			kind = "fatal error"
		} else if strings.HasPrefix(message, "runtime error: ") {
			kind = "runtime.Error"
		}
		var b strings.Builder
		started := false
		for _, l := range lines[i+1:] {
			if crashGoroutine.MatchString(l) {
				if started {
					break
				}
				started = true
			}
			if started {
				if l == "" {
					break
				}
				b.WriteString(l)
				b.WriteByte('\n')
			}
		}
		return truncate(message, 500), kind, truncate(b.String(), maxStack), message != ""
	}
	return "", "", "", false
}

// sentMarker is the file Recover writes next to a crash file: the panic it
// has already sent, so the crash the runtime writes when that panic then
// ends the process isn't sent a second time.
func sentMarker(crashLog string) string { return strings.TrimSuffix(crashLog, ".log") + ".sent" }

// markSent notes that this process sent a panic with message.
func (e *errorsModule) markSent(message string) {
	if e.crashFile == "" {
		return
	}
	mine := e.crashFile + "-" + strconv.Itoa(os.Getpid()) + ".log"
	os.WriteFile(sentMarker(mine), []byte(truncate(message, 500)), 0o600)
}

// sendCrashes sends the crashes earlier runs left, and tidies their files.
// A file is removed only once its crash is sent or written to the spool.
func (e *errorsModule) sendCrashes() {
	defer func() { recover() }()
	mine := e.crashFile + "-" + strconv.Itoa(os.Getpid()) + ".log"
	files, _ := filepath.Glob(e.crashFile + "-*.log")
	// Taken by a process that died while sending it.
	stale, _ := filepath.Glob(e.crashFile + "-*.log.sending")
	for _, file := range stale {
		if info, err := os.Stat(file); err == nil && time.Since(info.ModTime()) > time.Minute {
			files = append(files, file)
		}
	}
	for _, file := range files {
		if file == mine {
			continue
		}
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		log := strings.TrimSuffix(file, ".sending")
		if info.Size() == 0 {
			// A process that ended without crashing, or is still running.
			pid, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(log, e.crashFile+"-"), ".log"))
			if pid > 0 && !processAlive(pid) {
				os.Remove(file)
				os.Remove(sentMarker(log))
			}
			continue
		}
		taken := file
		if !strings.HasSuffix(file, ".sending") {
			taken = file + ".sending"
			if os.Rename(file, taken) != nil {
				continue
			}
		}
		e.sendCrash(taken, log, info.ModTime())
	}
}

func (e *errorsModule) sendCrash(taken, log string, at time.Time) {
	data, _ := os.ReadFile(taken)
	if len(data) > spoolBytes {
		data = data[:spoolBytes]
	}
	message, kind, stack, ok := parseCrash(string(data))
	if !ok {
		message, kind, stack = "the process crashed", "crash", truncate(string(data), maxStack)
	}
	marker := sentMarker(log)
	if sent, err := os.ReadFile(marker); err == nil && string(sent) == truncate(message, 500) {
		// Recover sent this panic before it ended the process.
		os.Remove(taken)
		os.Remove(marker)
		return
	}
	event := &ErrorEvent{
		Message: message, ErrorType: kind, Stack: stack, Kind: "error", Runtime: "Go", RuntimeVersion: goVersion(),
		OS: runtime.GOOS, ServerName: e.serverName, Release: e.release, At: isoMinuteMS(at),
	}
	if e.beforeSend != nil {
		if event = e.beforeSend(event, errors.New(message)); event == nil {
			os.Remove(taken)
			os.Remove(marker)
			return
		}
	}
	if failed(e.post(context.Background(), []*ErrorEvent{event})) {
		e.spool([]*ErrorEvent{event})
	}
	os.Remove(taken)
	os.Remove(marker)
}

func isoMinuteMS(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

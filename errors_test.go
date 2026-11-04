package sitegoose

// The errors module on its own: sent once, filled in by a later capture,
// retried, kept in the file and resent, crash files. errors_ext_test.go has
// the stacks and the middleware, from outside the package.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func testErrors(t *testing.T, c *collector, o ErrorsOptions) *errorsModule {
	t.Helper()
	if o.SpoolDir == "" {
		o.SpoolDir = t.TempDir()
	}
	o.DisableCrashCapture = true
	e := newErrors(testCore(c), o)
	e.job.halt(context.Background()) // the tests flush themselves
	return e
}

func sentErrors(c *collector) []map[string]any {
	var out []map[string]any
	for _, s := range c.requests("/events/server-errors") {
		for _, e := range s.body["errors"].([]any) {
			out = append(out, e.(map[string]any))
		}
	}
	return out
}

func TestAnErrorIsSentOnceWithTheSiteInTheBody(t *testing.T) {
	c := newCollector(t)
	e := testErrors(t, c, ErrorsOptions{Release: "v1.2 (x)", ServerName: "api-1"})
	err := errors.New("card declined")
	e.capture(context.Background(), err, "handled", 0, callers(0), false)
	e.capture(context.Background(), err, "handled", 0, callers(0), false)
	e.capture(context.Background(), fmt.Errorf("other"), "", 502, nil, false)
	e.flush(context.Background(), false)
	got := c.requests("/events/server-errors")
	if len(got) != 1 || got[0].body["site_id"] != testSite || got[0].body["sitesecret"] != "test-secret" {
		t.Fatalf("%+v", got)
	}
	events := sentErrors(c)
	if len(events) != 2 {
		t.Fatalf("%d events", len(events))
	}
	first := events[0]
	if first["message"] != "card declined" || first["error_type"] != "error" || first["kind"] != "handled" ||
		first["runtime"] != "Go" || first["server_name"] != "api-1" || first["release"] != "v1.2x" || first["os"] == "" {
		t.Fatalf("%v", first)
	}
	if events[1]["status_code"] != float64(502) || events[1]["kind"] != "handled" {
		t.Fatalf("%v", events[1])
	}
}

func TestALoggedErrorIsFilledInByTheNextCapture(t *testing.T) {
	c := newCollector(t)
	e := testErrors(t, c, ErrorsOptions{})
	err := &fs.PathError{Op: "open", Path: "/x", Err: fs.ErrNotExist}
	st := &reqState{method: "POST", path: "/orders/12?x=1", session: "s1"}
	ctx := withState(context.Background(), st)
	e.capture(ctx, err, "logged", 0, nil, false)
	e.capture(ctx, err, "error", 500, nil, false)
	e.capture(ctx, err, "logged", 0, nil, false)
	e.flush(context.Background(), false)
	events := sentErrors(c)
	if len(events) != 1 {
		t.Fatal(len(events))
	}
	ev := events[0]
	if ev["kind"] != "error" || ev["status_code"] != float64(500) || ev["error_type"] != "fs.PathError" ||
		ev["path"] != "/orders/12" || ev["route"] != "/orders/:id" || ev["method"] != "POST" || ev["session_id"] != "s1" {
		t.Fatalf("%v", ev)
	}
}

func TestBeforeSendChangesOrDrops(t *testing.T) {
	c := newCollector(t)
	e := testErrors(t, c, ErrorsOptions{BeforeSend: func(ev *ErrorEvent, err error) *ErrorEvent {
		if strings.Contains(ev.Message, "drop") {
			return nil
		}
		ev.Message = "[redacted]"
		return ev
	}})
	e.capture(context.Background(), errors.New("drop me"), "", 0, nil, false)
	e.capture(context.Background(), errors.New("secret"), "", 0, nil, false)
	e.flush(context.Background(), false)
	if events := sentErrors(c); len(events) != 1 || events[0]["message"] != "[redacted]" {
		t.Fatal(events)
	}
}

func TestTheQueueIsBounded(t *testing.T) {
	e := testErrors(t, nil, ErrorsOptions{DisableSpool: true})
	for i := 0; i < errorsQueueMax+20; i++ {
		e.capture(context.Background(), errors.New("e"+strconv.Itoa(i)), "", 0, nil, false)
	}
	if len(e.queue) != errorsQueueMax {
		t.Fatal(len(e.queue))
	}
}

func TestAFailedBatchIsRetriedThenKeptThenResent(t *testing.T) {
	old := errorsRetryAfter
	errorsRetryAfter = 0
	defer func() { errorsRetryAfter = old }()
	c := newCollector(t)
	c.json("/events/server-errors", 503, map[string]any{"error": "busy"})
	dir := t.TempDir()
	e := testErrors(t, c, ErrorsOptions{SpoolDir: dir})
	e.capture(context.Background(), errors.New("kept"), "", 0, nil, false)
	e.flush(context.Background(), true)
	if n := len(c.requests("/events/server-errors")); n != 2 {
		t.Fatalf("tried %d times", n)
	}
	data, err := os.ReadFile(e.spoolFile)
	if err != nil || !strings.Contains(string(data), `"kept"`) || strings.Contains(string(data), "test-secret") {
		t.Fatalf("%s %v", data, err)
	}
	if !strings.HasPrefix(filepath.Base(e.spoolFile), "analytics-errors-") || strings.Contains(e.spoolFile, testSite) {
		t.Fatal(e.spoolFile)
	}
	// The collector is back: the next flush (a minute on) resends the file.
	c.handle("/events/server-errors", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	e.capture(context.Background(), errors.New("new"), "", 0, nil, false)
	e.last = e.last.Add(-resendEvery)
	e.flush(context.Background(), true)
	got := c.requests("/events/server-errors")
	last := got[len(got)-1].body
	if last["sitesecret"] != "test-secret" || last["errors"].([]any)[0].(map[string]any)["message"] != "kept" {
		t.Fatalf("%v", last)
	}
	if _, err := os.Stat(e.spoolFile); !os.IsNotExist(err) {
		t.Fatal("the file was left")
	}
}

func TestErrorTypes(t *testing.T) {
	var nilMap map[string]int
	_ = nilMap
	for _, c := range []struct {
		err  error
		want string
	}{
		{errors.New("x"), "error"},
		{fmt.Errorf("wrap: %w", errors.New("x")), "error"},
		{fmt.Errorf("wrap: %w", &fs.PathError{Op: "open", Path: "a", Err: fs.ErrNotExist}), "fs.PathError"},
		{context.DeadlineExceeded, "context.deadlineExceededError"},
		{&statusError{status: 502}, "sitegoose.statusError"},
	} {
		if got := errorType(c.err); got != c.want {
			t.Errorf("%v: %q, want %q", c.err, got, c.want)
		}
	}
	s := &statusError{status: 503, method: "GET", route: "/x"}
	if s.typeName() != "http.StatusServiceUnavailable" || s.Error() != "GET /x answered 503 Service Unavailable" {
		t.Fatal(s.typeName(), s.Error())
	}
	if (&statusError{status: 599}).typeName() != "http.Status599" {
		t.Fatal()
	}
}

// stacked carries a stack as github.com/go-errors/errors does.
type stacked struct{ pcs []uintptr }

func (s stacked) Error() string      { return "stacked" }
func (s stacked) Callers() []uintptr { return s.pcs }

func TestACarriedStackWins(t *testing.T) {
	pcs := callers(0)
	if got := carriedStack(fmt.Errorf("outer: %w", stacked{pcs})); len(got) != len(pcs) {
		t.Fatal(len(got))
	}
	if carriedStack(errors.New("plain")) != nil {
		t.Fatal()
	}
}

const crashText = `panic: runtime error: index out of range [3] with length 2

goroutine 7 [running]:
main.handler({0x1, 0x2})
	/app/main.go:21 +0x1d
net/http.HandlerFunc.ServeHTTP(...)
	/usr/local/go/src/net/http/server.go:2220 +0x29

goroutine 1 [IO wait]:
main.main()
	/app/main.go:40 +0x50
`

func TestParseCrash(t *testing.T) {
	message, kind, stack, ok := parseCrash(crashText)
	if !ok || message != "runtime error: index out of range [3] with length 2" || kind != "runtime.Error" {
		t.Fatal(message, kind)
	}
	if !strings.HasPrefix(stack, "goroutine 7 [running]:\nmain.handler") || strings.Contains(stack, "goroutine 1") {
		t.Fatal(stack)
	}
	m, k, _, _ := parseCrash("panic: first [recovered]\n\tpanic: second\n\ngoroutine 1 [running]:\nmain.main()\n")
	if m != "second" || k != "panic" {
		t.Fatal(m, k)
	}
	if _, k, _, _ := parseCrash("fatal error: concurrent map writes\n"); k != "fatal error" {
		t.Fatal(k)
	}
	if _, _, _, ok := parseCrash("nothing here"); ok {
		t.Fatal()
	}
}

func TestAnEarlierRunsCrashIsSent(t *testing.T) {
	c := newCollector(t)
	dir := t.TempDir()
	e := testErrors(t, c, ErrorsOptions{SpoolDir: dir})
	e.crashFile = strings.Replace(e.spoolFile, "analytics-errors-", "analytics-crash-", 1)
	e.crashFile = strings.TrimSuffix(e.crashFile, ".jsonl")
	// 2^22 + 7 is above any pid Linux hands out: a process long gone.
	dead := e.crashFile + "-4194311.log"
	os.WriteFile(dead, []byte(crashText), 0o600)
	empty := e.crashFile + "-4194313.log"
	os.WriteFile(empty, nil, 0o600)
	e.sendCrashes()
	events := sentErrors(c)
	if len(events) != 1 || events[0]["error_type"] != "runtime.Error" || events[0]["kind"] != "error" {
		t.Fatal(events)
	}
	for _, f := range []string{dead, empty} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s left", f)
		}
	}
}

func TestReleaseIsCleaned(t *testing.T) {
	if got := cleanRelease("  v1.0/beta 2 "); got != "v1.0beta2" {
		t.Fatal(got)
	}
}

func TestTheSameErrorOnAnotherRequestIsSentAgain(t *testing.T) {
	c := newCollector(t)
	e := testErrors(t, c, ErrorsOptions{})
	sentinel := errors.New("no rows")
	for i := 0; i < 3; i++ {
		ctx := withState(context.Background(), &reqState{method: "GET", path: "/a"})
		e.capture(ctx, sentinel, "error", 500, nil, false)
		e.capture(ctx, sentinel, "handled", 0, nil, false)
	}
	e.flush(context.Background(), false)
	if events := sentErrors(c); len(events) != 3 {
		t.Fatal(len(events))
	}
}

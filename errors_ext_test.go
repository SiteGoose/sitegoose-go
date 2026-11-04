package sitegoose_test

// From outside the package, as an app uses it: these frames are the app's
// own (the package's are left out of every stack), so a stack's top frame
// is checked here.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

const site = "bbbbbbbbbbbbbbbbbbbbbbbb"

type fakeCollector struct {
	server *httptest.Server
	mu     sync.Mutex
	bodies map[string][]map[string]any
}

func newFake(t *testing.T) *fakeCollector {
	f := &fakeCollector{bodies: map[string][]map[string]any{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(data, &body)
		f.mu.Lock()
		f.bodies[r.URL.Path] = append(f.bodies[r.URL.Path], body)
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeCollector) rows(path, field string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, body := range f.bodies[path] {
		list, _ := body[field].([]any)
		for _, row := range list {
			out = append(out, row.(map[string]any))
		}
	}
	return out
}

func (f *fakeCollector) errors() []map[string]any { return f.rows("/events/server-errors", "errors") }

func newPlatform(t *testing.T, f *fakeCollector) *sitegoose.Platform {
	keep := map[string]bool{sitegoose.ModuleErrors: true, sitegoose.ModulePerformance: true}
	var off []string
	for _, m := range []string{sitegoose.ModuleProxy, sitegoose.ModuleFirewall, sitegoose.ModuleAnalytics, sitegoose.ModuleCrawlers,
		sitegoose.ModuleForms, sitegoose.ModuleHeaders, sitegoose.ModuleAudit, sitegoose.ModuleFlags, sitegoose.ModuleMaintenance,
		sitegoose.ModuleInventory, sitegoose.ModulePosture, sitegoose.ModuleResources} {
		if !keep[m] {
			off = append(off, m)
		}
	}
	p := sitegoose.New(sitegoose.Options{SiteID: site, Secret: "sec", Endpoint: f.server.URL, ServerName: "web-1", Disable: off,
		Errors: sitegoose.ErrorsOptions{SpoolDir: t.TempDir(), DisableCrashCapture: true}})
	t.Cleanup(func() { p.Close(context.Background()) })
	return p
}

func serve(h http.Handler, method, path string) (res *http.Response, panicked any) {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set(sitegoose.SessionHeader, "visit-1")
	w := httptest.NewRecorder()
	func() {
		defer func() { panicked = recover() }()
		h.ServeHTTP(w, r)
	}()
	return w.Result(), panicked
}

func topFrame(stack string) string {
	line, _, _ := strings.Cut(stack, "\n")
	return line
}

//go:noinline
func boom(list []int) int { return list[3] }

func TestAPanicIsSentWithTheLineThatPanicked(t *testing.T) {
	f := newFake(t)
	p := newPlatform(t, f)
	mux := http.NewServeMux()
	mux.HandleFunc("/orders/", func(w http.ResponseWriter, r *http.Request) { boom([]int{1}) })
	res, panicked := serve(p.Middleware(mux), "GET", "/orders/42")
	if panicked == nil {
		t.Fatal("the panic didn't go on to net/http", res.StatusCode, bodyText(res))
	}
	p.Flush(context.Background())
	events := f.errors()
	if len(events) != 1 {
		t.Fatal(events)
	}
	ev := events[0]
	if !strings.HasPrefix(ev["message"].(string), "runtime error: index out of range") || ev["error_type"] != "runtime.boundsError" ||
		ev["kind"] != "error" || ev["status_code"] != float64(500) || ev["session_id"] != "visit-1" || ev["server_name"] != "web-1" {
		t.Fatalf("%v", ev)
	}
	if top := topFrame(ev["stack"].(string)); top != "github.com/sitegoose/sitegoose-go_test.boom(...)" {
		t.Fatalf("top frame %q\n%s", top, ev["stack"])
	}
	if strings.Contains(ev["stack"].(string), "sitegoose-go.") {
		t.Fatal("the package's own frames are in the stack")
	}
	if !strings.Contains(ev["stack"].(string), "\terrors_ext_test.go:") {
		t.Fatalf("paths aren't relative to the root:\n%s", ev["stack"])
	}
	wantRoute := "/orders/"
	if ev["route"] != wantRoute {
		t.Fatalf("route %v", ev["route"])
	}
	rows := f.rows("/events/server-requests", "rows")
	if len(rows) != 1 || rows[0]["route"] != wantRoute || rows[0]["status"] != float64(500) || rows[0]["method"] != "GET" {
		t.Fatalf("%v", rows)
	}
}

//go:noinline
func failWith(w http.ResponseWriter) {
	http.Error(w, "database down\nretry later", http.StatusServiceUnavailable)
}

func TestA5xxAnswerIsAnError(t *testing.T) {
	f := newFake(t)
	p := newPlatform(t, f)
	res, _ := serve(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { failWith(w) })), "GET", "/report/2026")
	if res.StatusCode != 503 {
		t.Fatal(res.StatusCode)
	}
	p.Flush(context.Background())
	events := f.errors()
	if len(events) != 1 {
		t.Fatal(events)
	}
	ev := events[0]
	if ev["message"] != "database down" || ev["error_type"] != "http.StatusServiceUnavailable" || ev["route"] != "/report/:id" || ev["status_code"] != float64(503) {
		t.Fatalf("%v", ev)
	}
	if top := topFrame(ev["stack"].(string)); top != "github.com/sitegoose/sitegoose-go_test.failWith(...)" {
		t.Fatalf("top frame %q\n%s", top, ev["stack"])
	}
	// A 4xx isn't an error.
	serve(p.Middleware(http.NotFoundHandler()), "GET", "/nope")
	p.Flush(context.Background())
	if len(f.errors()) != 1 {
		t.Fatal("a 404 was sent")
	}
	for _, row := range f.rows("/events/server-requests", "rows") {
		if row["status"] == float64(404) && row["route"] != "/(not found)" {
			t.Fatalf("%v", row)
		}
	}
}

func TestACapturedErrorIsNotSentAgainForItsAnswer(t *testing.T) {
	f := newFake(t)
	p := newPlatform(t, f)
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.CaptureError(r.Context(), errors.New("payment provider timeout"))
		w.WriteHeader(http.StatusBadGateway)
	}))
	serve(h, "POST", "/pay")
	p.Flush(context.Background())
	events := f.errors()
	if len(events) != 1 || events[0]["kind"] != "handled" || events[0]["status_code"] != float64(502) || events[0]["method"] != "POST" {
		t.Fatal(events)
	}
}

func TestBreadcrumbsAndOutgoingRequests(t *testing.T) {
	f := newFake(t)
	p := newPlatform(t, f)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(418) }))
	defer upstream.Close()
	client := &http.Client{Transport: p.Transport(nil)}
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.AddBreadcrumb(r.Context(), "basket loaded")
		req, _ := http.NewRequestWithContext(r.Context(), "GET", upstream.URL+"/stock?id=1", nil)
		if res, err := client.Do(req); err == nil {
			res.Body.Close()
		}
		p.CaptureError(r.Context(), errors.New("stock unknown"))
	}))
	serve(h, "GET", "/basket")
	p.Flush(context.Background())
	events := f.errors()
	if len(events) != 1 {
		t.Fatal(events)
	}
	crumbs := events[0]["breadcrumbs"].([]any)
	if len(crumbs) != 2 {
		t.Fatal(crumbs)
	}
	note, request := crumbs[0].(map[string]any), crumbs[1].(map[string]any)
	if note["type"] != "note" || note["text"] != "basket loaded" {
		t.Fatal(note)
	}
	if request["type"] != "request" || request["text"] != "GET "+upstream.URL+"/stock" || request["status"] != float64(418) {
		t.Fatal(request)
	}
}

func TestLoggedErrorsThroughSlog(t *testing.T) {
	f := newFake(t)
	p := newPlatform(t, f)
	logger := slog.New(p.SlogHandler(slog.NewTextHandler(io.Discard, nil)))
	err := errors.New("cache miss storm")
	logger.Info("not an error", "err", err)
	logger.Error("no error attribute")
	logger.With("err", err).ErrorContext(context.Background(), "cache failed")
	p.CaptureError(context.Background(), err) // the same error: filled in, not sent twice
	p.Flush(context.Background())
	events := f.errors()
	if len(events) != 1 || events[0]["kind"] != "handled" || events[0]["message"] != "cache miss storm" {
		t.Fatal(events)
	}
	if top := topFrame(events[0]["stack"].(string)); !strings.HasPrefix(top, "github.com/sitegoose/sitegoose-go_test.TestLoggedErrorsThroughSlog") {
		t.Fatalf("top frame %q", top)
	}
}

func TestJobs(t *testing.T) {
	f := newFake(t)
	p := newPlatform(t, f)
	err := p.Job(context.Background(), "nightly import", func(ctx context.Context) error { return errors.New("feed 404") })
	if err == nil || err.Error() != "feed 404" {
		t.Fatal(err)
	}
	p.Job(context.Background(), "nightly import", func(ctx context.Context) error { return nil })
	p.Job(context.Background(), "nightly import", func(ctx context.Context) error { return context.Canceled })
	func() {
		defer func() { recover() }()
		p.Job(context.Background(), "panicky", func(ctx context.Context) error { panic("nil config") })
	}()
	p.Flush(context.Background())
	events := f.errors()
	if len(events) != 2 || events[0]["route"] != "/(job) nightly import" || events[0]["status_code"] != float64(500) ||
		events[1]["message"] != "nil config" || events[1]["error_type"] != "panic" {
		t.Fatal(events)
	}
	statuses := map[float64]float64{}
	for _, row := range f.rows("/events/server-requests", "rows") {
		if row["method"] != "JOB" {
			t.Fatal(row)
		}
		statuses[row["status"].(float64)] += row["count"].(float64)
	}
	if statuses[200] != 1 || statuses[500] != 2 {
		t.Fatal(statuses)
	}
}

func TestRecoverInAGoroutine(t *testing.T) {
	f := newFake(t)
	p := newPlatform(t, f)
	done := make(chan any)
	go func() {
		defer func() { done <- recover() }()
		defer p.Recover(context.Background())
		panic(errors.New("worker died"))
	}()
	if v := <-done; v == nil {
		t.Fatal("Recover swallowed the panic")
	}
	// Recover waited for it to go.
	if events := f.errors(); len(events) != 1 || events[0]["message"] != "worker died" {
		t.Fatal(events)
	}
}

func TestSetRouteAndRouteOption(t *testing.T) {
	f := newFake(t)
	p := newPlatform(t, f)
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sitegoose.SetRoute(r.Context(), "/things/:slug")
	}))
	serve(h, "GET", "/things/blue")
	p.Flush(context.Background())
	if rows := f.rows("/events/server-requests", "rows"); len(rows) != 1 || rows[0]["route"] != "/things/:slug" {
		t.Fatal(rows)
	}
}

func TestWithoutCredentialsEverythingPasses(t *testing.T) {
	p := sitegoose.New(sitegoose.Options{})
	res, _ := serve(p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })), "GET", "/")
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	p.CaptureError(context.Background(), errors.New("x"))
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func bodyText(res *http.Response) string {
	data, _ := io.ReadAll(res.Body)
	return string(data)
}

package sitegoose

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func callRows(t *testing.T, c *collector) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, s := range c.requests("/events/server-calls") {
		if s.header.Get("Authorization") != "Bearer test-secret" || s.body["site_id"] != testSite || s.body["server_name"] != "shop-api" {
			t.Fatal(s.header, s.body)
		}
		for _, row := range s.body["rows"].([]any) {
			r := row.(map[string]any)
			out[fmt.Sprint(r["method"], " ", r["route"], " ", r["call_method"], " ", r["host"])] = r
		}
	}
	return out
}

func TestCallHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://API.Stripe.com/v1/charges?key=x": "api.stripe.com",
		"https://api.stripe.com:443/v1":           "api.stripe.com",
		"http://localhost:80/x":                   "localhost",
		"http://localhost:8080/x":                 "localhost:8080",
		"https://localhost:80/x":                  "localhost:80",
		"http://[::1]:3000/x":                     "[::1]:3000",
		"http://[::1]/x":                          "[::1]",
		"http://exa%20mple.com/":                  "",
	} {
		u, err := url.Parse(in)
		got := ""
		if err == nil {
			got = callHost(u)
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func TestCallsThroughTransport(t *testing.T) {
	c := newCollector(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/down":
			w.WriteHeader(503)
		case "/missing":
			w.WriteHeader(404)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		default:
			w.WriteHeader(200)
		}
	}))
	defer upstream.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close() // refused: no answer, a failed call
	up, _ := url.Parse(upstream.URL)
	host := up.Host

	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, ServerName: "shop-api",
		Disable: allBut(ModulePerformance)})
	t.Cleanup(func() { p.Close(context.Background()) })
	client := &http.Client{Transport: p.Transport(nil)}
	get := func(ctx context.Context, method, address string) {
		req, _ := http.NewRequestWithContext(ctx, method, address, nil)
		if res, err := client.Do(req); err == nil {
			res.Body.Close()
		}
	}

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetRoute(r.Context(), "/checkout")
		ctx := r.Context()
		get(ctx, "POST", upstream.URL+"/v1/charges/ch_123?key=secret")
		get(ctx, "POST", upstream.URL+"/v1/other")
		get(ctx, "GET", upstream.URL+"/down")
		get(ctx, "GET", upstream.URL+"/missing")
		get(ctx, "GET", goneURL+"/x")
		get(ctx, "POST", c.server.URL+"/events/x") // the package's own collector: left out
		cancelled, cancel := context.WithCancel(ctx)
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		get(cancelled, "GET", upstream.URL+"/slow") // cancelled by the app: not counted
		late, cancelLate := context.WithTimeout(ctx, 50*time.Millisecond)
		get(late, "PUT", upstream.URL+"/slow") // out of time: no answer, a failed call
		cancelLate()
		// http.Client's own Timeout is out of time too, not a cancel.
		timed := &http.Client{Timeout: 50 * time.Millisecond, Transport: p.Transport(nil)}
		if req, err := http.NewRequestWithContext(ctx, "DELETE", upstream.URL+"/slow", nil); err == nil {
			if res, err := timed.Do(req); err == nil {
				res.Body.Close()
			}
		}
		// Wrapped twice, counted once.
		twice := &http.Client{Transport: p.Transport(p.Transport(nil))}
		if req, err := http.NewRequestWithContext(ctx, "PATCH", upstream.URL+"/v1", nil); err == nil {
			if res, err := twice.Do(req); err == nil {
				res.Body.Close()
			}
		}
		w.WriteHeader(200)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/checkout", nil))
	get(context.Background(), "GET", upstream.URL+"/health")
	p.Flush(context.Background())

	gu, _ := url.Parse(goneURL)
	rows := callRows(t, c)
	want := map[string][2]float64{ // count, errors
		"POST /checkout POST " + host:   {2, 0},
		"POST /checkout GET " + host:    {2, 1}, // a 5xx fails, a 4xx doesn't
		"POST /checkout GET " + gu.Host: {1, 1},
		"POST /checkout PUT " + host:    {1, 1},
		"POST /checkout DELETE " + host: {1, 1},
		"POST /checkout PATCH " + host:  {1, 0},
		"JOB (background) GET " + host:  {1, 0},
	}
	for key, n := range want {
		r := rows[key]
		if r == nil || r["count"] != n[0] || r["errors"] != n[1] || len(r["buckets"].([]any)) != len(bucketEdgesMS)+1 {
			t.Errorf("%s: %v", key, r)
		}
	}
	if len(rows) != len(want) {
		t.Error(rows)
	}
	for _, s := range c.requests("/events/server-calls") {
		if fmt.Sprint(s.body) == "" || containsAny(fmt.Sprint(s.body), "ch_123", "secret", "/v1") {
			t.Fatal("a path or query left the server", s.body)
		}
	}
}

func containsAny(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func TestCallsCanBeLeftOut(t *testing.T) {
	c := newCollector(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, ServerName: "shop-api",
		Disable: allBut(ModulePerformance), Performance: PerformanceOptions{DisableCalls: true, DisableQueues: true}})
	t.Cleanup(func() { p.Close(context.Background()) })
	client := &http.Client{Transport: p.Transport(nil)}
	if res, err := client.Get(upstream.URL); err == nil {
		res.Body.Close()
	}
	p.Flush(context.Background())
	if len(c.requests("/events/server-calls")) != 0 || p.calls != nil {
		t.Fatal("DisableCalls must leave calls out")
	}
	if stop := p.WatchQueues("asynq", "127.0.0.1:6379/0", func(context.Context) ([]QueueReading, error) { return nil, nil }); stop == nil {
		t.Fatal("stop must never be nil")
	}
}

func i64(v int64) *int64 { return &v }

func TestWatchQueues(t *testing.T) {
	c := newCollector(t)
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, ServerName: "worker-1",
		Disable: allBut(ModulePerformance)})
	t.Cleanup(func() { p.Close(context.Background()) })
	p.WatchQueues("asynq", "redis://user:pass@127.0.0.1:6379/0", func(context.Context) ([]QueueReading, error) {
		return []QueueReading{
			{Queue: "emails", Waiting: i64(1240), Running: i64(4), Delayed: i64(12), Failed: i64(3), OldestS: i64(610),
				Finished: i64(180), Shared: true},
			{Queue: "empty"}, // nothing to say: no row
			{Queue: ""},
		}, nil
	})
	p.WatchQueues("celery", "", func(context.Context) ([]QueueReading, error) { // no broker: not watched
		return []QueueReading{{Queue: "x", Waiting: i64(1)}}, nil
	})
	p.WatchQueues("made-up", "10.0.0.5:6379/1", func(context.Context) ([]QueueReading, error) {
		return nil, errors.New("connection refused") // a gap
	})
	old := queueReadWait
	queueReadWait = 100 * time.Millisecond
	defer func() { queueReadWait = old }()
	release := make(chan struct{})
	defer close(release)
	p.WatchQueues("rq", "10.0.0.6:6379/0", func(context.Context) ([]QueueReading, error) {
		<-release // never answers in time: a gap
		return []QueueReading{{Queue: "late", Waiting: i64(1)}}, nil
	})
	p.queueRead.sample(context.Background())
	p.queueRead.sample(context.Background()) // the hung reader isn't started again

	got := c.requests("/events/server-queues")
	if len(got) != 2 {
		t.Fatal(len(got))
	}
	body := got[0].body
	sender, _ := body["sender"].(string)
	if body["server_name"] != "worker-1" || len(sender) != 16 || got[1].body["sender"] != sender ||
		got[0].header.Get("Authorization") != "Bearer test-secret" {
		t.Fatal(body)
	}
	rows := body["rows"].([]any)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	r := rows[0].(map[string]any)
	if r["system"] != "asynq" || r["broker"] != "127.0.0.1:6379/0" || r["queue"] != "emails" || r["waiting"] != float64(1240) ||
		r["oldest_s"] != float64(610) || r["added"] != nil || r["finished"] != float64(180) || r["shared"] != true {
		t.Fatal(r)
	}
	if _, has := r["added"]; !has {
		t.Fatal("an unknown count is sent as null")
	}
}

func TestInflightPeak(t *testing.T) {
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: "http://127.0.0.1:1", Disable: allBut(ModulePerformance)})
	t.Cleanup(func() { p.Close(context.Background()) })
	if _, ok := p.perf.takeInflightPeak(); ok {
		t.Fatal("no peak before the middleware ran")
	}
	hold := make(chan struct{})
	inside := make(chan struct{}, 3)
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inside <- struct{}{}
		<-hold
	}))
	done := make(chan struct{})
	for i := 0; i < 3; i++ {
		go func() {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
			done <- struct{}{}
		}()
	}
	for i := 0; i < 3; i++ {
		<-inside
	}
	close(hold)
	for i := 0; i < 3; i++ {
		<-done
	}
	if peak, ok := p.perf.takeInflightPeak(); !ok || peak != 3 {
		t.Fatal(peak, ok)
	}
	if peak, ok := p.perf.takeInflightPeak(); !ok || peak != 0 {
		t.Fatal("the peak starts again at what is in progress", peak)
	}
}

func TestClickHouseDriverName(t *testing.T) {
	if databaseFor("clickhouse", nil) != "clickhouse" || databaseOf("ClickHouse") != "clickhouse" {
		t.Fatal("clickhouse")
	}
}

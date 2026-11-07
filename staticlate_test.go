package sitegoose

// A static-looking request counted after the response (firewall.md,
// `rate`): compared with the counts first, so an address already over is
// refused its files, then counted toward the rate and the page limits it
// skipped when ServeMux sent it to a pattern that isn't a file's
// ("GET /search/{q}" took "/search/x.css") or it answered 400 or more.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func searchLimit() map[string]any {
	return map[string]any{"mode": "block", "limits": map[string]any{"rules": []any{
		map[string]any{"id": "search", "action": "block", "limit": 2, "window": 60, "path": map[string]any{"prefix": []any{"/search"}}},
	}}}
}

func staticMux() *http.ServeMux {
	mux := http.NewServeMux()
	page := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("results"))
	}
	mux.HandleFunc("GET /search/{q}", page)
	// A file server under a subtree: its answer is a file's.
	mux.HandleFunc("/search/files/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified) // http.FileServer drops the Content-Type here
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write([]byte("body{}"))
	})
	// A pattern that is itself a file's by the static rule.
	mux.HandleFunc("/assets/", page)
	return mux
}

func getFrom(h http.Handler, path string, header ...string) int {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "198.51.100.7:5000"
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestStaticRoutedToAPatternCountsLate(t *testing.T) {
	p := checkPlatform(t, nil, searchLimit())
	h := p.Middleware(staticMux())
	for i, want := range []int{200, 200, 200, 429} {
		if got := getFrom(h, "/search/x.css"); got != want {
			t.Fatalf("request %d: %d, want %d", i+1, got, want)
		}
	}
}

func TestStaticFilesAndFileRoutesAreNotCounted(t *testing.T) {
	p := checkPlatform(t, nil, searchLimit())
	h := p.Middleware(staticMux())
	for i := 0; i < 5; i++ {
		for _, call := range [][]string{{"/search/files/app.css"}, {"/search/files/app.css", "If-None-Match", `"1"`}, {"/assets/x.css"}} {
			if got := getFrom(h, call[0], call[1:]...); got != 200 && got != 304 {
				t.Fatalf("%v: %d", call, got)
			}
		}
	}
	for i, want := range []int{200, 200, 429} {
		if got := getFrom(h, "/search/page"); got != want {
			t.Fatalf("page %d: %d, want %d", i+1, got, want)
		}
	}
}

func TestStaticErrorCountsAndOverIsRefusedItsFiles(t *testing.T) {
	more := searchLimit()
	more["rate"] = map[string]any{"limit": 2, "window": 60}
	p := checkPlatform(t, nil, more)
	h := p.Middleware(http.NotFoundHandler())
	for i, want := range []int{404, 404, 404, 429} {
		if got := getFrom(h, "/made-up.css"); got != want {
			t.Fatalf("request %d: %d, want %d", i+1, got, want)
		}
	}
}

func TestStaticPeekWithASharedCounter(t *testing.T) {
	var mu sync.Mutex
	shared := map[string]int64{}
	counter := func(key string, ttl time.Duration) (int64, error) {
		mu.Lock()
		defer mu.Unlock()
		shared[key]++
		return shared[key], nil
	}
	f := testFirewall(t, "s", challengeRules(nil, searchLimit()), FirewallOptions{Counter: counter})
	ask := func(target string) Decision {
		return f.Check(CheckInput{IP: "198.51.100.7", Method: "GET", Target: target})
	}
	if d := ask("/search/app.css"); d.Action != "allow" || d.late == nil || len(shared) != 0 {
		t.Fatalf("%+v %v: a static file adds nothing", d, shared)
	}
	ask("/search")
	ask("/search")
	if d := ask("/search"); d.Rule != "limit:search" {
		t.Fatal(d)
	}
	if d := ask("/search/app.css"); d.Rule != "limit:search" || len(shared) != 1 {
		t.Fatalf("%+v %v: seen over here, refused without adding", d, shared)
	}
	// A counter that fails falls back to the count here, peek and all.
	broken := testFirewall(t, "s", challengeRules(nil, searchLimit()), FirewallOptions{Counter: func(string, time.Duration) (int64, error) {
		return 0, errors.New("down")
	}})
	for i := 0; i < 3; i++ {
		broken.countStatic(broken.Check(CheckInput{IP: "198.51.100.7", Method: "GET", Target: "/search/x.css"}).late, 404, false)
	}
	if d := broken.Check(CheckInput{IP: "198.51.100.7", Method: "GET", Target: "/search/app.css"}); d.Rule != "limit:search" {
		t.Fatalf("%+v: over the count kept here, refused its files", d)
	}
}

// With a shared counter that is slow, static files are counted off their
// requests only lateSlotsMax at a time; past them, on the request, so a
// flood can't pile up goroutines waiting on the counter.
func TestStaticSharedCountsAreBounded(t *testing.T) {
	p := checkPlatform(t, nil, searchLimit())
	release := make(chan struct{})
	var calls atomic.Int64
	p.firewall.counter = func(string, time.Duration) (int64, error) {
		calls.Add(1)
		<-release
		return 1, nil
	}
	h := p.Middleware(staticMux())
	// Files a page asks for: nothing to count, the counter is never called.
	for i := 0; i < 2*lateSlotsMax; i++ {
		getFrom(h, "/search/files/app.css")
	}
	for i := 0; i < lateSlotsMax; i++ {
		if got := getFrom(h, "/search/x.css"); got != 200 {
			t.Fatalf("request %d: %d", i+1, got)
		}
	}
	done := make(chan struct{})
	go func() {
		getFrom(h, "/search/x.css")
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("past the slots, a request is counted on itself")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done
	for deadline := time.Now().Add(2 * time.Second); calls.Load() != lateSlotsMax+1 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if n := calls.Load(); n != lateSlotsMax+1 {
		t.Fatalf("counter called %d times, want %d", n, lateSlotsMax+1)
	}
}

func TestRoutedToPage(t *testing.T) {
	for _, c := range []struct {
		pattern, contentType string
		want                 bool
	}{
		{"GET /search/{q}", "text/html", true},
		{"example.com/search/{q}", "", true},
		{"/search/:q", "text/html", true},
		{"/search/*q", "", true},
		{"/", "text/html", true},
		{"", "text/html", false},
		{"/", "text/css; charset=utf-8", false},
		{"/public/*filepath", "image/png", false},
		{"/static/", "", false},
		{"GET /assets/*filepath", "", false},
		{"/avatars/:id.png", "text/html", false},
	} {
		if got := routedToPage(c.pattern, c.contentType); got != c.want {
			t.Errorf("routedToPage(%q, %q) = %v", c.pattern, c.contentType, got)
		}
	}
}

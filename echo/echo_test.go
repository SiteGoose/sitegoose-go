package sitegooseecho_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	sitegoose "github.com/sitegoose/sitegoose-go"
	sitegooseecho "github.com/sitegoose/sitegoose-go/echo"
)

type fake struct {
	server *httptest.Server
	mu     sync.Mutex
	rows   map[string][]map[string]any
}

func newFake(t *testing.T) *fake {
	f := &fake{rows: map[string][]map[string]any{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events/firewall/rules" {
			w.Write([]byte(`{"v":1,"enabled":true,"mode":"block","deny":["198.51.100.7"]}`))
			return
		}
		data, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(data, &body)
		f.mu.Lock()
		for _, field := range []string{"rows", "errors"} {
			list, _ := body[field].([]any)
			for _, row := range list {
				f.rows[r.URL.Path] = append(f.rows[r.URL.Path], row.(map[string]any))
			}
		}
		f.mu.Unlock()
		w.WriteHeader(202)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fake) get(path string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.rows[path]...)
}

func TestEcho(t *testing.T) {
	f := newFake(t)
	p := sitegoose.New(sitegoose.Options{SiteID: "cccccccccccccccccccccccc", Secret: "s", Endpoint: f.server.URL, TrustProxy: "1",
		Disable: []string{"inventory", "posture", "resources", "proxy", "maintenance", "analytics", "crawlers", "flags", "forms", "headers", "audit"},
		Errors:  sitegoose.ErrorsOptions{SpoolDir: t.TempDir(), DisableCrashCapture: true}})
	defer p.Close(context.Background())
	e := echo.New()
	e.Use(middleware.Recover(), sitegooseecho.Middleware(p))
	e.GET("/orders/:id", func(c echo.Context) error { return c.String(200, "order") })
	e.GET("/boom", func(c echo.Context) error { panic("boom") })
	e.GET("/bad", func(c echo.Context) error { return errors.New("upstream gone") })
	e.GET("/missing", func(c echo.Context) error { return echo.NewHTTPError(404, "no") })
	do := func(path, ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Forwarded-For", ip)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
		return w
	}
	for i := 0; i < 200 && do("/orders/1", "198.51.100.7").Code != 403; i++ {
		p.Flush(context.Background())
	}
	if w := do("/orders/1", "198.51.100.7"); w.Code != 403 {
		t.Fatal("not blocked", w.Code)
	}
	if w := do("/orders/2", "203.0.113.1"); w.Code != 200 || w.Body.String() != "order" {
		t.Fatal(w.Code)
	}
	if w := do("/boom", "203.0.113.1"); w.Code != 500 {
		t.Fatal(w.Code)
	}
	if w := do("/bad", "203.0.113.1"); w.Code != 500 {
		t.Fatal(w.Code)
	}
	if w := do("/missing", "203.0.113.1"); w.Code != 404 {
		t.Fatal(w.Code)
	}
	p.Flush(context.Background())
	routes := map[string]bool{}
	for _, row := range f.get("/events/server-requests") {
		routes[row["route"].(string)] = true
	}
	if !routes["/orders/:id"] || !routes["/boom"] || !routes["/bad"] {
		t.Fatal(routes)
	}
	errs := f.get("/events/server-errors")
	if len(errs) != 2 || errs[0]["message"] != "boom" || !strings.HasPrefix(errs[0]["stack"].(string), "github.com/sitegoose/sitegoose-go/echo_test.TestEcho.func") ||
		errs[1]["message"] != "upstream gone" || errs[1]["status_code"] != float64(500) || errs[1]["route"] != "/bad" {
		t.Fatalf("%v", errs)
	}
}

func TestEchoOuterMiddlewareSeesTheError(t *testing.T) {
	p := sitegoose.New(sitegoose.Options{})
	defer p.Close(context.Background())
	e := echo.New()
	var seen error
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { seen = next(c); return seen }
	}, sitegooseecho.Middleware(p))
	e.GET("/bad", func(c echo.Context) error { return errors.New("upstream gone") })
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest("GET", "/bad", nil))
	if seen == nil || w.Code != 500 || strings.Count(w.Body.String(), "Internal Server Error") != 1 {
		t.Fatal(seen, w.Code, w.Body.String())
	}
}

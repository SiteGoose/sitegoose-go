package sitegoosechi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	sitegoose "github.com/sitegoose/sitegoose-go"
	sitegoosechi "github.com/sitegoose/sitegoose-go/chi"
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

func TestChi(t *testing.T) {
	f := newFake(t)
	p := sitegoose.New(sitegoose.Options{SiteID: "cccccccccccccccccccccccc", Secret: "s", Endpoint: f.server.URL, TrustProxy: "1",
		Disable: []string{"inventory", "posture", "resources", "proxy", "maintenance", "analytics", "crawlers", "flags", "forms", "headers", "audit"},
		Errors:  sitegoose.ErrorsOptions{SpoolDir: t.TempDir(), DisableCrashCapture: true}})
	defer p.Close(context.Background())
	r := chi.NewRouter()
	r.Use(sitegoosechi.Middleware(p))
	r.Get("/orders/{id}", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("order")) })
	r.Get("/boom/{x}", func(w http.ResponseWriter, r *http.Request) { panic("boom") })
	do := func(path, ip string) (w *httptest.ResponseRecorder) {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Forwarded-For", ip)
		w = httptest.NewRecorder()
		defer func() { recover() }()
		r.ServeHTTP(w, req)
		return w
	}
	for i := 0; i < 200 && do("/orders/1", "198.51.100.7").Code != 403; i++ {
		p.Flush(context.Background())
	}
	if w := do("/orders/1", "198.51.100.7"); w.Code != 403 {
		t.Fatal("not blocked", w.Code)
	}
	if w := do("/orders/2", "203.0.113.1"); w.Body.String() != "order" {
		t.Fatal(w.Code)
	}
	do("/boom/1", "203.0.113.1")
	p.Flush(context.Background())
	routes := map[string]bool{}
	for _, row := range f.get("/events/server-requests") {
		routes[row["route"].(string)] = true
	}
	if !routes["/orders/{id}"] || !routes["/boom/{x}"] {
		t.Fatal(routes)
	}
	errs := f.get("/events/server-errors")
	if len(errs) != 1 || errs[0]["message"] != "boom" || errs[0]["route"] != "/boom/{x}" ||
		!strings.HasPrefix(errs[0]["stack"].(string), "github.com/sitegoose/sitegoose-go/chi_test.TestChi.func") {
		t.Fatalf("%v", errs)
	}
}

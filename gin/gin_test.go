package sitegoosegin_test

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

	"github.com/gin-gonic/gin"

	sitegoose "github.com/sitegoose/sitegoose-go"
	sitegoosegin "github.com/sitegoose/sitegoose-go/gin"
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

func TestGin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newFake(t)
	p := sitegoose.New(sitegoose.Options{SiteID: "cccccccccccccccccccccccc", Secret: "s", Endpoint: f.server.URL, TrustProxy: "1",
		Disable: []string{"inventory", "posture", "resources", "proxy", "maintenance", "analytics", "crawlers", "flags", "forms", "headers", "audit"},
		Errors:  sitegoose.ErrorsOptions{SpoolDir: t.TempDir(), DisableCrashCapture: true}})
	defer p.Close(context.Background())
	r := gin.New()
	r.Use(gin.Recovery(), sitegoosegin.Middleware(p))
	r.GET("/orders/:id", func(c *gin.Context) { c.String(200, "order") })
	r.GET("/boom", func(c *gin.Context) { panic("boom") })
	r.GET("/bad", func(c *gin.Context) {
		c.Error(errors.New("upstream gone"))
		c.String(502, "bad gateway")
	})
	do := func(path, ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Forwarded-For", ip)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	// Wait for the rules.
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
	do("/bad", "203.0.113.1")
	p.Flush(context.Background())
	routes := map[string]bool{}
	for _, row := range f.get("/events/server-requests") {
		routes[row["route"].(string)] = true
	}
	if !routes["/orders/:id"] || !routes["/boom"] || !routes["/bad"] {
		t.Fatal(routes)
	}
	errs := f.get("/events/server-errors")
	if len(errs) != 2 || errs[0]["message"] != "boom" || !strings.HasPrefix(errs[0]["stack"].(string), "github.com/sitegoose/sitegoose-go/gin_test.TestGin.func") ||
		errs[1]["message"] != "upstream gone" || errs[1]["status_code"] != float64(502) || errs[1]["route"] != "/bad" {
		t.Fatalf("%v", errs)
	}
}

func TestGinStreamsInsideTheMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p := sitegoose.New(sitegoose.Options{})
	defer p.Close(context.Background())
	r := gin.New()
	r.Use(gin.Recovery(), sitegoosegin.Middleware(p))
	r.GET("/sse", func(c *gin.Context) {
		c.Stream(func(w io.Writer) bool { io.WriteString(w, "data: hi\n\n"); return false })
	})
	srv := httptest.NewServer(p.Middleware(r))
	defer srv.Close()
	res, err := http.Get(srv.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(b) != "data: hi\n\n" {
		t.Fatal(res.StatusCode, string(b))
	}
}

func TestGinWebSocketsAreNotTimed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newFake(t)
	p := sitegoose.New(sitegoose.Options{SiteID: "cccccccccccccccccccccccc", Secret: "s", Endpoint: f.server.URL,
		Disable: []string{"firewall", "inventory", "posture", "resources", "proxy"}})
	defer p.Close(context.Background())
	r := gin.New()
	r.Use(sitegoosegin.Middleware(p))
	r.GET("/ws", func(c *gin.Context) {
		conn, rw, err := c.Writer.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		conn.Close()
	})
	srv := httptest.NewServer(r)
	defer srv.Close()
	if res, err := http.Get(srv.URL + "/ws"); err == nil {
		res.Body.Close()
	}
	p.Flush(context.Background())
	if rows := f.get("/events/server-requests"); len(rows) != 0 {
		t.Fatal(rows)
	}
}

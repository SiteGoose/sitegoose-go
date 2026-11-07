package sitegoosegin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	sitegoose "github.com/sitegoose/sitegoose-go"
	sitegoosegin "github.com/sitegoose/sitegoose-go/gin"
)

// A static-looking request gin routes to a page ("/search/:q" took
// "/search/x.css") counts toward the /search page limit after the response;
// a file gin's Static serves doesn't (firewall.md, `rate`).
func TestGinCountsARoutedStaticFileLate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events/firewall/rules" {
			w.Write([]byte(`{"v":1,"enabled":true,"mode":"block","deny":["198.51.100.9"],"limits":{"rules":[` +
				`{"id":"search","action":"block","limit":2,"window":60,"path":{"prefix":["/search"]}}]}}`))
			return
		}
		w.WriteHeader(202)
	}))
	defer server.Close()
	p := sitegoose.New(sitegoose.Options{SiteID: "cccccccccccccccccccccccc", Secret: "s", Endpoint: server.URL, TrustProxy: "1",
		Disable: []string{"inventory", "posture", "resources", "proxy", "maintenance", "analytics", "crawlers", "flags", "forms", "headers", "audit", "errors", "performance"}})
	defer p.Close(context.Background())
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.css"), []byte("body{}"), 0o600)
	r := gin.New()
	r.Use(sitegoosegin.Middleware(p))
	r.GET("/search/:q", func(c *gin.Context) { c.Data(200, "text/html; charset=utf-8", []byte("results")) })
	r.Static("/search-files", dir)
	do := func(path, ip string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Forwarded-For", ip)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	for i := 0; i < 200 && do("/search/q", "198.51.100.9") != 403; i++ {
		p.Flush(context.Background())
	}
	for i := 0; i < 5; i++ {
		if code := do("/search-files/app.css", "203.0.113.1"); code != 200 {
			t.Fatal("a file gin serves", code)
		}
	}
	for i, want := range []int{200, 200, 200, 429} {
		if code := do("/search/x.css", "203.0.113.1"); code != want {
			t.Fatalf("request %d: %d, want %d", i+1, code, want)
		}
	}
}

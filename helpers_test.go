package sitegoose

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const testSite = "aaaaaaaaaaaaaaaaaaaaaaaa"

// sent is one request the fake collector got.
type sent struct {
	method string
	path   string
	query  string
	header http.Header
	body   map[string]any
}

// collector is a fake collector: it records what it gets and answers with
// the handler for the path, else 202.
type collector struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	got      []sent
	handlers map[string]func(w http.ResponseWriter, r *http.Request)
}

func newCollector(t *testing.T) *collector {
	c := &collector{t: t, handlers: map[string]func(http.ResponseWriter, *http.Request){}}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(data, &body)
		c.mu.Lock()
		c.got = append(c.got, sent{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
		handler := c.handlers[r.URL.Path]
		c.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"accepted"}`))
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *collector) handle(path string, fn func(w http.ResponseWriter, r *http.Request)) {
	c.mu.Lock()
	c.handlers[path] = fn
	c.mu.Unlock()
}

func (c *collector) json(path string, status int, body any) {
	data, _ := json.Marshal(body)
	c.handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(data)
	})
}

func (c *collector) requests(path string) []sent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []sent
	for _, s := range c.got {
		if s.path == path {
			out = append(out, s)
		}
	}
	return out
}

// waitFor polls until at least n requests reached path.
func (c *collector) waitFor(path string, n int) []sent {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.requests(path); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.t.Fatalf("collector never got %d requests to %s (got %d)", n, path, len(c.requests(path)))
	return nil
}

// testCore is a core that sends to c, with no background jobs of its own.
func testCore(c *collector) *core {
	endpoint := ""
	if c != nil {
		endpoint = c.server.URL
	}
	return newCore(testSite, "test-secret", endpoint, false, "test-server")
}

// offlineCore is valid in shape but starts no jobs (no endpoint).
func offlineCore(secret string) *core {
	return newCore(testSite, secret, "", false, "test-server")
}

func readShared(t *testing.T, name string, into any) {
	t.Helper()
	path := filepath.Join("..", "protocols", name)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("%s isn't here: the package is outside the sdk tree", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatal(err)
	}
}

func rulesFrom(t *testing.T, data map[string]any) *firewallRules {
	t.Helper()
	// Through JSON, as the rules arrive.
	raw, _ := json.Marshal(data)
	var decoded map[string]any
	json.Unmarshal(raw, &decoded)
	rules, err := compileFirewall(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func testFirewall(t *testing.T, secret string, data map[string]any, o FirewallOptions) *Firewall {
	f := newFirewall(offlineCore(secret), o, "", nil)
	f.rules.Store(rulesFrom(t, data))
	return f
}

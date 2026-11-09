package sitegooseredis

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/redis/go-redis/v9"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

// fakeRedis answers RESP2 commands (HELLO is unknown): GET of a missing key is nil, LPUSH a
// WRONGTYPE error, MULTI/EXEC a transaction, called off after a WATCH, anything else +OK.
func fakeRedis(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveRESP(conn)
		}
	}()
	return ln.Addr().String()
}

func serveRESP(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	var queued []string
	inMulti, watched := false, false
	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		name := strings.ToUpper(args[0])
		reply := "+OK\r\n"
		switch name {
		case "GET":
			reply = "$-1\r\n"
		case "LPUSH":
			reply = "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"
		case "INCR":
			reply = ":1\r\n"
		case "HELLO": // a RESP2 server: the client goes on without
			reply = "-ERR unknown command 'HELLO'\r\n"
		}
		switch {
		case name == "WATCH" || name == "UNWATCH":
			watched = name == "WATCH"
		case name == "MULTI":
			inMulti, queued = true, nil
		case name == "EXEC" && watched: // as if the watched key changed
			reply = "*-1\r\n"
			inMulti, watched = false, false
		case name == "EXEC":
			reply = "*" + strconv.Itoa(len(queued)) + "\r\n" + strings.Join(queued, "")
			inMulti = false
		case inMulti:
			queued = append(queued, reply)
			reply = "+QUEUED\r\n"
		}
		if _, err := io.WriteString(conn, reply); err != nil {
			return
		}
	}
}

func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil || line[0] != '*' {
		return nil, fmt.Errorf("bad command %q", line)
	}
	args := make([]string, n)
	for i := range args {
		if _, err := r.ReadString('\n'); err != nil {
			return nil, err
		}
		s, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		args[i] = strings.TrimRight(s, "\r\n")
	}
	return args, nil
}

func TestHook(t *testing.T) {
	var mu sync.Mutex
	rows := map[string]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events/server-queries" {
			data, _ := io.ReadAll(r.Body)
			var body struct{ Rows []map[string]any }
			json.Unmarshal(data, &body)
			mu.Lock()
			for _, row := range body.Rows {
				rows[row["method"].(string)+" "+row["route"].(string)+" "+row["db"].(string)+" "+row["statement"].(string)] = row
			}
			mu.Unlock()
		}
		w.WriteHeader(202)
	}))
	defer server.Close()
	p := sitegoose.New(sitegoose.Options{SiteID: "cccccccccccccccccccccccc", Secret: "s", Endpoint: server.URL,
		Disable: []string{"firewall", "errors", "inventory", "posture", "resources", "proxy", "maintenance", "analytics", "crawlers", "flags", "forms", "headers", "audit"}})
	defer p.Close(context.Background())

	rdb := redis.NewClient(&redis.Options{Addr: fakeRedis(t), Protocol: 2, DisableIndentity: true})
	defer rdb.Close()
	rdb.AddHook(Hook(p))
	var universal redis.UniversalClient = rdb // the same hook, through the interface
	bg := context.Background()

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sitegoose.SetRoute(r.Context(), "/cart")
		ctx := r.Context()
		if err := rdb.Get(ctx, "user:42:cart").Err(); !errors.Is(err, redis.Nil) {
			t.Error("the nil reply must come through", err)
		}
		if err := rdb.Set(ctx, "session:abc123", `{"user":"bob@x.com"}`, 0).Err(); err != nil {
			t.Error(err)
		}
		if err := universal.LPush(ctx, "jobs", "x").Err(); err == nil || !strings.HasPrefix(err.Error(), "WRONGTYPE") {
			t.Error("the error reply must come through", err)
		}
		if _, err := rdb.Pipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Get(ctx, "a:1")
			pipe.Set(ctx, "b:2", "v", 0)
			return nil
		}); !errors.Is(err, redis.Nil) {
			t.Error(err)
		}
		if _, err := rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Incr(ctx, "hits:9")
			return nil
		}); err != nil {
			t.Error(err)
		}
		w.WriteHeader(200)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/cart", nil))
	rdb.Set(bg, "lock:9", "1", 0)
	rdb.BLPop(bg, 0, "queue:empty") // waiting: not counted (the fake answers +OK at once)
	if err := rdb.Watch(bg, func(tx *redis.Tx) error {
		_, err := tx.TxPipelined(bg, func(pipe redis.Pipeliner) error {
			pipe.Incr(bg, "stock:7")
			return nil
		})
		return err
	}, "stock:7"); !errors.Is(err, redis.TxFailedErr) {
		t.Error("the called-off transaction must come through", err)
	}

	down := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, Protocol: 2, DisableIndentity: true})
	defer down.Close()
	down.AddHook(Hook(p))
	if err := down.Get(bg, "user:7").Err(); err == nil || errors.Is(err, redis.Nil) {
		t.Error("no connection must fail", err)
	}
	p.Flush(bg)

	mu.Lock()
	defer mu.Unlock()
	want := map[string][2]float64{
		"GET /cart redis GET user:?:cart":           {1, 0}, // a nil reply isn't a failure
		"GET /cart redis SET session:?":             {1, 0},
		"GET /cart redis LPUSH jobs":                {1, 1},
		"GET /cart redis PIPELINE GET a:?":          {1, 0},
		"GET /cart redis MULTI INCR hits:?":         {1, 0},
		"JOB (background) redis SET lock:?":         {1, 0},
		"JOB (background) redis WATCH stock:?":      {1, 0},
		"JOB (background) redis MULTI INCR stock:?": {1, 0}, // WATCH called it off: not a failure
		"JOB (background) redis UNWATCH":            {1, 0},
		"JOB (background) redis GET user:?":         {1, 1},
	}
	for key, n := range want {
		r := rows[key]
		if r == nil || r["count"] != n[0] || r["errors"] != n[1] {
			t.Errorf("%s: %v", key, r)
		}
	}
	if len(rows) != len(want) {
		t.Error(rows)
	}
}

// Every go-redis client takes the hook.
var (
	_ interface{ AddHook(redis.Hook) } = (*redis.Client)(nil)
	_ interface{ AddHook(redis.Hook) } = (*redis.ClusterClient)(nil)
	_ interface{ AddHook(redis.Hook) } = (*redis.Ring)(nil)
	_ interface{ AddHook(redis.Hook) } = redis.UniversalClient(nil)
)

// A hook with no platform, or a command it can't read, leaves the client alone.
func TestHookNeverGetsInTheWay(t *testing.T) {
	h := Hook(nil)
	cmd := redis.NewStringCmd(context.Background(), "get", "k")
	want := errors.New("boom")
	if err := h.ProcessHook(func(context.Context, redis.Cmder) error { return want })(context.Background(), cmd); err != want {
		t.Fatal(err)
	}
	if err := h.ProcessPipelineHook(func(context.Context, []redis.Cmder) error { return want })(context.Background(), nil); err != want {
		t.Fatal(err)
	}
}

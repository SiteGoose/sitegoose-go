package sitegoose

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// redis_commands in query-cases.json: the command as a client sends it ->
// its statement, or null for one that isn't timed.
func TestRedisCommandCases(t *testing.T) {
	var shared struct {
		Commands []struct {
			Args     []any   `json:"args"`
			Expected *string `json:"expected"`
		} `json:"redis_commands"`
	}
	readShared(t, "query-cases.json", &shared)
	if len(shared.Commands) == 0 {
		t.Fatal("no redis_commands")
	}
	for _, c := range shared.Commands {
		got, ok := redisCommand(c.Args)
		if c.Expected == nil {
			if ok {
				t.Errorf("%v: got %q, want not timed", c.Args, got)
			}
		} else if !ok || got != *c.Expected {
			t.Errorf("%v: got %q (%v), want %q", c.Args, got, ok, *c.Expected)
		}
	}
}

// What go-redis sends: lower-case names, []byte keys, int counts of keys.
func TestRedisCommandGoArgs(t *testing.T) {
	for _, c := range []struct {
		args []any
		want string
	}{
		{[]any{"get", []byte("user:42")}, "GET user:?"},
		{[]any{[]byte("set"), []byte{0xff, ':', 'a'}, "v"}, "SET ?:a"},
		{[]any{"eval", "return 1", 1, "lock:9"}, "EVAL lock:?"},
		{[]any{"evalsha", "abc", int64(0), "lock:9"}, "EVALSHA"},
		{[]any{"zunion", uint(2), "a:1", "b"}, "ZUNION a:?"},
		{[]any{"eval", "s", "0x1", "k"}, "EVAL k"},
		{[]any{"eval", "s", "-0x1", "k"}, "EVAL"},
		{[]any{"eval", "s", " 1e0 ", "k"}, "EVAL k"},
		{[]any{"eval", "s", 1.5, "k"}, "EVAL k"},
		{[]any{"eval", "s", time.Duration(1), "k"}, "EVAL k"},
		{[]any{"xread", "count", 1, []byte("streams"), "s:1", "0"}, "XREAD s:?"},
		{[]any{"get", 42}, "GET ?"},
	} {
		if got, ok := redisCommand(c.args); !ok || got != c.want {
			t.Errorf("%v: got %q (%v), want %q", c.args, got, ok, c.want)
		}
	}
	// ASCII only: the Kelvin sign isn't a k, so this XREAD doesn't block.
	if got, ok := redisCommand([]any{"xread", "blocK", "0", "streams", "s"}); !ok || got != "XREAD s" {
		t.Error(got, ok)
	}
	if _, ok := redisCommand([]any{"xread", []byte("block"), "0", "streams", "s"}); ok {
		t.Error("XREAD BLOCK is timed")
	}
}

func TestRecordRedis(t *testing.T) {
	c := newCollector(t)
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, ServerName: "shop-api",
		Disable: allBut(ModulePerformance)})
	t.Cleanup(func() { p.Close(context.Background()) })
	bg := context.Background()
	p.RecordRedis(bg, []any{"get", "user:42:cart"}, 2*time.Millisecond, nil)
	p.RecordRedis(bg, []any{"lpush", "jobs", "x"}, time.Millisecond, errors.New("WRONGTYPE"))
	p.RecordRedis(bg, []any{"blpop", "jobs", 0}, time.Second, nil) // waiting: not counted
	p.RecordRedis(bg, nil, time.Millisecond, nil)
	p.RecordRedis(markTimed(bg), []any{"get", "own"}, time.Millisecond, nil)
	p.RecordRedisPipeline(bg, [][]any{{"blpop", "q", 0}, {"set", "session:abc123", "v"}, {"get", "x"}}, false, 3*time.Millisecond, nil)
	p.RecordRedisPipeline(bg, [][]any{{"multi"}, {"incr", "hits:9"}, {"exec"}}, true, time.Millisecond, errors.New("EXECABORT"))
	p.RecordRedisPipeline(bg, [][]any{{"multi"}, {"exec"}}, true, time.Millisecond, nil) // nothing in it
	p.RecordRedisPipeline(bg, [][]any{{"brpop", "q", 0}}, false, time.Millisecond, nil)

	// The asynq reading's own commands: its ctx is marked, and asynq's
	// Inspector, which reads with context.Background(), by its keys.
	p.WatchQueues("asynq", "127.0.0.1:6379/0", func(ctx context.Context) ([]QueueReading, error) {
		p.RecordRedis(ctx, []any{"smembers", "asynq:queues"}, time.Millisecond, nil)
		p.RecordRedis(bg, []any{"sismember", "asynq:queues", "default"}, time.Millisecond, nil)
		p.RecordRedis(bg, []any{"evalsha", "abc", 2, "asynq:{default}:pending", "x"}, time.Millisecond, nil)
		p.RecordRedisPipeline(bg, [][]any{{"llen", "asynq:{default}:active"}}, false, time.Millisecond, nil)
		p.RecordRedis(bg, []any{"get", "app:1"}, time.Millisecond, nil) // the app's, meanwhile
		return nil, nil
	})
	p.queueRead.sample(bg)
	p.RecordRedis(bg, []any{"sismember", "asynq:queues", "default"}, time.Millisecond, nil) // the app's asynq, after
	p.Flush(bg)

	rows := queryRows(t, c)
	want := map[string][2]float64{
		"JOB (background) redis GET user:?:cart":        {1, 0},
		"JOB (background) redis LPUSH jobs":             {1, 1},
		"JOB (background) redis PIPELINE SET session:?": {1, 0},
		"JOB (background) redis MULTI INCR hits:?":      {1, 1},
		"JOB (background) redis GET app:?":              {1, 0},
		"JOB (background) redis SISMEMBER asynq:queues": {1, 0},
	}
	for key, n := range want {
		r := rows[key]
		if r == nil || r["count"] != n[0] || r["errors"] != n[1] {
			t.Errorf("%s: %v", key, r)
		}
	}
	if len(rows) != len(want) {
		var keys []string
		for k := range rows {
			keys = append(keys, k)
		}
		t.Error(strings.Join(keys, "\n"))
	}
}

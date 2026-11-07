package sitegooseasynq

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hibiken/asynq"
)

type fakeInspector struct {
	infos map[string]*asynq.QueueInfo
	fail  bool
}

func (f *fakeInspector) Queues() ([]string, error) {
	if f.fail {
		return nil, errors.New("redis: connection refused")
	}
	return []string{"emails", "broken"}, nil
}

func (f *fakeInspector) GetQueueInfo(q string) (*asynq.QueueInfo, error) {
	if info := f.infos[q]; info != nil {
		return info, nil
	}
	return nil, errors.New("no such queue")
}

func TestBroker(t *testing.T) {
	cases := map[string]asynq.RedisConnOpt{
		"127.0.0.1:6379/2":      asynq.RedisClientOpt{Addr: "127.0.0.1:6379", DB: 2, Password: "secret", Username: "u"},
		"redis.internal:6380/0": &asynq.RedisClientOpt{Addr: "user:pw@redis.internal:6380"},
		"redis.sock/1":          asynq.RedisClientOpt{Network: "unix", Addr: "/var/run/redis/redis.sock", DB: 1},
		"10.0.0.1:26379/main/0": asynq.RedisFailoverClientOpt{MasterName: "main", SentinelAddrs: []string{"10.0.0.1:26379"}, Password: "x"},
		"10.0.0.2:7000/0":       asynq.RedisClusterClientOpt{Addrs: []string{"10.0.0.2:7000", "10.0.0.3:7000"}},
		"":                      nil,
	}
	for want, opt := range cases {
		if got := Broker(opt); got != want {
			t.Errorf("%#v: got %q, want %q", opt, got, want)
		}
	}
}

func TestRead(t *testing.T) {
	info := &asynq.QueueInfo{Queue: "emails", Pending: 12, Active: 3, Scheduled: 4, Retry: 1, Archived: 2,
		Latency: 95 * time.Second, Processed: 100, Failed: 10}
	f := &fakeInspector{infos: map[string]*asynq.QueueInfo{"emails": info}}
	now := time.Date(2026, 11, 7, 23, 58, 0, 0, time.UTC)
	w := &watcher{inspector: f, last: map[string]counters{}, now: func() time.Time { return now }}

	rows, err := w.read(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	r := rows[0]
	if r.Queue != "emails" || *r.Waiting != 12 || *r.Running != 3 || *r.Delayed != 5 || *r.Failed != 2 ||
		*r.OldestS != 95 || !r.Shared || r.Added != nil || r.Finished != nil {
		t.Fatalf("first reading: %+v (no counters from one reading)", r)
	}

	// A minute on: 30 processed, 5 of them failed, 1 newly archived.
	now = now.Add(time.Minute)
	info.Processed, info.Failed, info.Archived, info.Pending = 130, 15, 3, 0
	rows, _ = w.read(context.Background())
	if r := rows[0]; r.Finished == nil || *r.Finished != 26 || *r.OldestS != 0 {
		t.Fatalf("second reading: %+v", r)
	}

	// Midnight: the daily counters start again, so nothing for this minute.
	now = now.Add(time.Minute)
	info.Processed, info.Failed = 2, 0
	rows, _ = w.read(context.Background())
	if rows[0].Finished != nil {
		t.Fatal("a counter that went down must send nothing", *rows[0].Finished)
	}
	// And after a gap the pair isn't this minute's.
	now = now.Add(10 * time.Minute)
	info.Processed = 50
	rows, _ = w.read(context.Background())
	if rows[0].Finished != nil {
		t.Fatal("a pair across a gap must send nothing")
	}

	f.fail = true
	if _, err := w.read(context.Background()); err == nil {
		t.Fatal("a failed reading is an error: a gap")
	}
}

func TestReadTotals(t *testing.T) {
	// Workers on asynq 0.24 or later keep running totals: midnight changes nothing.
	info := &asynq.QueueInfo{Queue: "emails", Pending: 1, Aggregating: 2, Processed: 900, Failed: 9,
		ProcessedTotal: 5000, FailedTotal: 50}
	f := &fakeInspector{infos: map[string]*asynq.QueueInfo{"emails": info}}
	now := time.Date(2026, 11, 7, 23, 59, 30, 0, time.UTC)
	w := &watcher{inspector: f, last: map[string]counters{}, now: func() time.Time { return now }}
	if rows, _ := w.read(context.Background()); *rows[0].Delayed != 2 {
		t.Fatal("aggregating tasks are held back: delayed", *rows[0].Delayed)
	}
	now = now.Add(time.Minute)
	info.Processed, info.Failed, info.ProcessedTotal, info.FailedTotal = 4, 1, 5020, 52
	rows, _ := w.read(context.Background())
	if r := rows[0]; r.Finished == nil || *r.Finished != 18 {
		t.Fatalf("across midnight the totals still pair: %+v", r)
	}

	// Old workers write only the day's counts: a pair across midnight sends nothing.
	info = &asynq.QueueInfo{Queue: "emails", Processed: 3}
	f.infos["emails"] = info
	w = &watcher{inspector: f, last: map[string]counters{}, now: func() time.Time { return now }}
	now = time.Date(2026, 11, 7, 23, 59, 30, 0, time.UTC)
	w.read(context.Background())
	now = now.Add(time.Minute)
	info.Processed = 5 // a new day's 5, more than the old day's 3
	if rows, _ := w.read(context.Background()); rows[0].Finished != nil {
		t.Fatal("the day's counts of two days don't pair", *rows[0].Finished)
	}
}

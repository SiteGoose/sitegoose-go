// Package sitegooseasynq reads asynq's queues once a minute for Health ->
// Server speed -> Jobs (sdk/protocols/queues.md), through asynq's own
// Inspector:
//
//	redis := asynq.RedisClientOpt{Addr: "127.0.0.1:6379"}
//	inspector := asynq.NewInspector(redis)
//	stop := sitegooseasynq.Watch(p, inspector, redis)
//	defer stop()
//
// Each queue's pending tasks are waiting, active running, scheduled, retry
// and aggregating delayed, archived failed, and its latency how long the
// oldest pending task has waited. asynq counts the tasks processed and
// failed for the whole queue; finished is the minute's succeeded tasks
// (processed less failed) plus the tasks newly archived (failed for good),
// sent as the broker's shared count, so every process watching reads the
// same and the dashboard takes one. The counts are asynq's running totals;
// where the workers are too old to keep those (before asynq 0.24), the
// day's counts, and a pair across midnight UTC sends no finished. asynq has
// no count of tasks added: added is left out. A counter that went down (the
// archive was cleared) sends no finished for that minute, and a reading
// that fails sends nothing: a gap, never a zero.
//
// The Redis is named by host, port and database ("127.0.0.1:6379/0"),
// never its user name or password. It is in a module of its own so the
// platform package needs nothing but the standard library.
package sitegooseasynq

import (
	"context"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hibiken/asynq"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

// Inspector is what is read: *asynq.Inspector has both.
type Inspector interface {
	Queues() ([]string, error)
	GetQueueInfo(queue string) (*asynq.QueueInfo, error)
}

// A counter pair further apart than this is from before a gap (the module
// off, a reading that failed): its difference isn't this minute's.
const maxPair = 150 * time.Second

// Watch reads inspector's queues once a minute until the function it gives
// back is called. redis is the connection the inspector was made with, and
// only names where the queues live.
func Watch(p *sitegoose.Platform, inspector Inspector, redis asynq.RedisConnOpt) (stop func()) {
	if p == nil || inspector == nil {
		return func() {}
	}
	w := &watcher{inspector: inspector, last: map[string]counters{}, now: time.Now}
	return p.WatchQueues("asynq", Broker(redis), w.read)
}

// Broker is where redis points, host, port and database, with no user name
// or password: "127.0.0.1:6379/0", a socket's file name, a Sentinel's first
// address and master, a cluster's first node. "" when it can't say.
func Broker(redis asynq.RedisConnOpt) string {
	switch o := redis.(type) {
	case asynq.RedisClientOpt:
		return clientBroker(o.Network, o.Addr, o.DB)
	case *asynq.RedisClientOpt:
		if o != nil {
			return clientBroker(o.Network, o.Addr, o.DB)
		}
	case asynq.RedisFailoverClientOpt:
		return failoverBroker(o.SentinelAddrs, o.MasterName, o.DB)
	case *asynq.RedisFailoverClientOpt:
		if o != nil {
			return failoverBroker(o.SentinelAddrs, o.MasterName, o.DB)
		}
	case asynq.RedisClusterClientOpt:
		return clusterBroker(o.Addrs)
	case *asynq.RedisClusterClientOpt:
		if o != nil {
			return clusterBroker(o.Addrs)
		}
	}
	return ""
}

// hostOnly drops anything before an "@" and anything that isn't part of
// host:port.
func hostOnly(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		addr = addr[i+1:]
	}
	return strings.Map(func(c rune) rune {
		if c <= ' ' || c == '/' || c == 0x7f {
			return -1
		}
		return c
	}, addr)
}

func clientBroker(network, addr string, db int) string {
	if network == "unix" {
		name := path.Base(addr)
		if len(name) > 80 {
			name = name[:80]
		}
		return name + "/" + strconv.Itoa(db)
	}
	addr = hostOnly(addr)
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	return addr + "/" + strconv.Itoa(db)
}

func failoverBroker(sentinels []string, master string, db int) string {
	if len(sentinels) == 0 {
		return ""
	}
	return hostOnly(sentinels[0]) + "/" + hostOnly(master) + "/" + strconv.Itoa(db)
}

func clusterBroker(addrs []string) string {
	if len(addrs) == 0 {
		return ""
	}
	return hostOnly(addrs[0]) + "/0"
}

// counters are one queue's processed and failed counts and archive at a
// reading: running totals, or the day's when daily is set.
type counters struct {
	processed, failed, archived int64
	daily                       bool
	at                          time.Time
}

// countersOf takes asynq's running totals, which never start again at
// midnight. Workers older than asynq 0.24 write only the day's, leaving the
// totals at 0 while the day's count up: then those are what there is.
func countersOf(info *asynq.QueueInfo, at time.Time) counters {
	c := counters{processed: int64(info.ProcessedTotal), failed: int64(info.FailedTotal), archived: int64(info.Archived), at: at}
	if info.ProcessedTotal == 0 && info.Processed > 0 {
		c = counters{processed: int64(info.Processed), failed: int64(info.Failed), archived: int64(info.Archived), daily: true, at: at}
	}
	return c
}

type watcher struct {
	inspector Inspector
	mu        sync.Mutex
	last      map[string]counters
	now       func() time.Time
}

func gauge(n int) *int64 {
	v := int64(n)
	if v < 0 {
		v = 0
	}
	return &v
}

// read is one reading of every queue: a queue whose info fails is left out.
func (w *watcher) read(context.Context) ([]sitegoose.QueueReading, error) {
	names, err := w.inspector.Queues()
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	seen := map[string]bool{}
	var out []sitegoose.QueueReading
	for _, name := range names {
		info, err := w.inspector.GetQueueInfo(name)
		if err != nil || info == nil {
			continue
		}
		seen[name] = true
		now := w.now()
		oldest := int64(info.Latency / time.Second)
		if info.Pending == 0 || oldest < 0 {
			oldest = 0
		}
		r := sitegoose.QueueReading{
			Queue:   name,
			Waiting: gauge(info.Pending),
			Running: gauge(info.Active),
			Delayed: gauge(info.Scheduled + info.Retry + info.Aggregating),
			Failed:  gauge(info.Archived),
			OldestS: &oldest,
			Shared:  true,
		}
		cur := countersOf(info, now)
		if before, ok := w.last[name]; ok && now.Sub(before.at) <= maxPair {
			r.Finished = finished(before, cur)
		}
		w.last[name] = cur
		out = append(out, r)
	}
	// Queues that went away don't keep their counts.
	for name := range w.last {
		if !seen[name] {
			delete(w.last, name)
		}
	}
	return out, nil
}

// finished is the tasks that left the queue between two readings: the ones
// that succeeded and the ones newly archived. nil when a counter went down,
// when the two readings count differently, or when the day's counts of two
// different days would be compared.
func finished(before, after counters) *int64 {
	if before.daily != after.daily {
		return nil
	}
	if after.daily {
		y1, m1, d1 := before.at.UTC().Date()
		y2, m2, d2 := after.at.UTC().Date()
		if y1 != y2 || m1 != m2 || d1 != d2 {
			return nil
		}
	}
	processed := after.processed - before.processed
	failed := after.failed - before.failed
	archived := after.archived - before.archived
	if processed < 0 || failed < 0 || archived < 0 || failed > processed {
		return nil
	}
	n := processed - failed + archived
	return &n
}

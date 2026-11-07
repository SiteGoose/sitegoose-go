package sitegoose

// Job queues (sdk/protocols/queues.md): how many jobs wait, run, are delayed
// or kept as failed, how long the oldest has waited, and how many were added
// and finished, read once a minute and sent at once to POST
// /events/server-queues, for Health -> Server speed -> Jobs. The reading
// itself is the queue library's: p.WatchQueues takes a function that reads
// one broker's queues (the asynq submodule is one). Readings run in the
// background, never in a request, each given readTimeout; one that fails or
// takes longer sends nothing for that minute: a gap, never a zero. Rides on
// the performance module's switch; PerformanceOptions.DisableQueues leaves
// them out.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// queueReadWait is how long one reading may take (a var for the tests).
var queueReadWait = 10 * time.Second

const (
	queueEvery      = 60 * time.Second
	maxQueueReaders = 20
	maxQueuesRead   = 100 // queues one reader's reading keeps
)

var queueSystems = map[string]bool{"bullmq": true, "bull": true, "sidekiq": true, "laravel": true, "celery": true,
	"rq": true, "hangfire": true, "asynq": true, "rabbitmq": true, "other": true}

// QueueReading is one queue as read now. A nil field is one the system
// can't say, sent as null: never fill one in with 0.
type QueueReading struct {
	// Queue is the queue's name.
	Queue string
	// Waiting, Running, Delayed and Failed are what the queue holds now
	// (Failed: the jobs kept as failed, not this minute's failures).
	Waiting, Running, Delayed, Failed *int64
	// OldestS is how many seconds the oldest waiting job has waited; 0 with
	// nothing waiting.
	OldestS *int64
	// Added and Finished are the jobs added and finished (done, or failed
	// for good) since the last reading.
	Added, Finished *int64
	// Shared: Added and Finished are the broker's counts for the whole
	// queue, which every process reads alike, not this process's own.
	Shared bool
}

// QueueReader reads the queues of one broker. It is called once a minute in
// the background; an error sends nothing for that minute.
type QueueReader func(ctx context.Context) ([]QueueReading, error)

type queueReader struct {
	system, broker string
	read           QueueReader
	busy           bool // a reading that hasn't come back yet
	stopped        bool
}

type queueWatch struct {
	core       *core
	serverName string
	// sender is this process, so the collector can tell a reading resent
	// after a failed answer from another process's with the same counts.
	sender  string
	mu      sync.Mutex
	readers []*queueReader
	job     *periodic
	started sync.Once
	now     func() time.Time
}

func newQueueWatch(c *core, perf *performance) *queueWatch {
	id := make([]byte, 8)
	rand.Read(id)
	return &queueWatch{core: c, serverName: perf.serverName, sender: hex.EncodeToString(id), now: time.Now}
}

// WatchQueues reads system's queues on broker once a minute with read, for
// Health -> Server speed -> Jobs. system is "asynq", "rabbitmq"... (anything
// else is "other"); broker is where the queues live, host, port and
// database ("127.0.0.1:6379/0"), never a user name or password. The function
// it gives back stops the readings. For a library of your own; asynq has
// its own module (github.com/sitegoose/sitegoose-go/asynq).
func (p *Platform) WatchQueues(system, broker string, read QueueReader) (stop func()) {
	stop = func() {}
	if p == nil || p.queueRead == nil || read == nil {
		return stop
	}
	return p.queueRead.watch(system, broker, read)
}

func (q *queueWatch) watch(system, broker string, read QueueReader) func() {
	system = strings.ToLower(strings.TrimSpace(system))
	if !queueSystems[system] {
		system = "other"
	}
	broker = cleanBroker(broker)
	if broker == "" {
		q.core.log("performance", "WatchQueues: no broker to name the queues by; not watched")
		return func() {}
	}
	r := &queueReader{system: system, broker: broker, read: read}
	q.mu.Lock()
	if len(q.readers) >= maxQueueReaders {
		q.mu.Unlock()
		q.core.log("performance", "WatchQueues: already reading %d brokers; this one isn't", maxQueueReaders)
		return func() {}
	}
	q.readers = append(q.readers, r)
	q.mu.Unlock()
	q.started.Do(func() {
		job := q.core.every(queueEvery, func() time.Duration {
			q.sample(context.Background())
			return queueEvery
		})
		q.mu.Lock()
		q.job = job
		q.mu.Unlock()
	})
	return func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		r.stopped = true
		for i, x := range q.readers {
			if x == r {
				q.readers = append(q.readers[:i], q.readers[i+1:]...)
				break
			}
		}
	}
}

// cleanBroker keeps host, port and database: a scheme, anything before an
// "@" (a user and password) and a query string are dropped.
func cleanBroker(broker string) string {
	broker = strings.TrimSpace(broker)
	if i := strings.Index(broker, "://"); i >= 0 {
		broker = broker[i+3:]
	}
	if i := strings.LastIndex(broker, "@"); i >= 0 {
		broker = broker[i+1:]
	}
	// A query string or fragment can carry a password too (?password=...).
	if i := strings.IndexAny(broker, "?#"); i >= 0 {
		broker = broker[:i]
	}
	broker = strings.Map(func(c rune) rune {
		if c <= ' ' || c == 0x7f {
			return -1
		}
		return c
	}, broker)
	return truncate(broker, 200)
}

// readWithin runs one reading, giving up after queueReadWait: a broker that
// doesn't answer is a gap, and is left to come back before it is read again.
func (q *queueWatch) readWithin(ctx context.Context, r *queueReader) ([]QueueReading, bool) {
	q.mu.Lock()
	if r.busy || r.stopped {
		q.mu.Unlock()
		return nil, false
	}
	r.busy = true
	q.mu.Unlock()
	type result struct {
		rows []QueueReading
		err  error
	}
	ctx, cancel := context.WithTimeout(ctx, queueReadWait)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		var res result
		defer func() {
			if rec := recover(); rec != nil {
				q.core.log("performance", "a queue reading panicked: %v", rec)
				res = result{}
			}
			q.mu.Lock()
			r.busy = false
			q.mu.Unlock()
			done <- res
		}()
		res.rows, res.err = r.read(ctx)
	}()
	select {
	case res := <-done:
		if res.err != nil {
			q.core.log("performance", "could not read the %s queues on %s: %v", r.system, r.broker, res.err)
			return nil, false
		}
		return res.rows, true
	case <-ctx.Done():
		q.core.log("performance", "the %s queues on %s didn't answer in time", r.system, r.broker)
		return nil, false
	}
}

func optInt(v *int64) any {
	if v == nil {
		return nil
	}
	if *v < 0 {
		return int64(0)
	}
	return *v
}

// sample reads every broker watched and sends a row per queue at once.
func (q *queueWatch) sample(ctx context.Context) {
	if !q.core.isOn(ModulePerformance) {
		return
	}
	q.mu.Lock()
	readers := append([]*queueReader(nil), q.readers...)
	q.mu.Unlock()
	minute := isoMinute(time.Unix(q.now().Unix()/60*60, 0))
	// Every broker at once: one that doesn't answer costs the others nothing,
	// and a reading never runs into the next minute's.
	results := make([][]QueueReading, len(readers))
	var wg sync.WaitGroup
	for i, r := range readers {
		wg.Add(1)
		go func(i int, r *queueReader) {
			defer wg.Done()
			if readings, ok := q.readWithin(ctx, r); ok {
				results[i] = readings
			}
		}(i, r)
	}
	wg.Wait()
	var rows []map[string]any
	for i, r := range readers {
		readings := results[i]
		seen := map[string]bool{}
		for _, x := range readings {
			name := truncate(strings.TrimSpace(x.Queue), 200)
			if name == "" || seen[name] || len(seen) >= maxQueuesRead {
				continue
			}
			seen[name] = true
			row := map[string]any{"minute": minute, "system": r.system, "broker": r.broker, "queue": name,
				"waiting": optInt(x.Waiting), "running": optInt(x.Running), "delayed": optInt(x.Delayed),
				"failed": optInt(x.Failed), "oldest_s": optInt(x.OldestS), "added": optInt(x.Added),
				"finished": optInt(x.Finished), "shared": x.Shared}
			empty := true
			for _, k := range []string{"waiting", "running", "delayed", "failed", "oldest_s", "added", "finished"} {
				empty = empty && row[k] == nil
			}
			if !empty {
				rows = append(rows, row)
			}
		}
	}
	inChunks(rows, func(part []map[string]any) {
		q.core.send(ctx, "performance", "/events/server-queues", http.MethodPost, map[string]any{
			"site_id": q.core.siteID, "server_name": q.serverName, "runtime": runtimeName(), "sender": q.sender,
			"rows": part,
		}, authBearer, nil)
	})
}

func (q *queueWatch) close(ctx context.Context) {
	q.mu.Lock()
	job := q.job
	q.mu.Unlock()
	job.halt(ctx)
}

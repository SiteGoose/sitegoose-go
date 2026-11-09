package sitegoose

// Database queries (sdk/protocols/queries.md): the half of Server speed that
// says why a route is slow. Every query the app runs through a hook (OpenDB,
// WrapConnector, WrapDriver, the pgx and Mongo hooks, or RecordQuery) has
// its values taken out (querytext.go) and is added to the request its ctx
// belongs to; when that request finishes, its queries join the minute's rows
// under the method and route Server speed counted it under. A query whose
// ctx belongs to no request (context.Background()) is JOB "(background)",
// and one inside p.Job is that job's. One row per minute, method, route,
// database and statement goes to POST /events/server-queries, as Server
// speed sends its own. On with the performance module, unless
// PerformanceOptions.DisableQueries.
//
// Outgoing HTTP calls (sdk/protocols/calls.md, calls.go) are filed the same
// way by this same code, keyed by call method and host in place of database
// and statement, and go to POST /events/server-calls.

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxRequestStatements = 50  // distinct statements one request keeps; then (other)
	maxMinuteStatements  = 200 // keys one minute keeps; then (other)
	maxMinuteKeys        = 300 // past this nothing new is kept
	// Minutes held unsent: the flush takes them every 60 seconds, but with no
	// flush running (credentials missing, after Close) the oldest goes, so
	// the rows can't grow without end.
	maxHeldMinutes  = 5
	backgroundRoute = "(background)"
)

// defaultPlatform is the one New made last: OpenDB and the other package
// functions count queries outside any request there.
var defaultPlatform atomic.Pointer[Platform]

type queryStat struct {
	count   int64
	errors  int64
	sumMS   float64
	maxMS   float64
	buckets []int64
}

func newQueryStat() *queryStat { return &queryStat{buckets: make([]int64, len(bucketEdgesMS)+1)} }

func (s *queryStat) add(ms float64, failed bool) {
	s.count++
	if failed {
		s.errors++
	}
	s.sumMS += ms
	if ms > s.maxMS {
		s.maxMS = ms
	}
	s.buckets[bucketOf(ms)]++
}

func (s *queryStat) merge(o *queryStat) {
	s.count += o.count
	s.errors += o.errors
	s.sumMS += o.sumMS
	if o.maxMS > s.maxMS {
		s.maxMS = o.maxMS
	}
	for i, n := range o.buckets {
		s.buckets[i] += n
	}
}

// queryStatKey is a query's database and statement, or a call's method and
// host: the second is the one a capped key folds into "(other)".
type queryStatKey struct{ a, b string }

// timingKind is what a queries value files: database queries or outgoing
// calls, their endpoint and the names of their two key fields.
type timingKind struct {
	path   string
	fields [2]string
	// of is the request's own map of this kind.
	of func(st *reqState) *requestQueries
}

var (
	queriesKind = timingKind{path: "/events/server-queries", fields: [2]string{"db", "statement"},
		of: func(st *reqState) *requestQueries { return &st.queries }}
	callsKind = timingKind{path: "/events/server-calls", fields: [2]string{"call_method", "host"},
		of: func(st *reqState) *requestQueries { return &st.calls }}
)

// requestQueries are the queries (or calls) one request (or job) ran, until it finishes.
type requestQueries struct {
	mu    sync.Mutex
	stats map[queryStatKey]*queryStat
	done  bool
	// The method and route it was counted under, for a query its ctx runs
	// after it finished (a goroutine it started).
	method string
	route  string
}

type queryRowKey struct{ method, route, a, b string }

type queries struct {
	core       *core
	kind       timingKind
	serverName string
	mu         sync.Mutex
	rows       map[int64]map[queryRowKey]*queryStat // by minute
	job        *periodic
	now        func() time.Time
}

func newTimings(c *core, perf *performance, kind timingKind) *queries {
	q := &queries{core: c, kind: kind, serverName: perf.serverName, rows: map[int64]map[queryRowKey]*queryStat{}, now: time.Now}
	q.job = c.every(performanceFlush, func() time.Duration {
		q.flush(context.Background(), false)
		return performanceFlush
	})
	return q
}

// timedKey marks a ctx whose query an outer hook is already timing: a hook
// underneath (pgx's tracer under database/sql) leaves it alone.
type timedKey struct{}

func markTimed(ctx context.Context) context.Context { return context.WithValue(ctx, timedKey{}, true) }

func timedOutside(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	on, _ := ctx.Value(timedKey{}).(bool)
	return on
}

// RecordQuery counts one database query the app ran, for a database library
// this package has no hook for: db is "postgresql", "mysql", "mariadb",
// "sqlite", "mssql", "oracle", "clickhouse" or "mongodb" (anything else is
// "other"; Redis commands go through RecordRedis), and
// statement the query as run. Its values are taken out here, before it is
// counted; bound parameters are never asked for. ctx is the one the query
// was given: the request (or p.Job) it belongs to, else it counts as a
// background query. err is the query's error, nil when it worked.
func (p *Platform) RecordQuery(ctx context.Context, db, statement string, d time.Duration, err error) {
	if p == nil || p.queries == nil || timedOutside(ctx) {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.core.log("performance", "could not count a query: %v", r)
		}
	}()
	if !p.core.isOn(ModulePerformance) {
		return
	}
	db = databaseOf(db)
	statement = normalizeStatement(statement, db)
	if statement == "" {
		return
	}
	p.queries.record(ctx, p, db, statement, float64(d)/float64(time.Millisecond), err != nil)
}

// RecordRedis counts one Redis command the app ran, as database "redis":
// args is the command as sent to the server (["SET", "session:abc", value,
// "EX", 60]), of which only the name, a subcommand and the first key's shape
// are kept ("SET session:?"), never a value. Strings and []byte are read;
// anything else is a value. Blocking commands (BLPOP, XREAD BLOCK...) wait
// rather than work and aren't counted. err is an error reply or no answer
// (a connection error, a timeout); a nil reply is an answer, so pass nil for
// it. The redis submodule does this for go-redis.
func (p *Platform) RecordRedis(ctx context.Context, args []any, d time.Duration, err error) {
	if p == nil || p.queries == nil || timedOutside(ctx) {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.core.log("performance", "could not count a Redis command: %v", r)
		}
	}()
	if !p.core.isOn(ModulePerformance) {
		return
	}
	statement, ok := redisCommand(args)
	if !ok || p.ownRedis(statement) {
		return
	}
	p.queries.record(ctx, p, "redis", cutStatement(statement), float64(d)/float64(time.Millisecond), err != nil)
}

// RecordRedisPipeline counts commands sent together as one call, for the
// whole round trip: "PIPELINE " and the statement of the first command
// RecordRedis would count, or with transaction "MULTI " (the MULTI and EXEC
// around the commands are passed over). err is the round trip's error or
// any command's error reply. A pipeline of nothing but blocking commands
// isn't counted.
func (p *Platform) RecordRedisPipeline(ctx context.Context, cmds [][]any, transaction bool, d time.Duration, err error) {
	if p == nil || p.queries == nil || timedOutside(ctx) {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.core.log("performance", "could not count a Redis pipeline: %v", r)
		}
	}()
	if !p.core.isOn(ModulePerformance) {
		return
	}
	prefix := "PIPELINE "
	if transaction {
		prefix = "MULTI "
	}
	for _, args := range cmds {
		statement, ok := redisCommand(args)
		if !ok || (transaction && (statement == "MULTI" || statement == "EXEC")) {
			continue
		}
		if p.ownRedis(statement) {
			return
		}
		p.queries.record(ctx, p, "redis", cutStatement(prefix+statement), float64(d)/float64(time.Millisecond), err != nil)
		return
	}
}

// ownRedis: a command of asynq's Inspector while this package reads the
// queues through it. The Inspector reads with context.Background(), so the
// reading's marked ctx can't reach a hook on the app's own client; its keys
// all start "asynq:". An app's own asynq command in those few milliseconds
// a minute goes uncounted too.
func (p *Platform) ownRedis(statement string) bool {
	return p.queueRead != nil && p.queueRead.asynqReading.Load() > 0 && strings.Contains(statement, " asynq:")
}

// record files one query (a: database, b: statement) or call (a: call
// method, b: host) under the request ctx belongs to.
func (q *queries) record(ctx context.Context, p *Platform, a, b string, ms float64, failed bool) {
	if !q.core.isOn(ModulePerformance) {
		return
	}
	if ms < 0 {
		ms = 0
	}
	method, route := "JOB", backgroundRoute
	if st := stateFrom(ctx); st != nil && st.platform == p {
		rq := q.kind.of(st)
		rq.mu.Lock()
		if !rq.done {
			key := queryStatKey{a, b}
			if rq.stats == nil {
				rq.stats = map[queryStatKey]*queryStat{}
			}
			if _, ok := rq.stats[key]; !ok && len(rq.stats) >= maxRequestStatements {
				key.b = otherStatement
			}
			s := rq.stats[key]
			if s == nil {
				s = newQueryStat()
				rq.stats[key] = s
			}
			s.add(ms, failed)
			rq.mu.Unlock()
			return
		}
		method, route = rq.method, rq.route
		rq.mu.Unlock()
	}
	s := newQueryStat()
	s.add(ms, failed)
	q.mu.Lock()
	q.addLocked(q.now().Unix()/60*60, queryRowKey{method, route, a, b}, s)
	q.mu.Unlock()
}

// addLocked adds s into a minute's rows: past maxMinuteStatements keys a new
// statement is (other), past maxMinuteKeys nothing new is kept.
func (q *queries) addLocked(minute int64, key queryRowKey, s *queryStat) {
	rows := q.rows[minute]
	if rows == nil {
		for len(q.rows) >= maxHeldMinutes {
			oldest := minute
			for m := range q.rows {
				if m < oldest {
					oldest = m
				}
			}
			if oldest == minute {
				return
			}
			delete(q.rows, oldest)
		}
		rows = map[queryRowKey]*queryStat{}
		q.rows[minute] = rows
	}
	if _, ok := rows[key]; !ok && len(rows) >= maxMinuteStatements {
		key.b = otherStatement
		if _, ok := rows[key]; !ok && len(rows) >= maxMinuteKeys {
			return
		}
	}
	row := rows[key]
	if row == nil {
		row = newQueryStat()
		rows[key] = row
	}
	row.merge(s)
}

// endQueries adds a finished request's (or job's) queries and calls into
// the minute's rows, under the method and route it was counted under:
// method "" works them out as Server speed does.
func (p *Platform) endQueries(st *reqState, method, route string, status int) {
	if p == nil || st == nil || (p.queries == nil && p.calls == nil) {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.core.log("performance", "could not count a request's queries: %v", r)
		}
	}()
	if method == "" {
		method, route = perfName(st.method, st.routeName(), status, st.path)
	}
	p.queries.end(st, method, route)
	p.calls.end(st, method, route)
}

func (q *queries) end(st *reqState, method, route string) {
	if q == nil {
		return
	}
	rq := q.kind.of(st)
	rq.mu.Lock()
	stats := rq.stats
	rq.stats, rq.done, rq.method, rq.route = nil, true, method, route
	rq.mu.Unlock()
	if len(stats) == 0 {
		return
	}
	minute := q.now().Unix() / 60 * 60
	q.mu.Lock()
	defer q.mu.Unlock()
	for k, s := range stats {
		q.addLocked(minute, queryRowKey{method, route, k.a, k.b}, s)
	}
}

// flush sends finished minutes (everything: the current one too).
func (q *queries) flush(ctx context.Context, everything bool) {
	current := q.now().Unix() / 60 * 60
	q.mu.Lock()
	var rows []map[string]any
	for minute, keys := range q.rows {
		if !everything && minute >= current {
			continue
		}
		delete(q.rows, minute)
		for k, v := range keys {
			rows = append(rows, map[string]any{
				"minute": isoMinute(time.Unix(minute, 0)), "method": k.method, "route": k.route, q.kind.fields[0]: k.a,
				q.kind.fields[1]: k.b, "count": v.count, "errors": v.errors, "sum_ms": round1(v.sumMS),
				"max_ms": round1(v.maxMS), "buckets": v.buckets,
			})
		}
	}
	q.mu.Unlock()
	inChunks(rows, func(part []map[string]any) {
		q.core.send(ctx, "performance", q.kind.path, http.MethodPost, map[string]any{
			"site_id": q.core.siteID, "server_name": q.serverName, "runtime": runtimeName(), "rows": part,
		}, authBearer, nil)
	})
}

func (q *queries) close(ctx context.Context) {
	q.job.halt(ctx)
	q.flush(ctx, true)
}

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

import (
	"context"
	"net/http"
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

type queryStatKey struct{ db, statement string }

// requestQueries are the queries one request (or job) ran, until it finishes.
type requestQueries struct {
	mu    sync.Mutex
	stats map[queryStatKey]*queryStat
	done  bool
	// The method and route it was counted under, for a query its ctx runs
	// after it finished (a goroutine it started).
	method string
	route  string
}

type queryRowKey struct{ method, route, db, statement string }

type queries struct {
	core       *core
	serverName string
	mu         sync.Mutex
	rows       map[int64]map[queryRowKey]*queryStat // by minute
	job        *periodic
	now        func() time.Time
}

func newQueries(c *core, perf *performance) *queries {
	q := &queries{core: c, serverName: perf.serverName, rows: map[int64]map[queryRowKey]*queryStat{}, now: time.Now}
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
// "sqlite", "mssql", "oracle" or "mongodb" (anything else is "other"), and
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
	p.queries.record(ctx, p, db, statement, float64(d)/float64(time.Millisecond), err != nil)
}

func (q *queries) record(ctx context.Context, p *Platform, db, statement string, ms float64, failed bool) {
	if !q.core.isOn(ModulePerformance) {
		return
	}
	db = databaseOf(db)
	statement = normalizeStatement(statement, db)
	if statement == "" {
		return
	}
	if ms < 0 {
		ms = 0
	}
	method, route := "JOB", backgroundRoute
	if st := stateFrom(ctx); st != nil && st.platform == p {
		rq := &st.queries
		rq.mu.Lock()
		if !rq.done {
			key := queryStatKey{db, statement}
			if rq.stats == nil {
				rq.stats = map[queryStatKey]*queryStat{}
			}
			if _, ok := rq.stats[key]; !ok && len(rq.stats) >= maxRequestStatements {
				key.statement = otherStatement
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
	q.addLocked(q.now().Unix()/60*60, queryRowKey{method, route, db, statement}, s)
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
		key.statement = otherStatement
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

// endQueries adds a finished request's (or job's) queries into the minute's
// rows, under the method and route it was counted under: method "" works
// them out as Server speed does.
func (p *Platform) endQueries(st *reqState, method, route string, status int) {
	if p == nil || p.queries == nil || st == nil {
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
	rq := &st.queries
	rq.mu.Lock()
	stats := rq.stats
	rq.stats, rq.done, rq.method, rq.route = nil, true, method, route
	rq.mu.Unlock()
	if len(stats) == 0 {
		return
	}
	q := p.queries
	minute := q.now().Unix() / 60 * 60
	q.mu.Lock()
	defer q.mu.Unlock()
	for k, s := range stats {
		q.addLocked(minute, queryRowKey{method, route, k.db, k.statement}, s)
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
				"minute": isoMinute(time.Unix(minute, 0)), "method": k.method, "route": k.route, "db": k.db,
				"statement": k.statement, "count": v.count, "errors": v.errors, "sum_ms": round1(v.sumMS),
				"max_ms": round1(v.maxMS), "buckets": v.buckets,
			})
		}
	}
	q.mu.Unlock()
	for i := 0; i < len(rows); i += maxRows {
		end := i + maxRows
		if end > len(rows) {
			end = len(rows)
		}
		q.core.send(ctx, "performance", "/events/server-queries", http.MethodPost, map[string]any{
			"site_id": q.core.siteID, "server_name": q.serverName, "runtime": runtimeName(), "rows": rows[i:end],
		}, authBearer, nil)
	}
}

func (q *queries) close(ctx context.Context) {
	q.job.halt(ctx)
	q.flush(ctx, true)
}

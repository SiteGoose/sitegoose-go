// Package sitegoosepgx times the queries pgx v5 runs, for Server speed ->
// Queries, through pgx's own tracer hook:
//
//	config, _ := pgxpool.ParseConfig(dsn)
//	config.ConnConfig.Tracer = sitegoosepgx.Tracer(p)
//	pool, _ := pgxpool.NewWithConfig(ctx, config)
//
// A query counts under the request its ctx belongs to (pool.Query(r.Context(), ...)),
// else as a background query. Queries, batches (each query in one) and
// CopyFrom are timed; a query is timed until its rows are closed, as pgx
// traces it. Through database/sql (pgx's stdlib) wrapped by sitegoose.OpenDB,
// the wrapper counts each query and this tracer leaves it alone.
//
// It is in a module of its own so the platform package needs nothing but
// the standard library. A tracer of your own as well: pgx's multitracer.
package sitegoosepgx

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

// QueryTracer is pgx's tracer: pgx.QueryTracer, pgx.BatchTracer and
// pgx.CopyFromTracer.
type QueryTracer struct {
	p *sitegoose.Platform
}

var (
	_ pgx.QueryTracer    = (*QueryTracer)(nil)
	_ pgx.BatchTracer    = (*QueryTracer)(nil)
	_ pgx.CopyFromTracer = (*QueryTracer)(nil)
)

// Tracer is the tracer to set as pgx.ConnConfig.Tracer.
func Tracer(p *sitegoose.Platform) *QueryTracer { return &QueryTracer{p: p} }

type started struct {
	at  time.Time
	sql string
}

type startedKey struct{}

type batch struct {
	mu   sync.Mutex
	last time.Time
}

type batchKey struct{}

// failed: the query's error, but not "no rows", which is an answer.
func failed(err error) error {
	if err == nil || errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

func (t *QueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, startedKey{}, started{at: time.Now(), sql: data.SQL})
}

func (t *QueryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	t.end(ctx, data.Err)
}

// end counts the query (or copy) the start hook put in ctx.
func (t *QueryTracer) end(ctx context.Context, err error) {
	if s, ok := ctx.Value(startedKey{}).(started); ok {
		t.p.RecordQuery(ctx, "postgresql", s.sql, time.Since(s.at), failed(err))
	}
}

func (t *QueryTracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return context.WithValue(ctx, batchKey{}, &batch{last: time.Now()})
}

// TraceBatchQuery: each query's time is from the one before it (or the
// batch's start), as their results are read in turn.
func (t *QueryTracer) TraceBatchQuery(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchQueryData) {
	b, ok := ctx.Value(batchKey{}).(*batch)
	if !ok {
		return
	}
	now := time.Now()
	b.mu.Lock()
	d := now.Sub(b.last)
	b.last = now
	b.mu.Unlock()
	t.p.RecordQuery(ctx, "postgresql", data.SQL, d, failed(data.Err))
}

func (t *QueryTracer) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

func (t *QueryTracer) TraceCopyFromStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceCopyFromStartData) context.Context {
	return context.WithValue(ctx, startedKey{}, started{at: time.Now(), sql: "COPY " + data.TableName.Sanitize() + " FROM STDIN"})
}

func (t *QueryTracer) TraceCopyFromEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceCopyFromEndData) {
	t.end(ctx, data.Err)
}

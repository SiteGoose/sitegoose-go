// Package sitegooseclickhouse times the queries clickhouse-go v2's native
// API runs, for Server speed -> Queries, by wrapping the driver.Conn you
// already have:
//
//	conn, err := clickhouse.Open(&clickhouse.Options{Addr: []string{"127.0.0.1:9000"}})
//	conn = sitegooseclickhouse.Wrap(p, conn)
//
// Query is timed until its rows are closed (or read to the end), QueryRow
// until its Scan (no row is not a failure), Select, Exec and AsyncInsert
// until they answer, and a batch as the waits on the server it is made of:
// PrepareBatch, each Flush and Send, counted once when Send answers. A batch
// aborted isn't counted. A query counts under the request its ctx belongs to
// (conn.Query(r.Context(), ...)), else as a background query. Its values are
// taken out before it is counted, and bound parameters are never read.
//
// Only the driver's public interface is used: the wrapper embeds the
// driver.Conn it is given, so every method this package doesn't time
// (including ones newer versions of the driver add) goes straight to it.
// Through database/sql (clickhouse.OpenDB, sql.Open("clickhouse", ...))
// wrap with sitegoose.OpenDB or WrapConnector instead.
//
// It is in a module of its own so the platform package needs nothing but
// the standard library.
package sitegooseclickhouse

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

const db = "clickhouse"

// Conn is a driver.Conn whose queries are timed.
type Conn struct {
	driver.Conn
	p *sitegoose.Platform
}

var _ driver.Conn = (*Conn)(nil)

// Wrap gives conn back with its queries timed on p. A conn already wrapped
// is given back as it is; nil stays nil.
func Wrap(p *sitegoose.Platform, conn driver.Conn) driver.Conn {
	if conn == nil {
		return nil
	}
	if w, ok := conn.(*Conn); ok {
		return w
	}
	return &Conn{Conn: conn, p: p}
}

// Unwrap is the driver's own connection.
func (c *Conn) Unwrap() driver.Conn { return c.Conn }

func (c *Conn) record(ctx context.Context, query string, started time.Time, err error) {
	c.p.RecordQuery(ctx, db, query, time.Since(started), err)
}

// countOnce is a query's count, made at most once whichever way it ends.
type countOnce struct {
	done sync.Once
	end  func(error)
}

func (o *countOnce) finish(err error) { o.done.Do(func() { o.end(err) }) }

func (o *countOnce) drop() { o.done.Do(func() {}) }

func (c *Conn) Select(ctx context.Context, dest any, query string, args ...any) error {
	started := time.Now()
	err := c.Conn.Select(ctx, dest, query, args...)
	c.record(ctx, query, started, err)
	return err
}

func (c *Conn) Query(ctx context.Context, query string, args ...any) (driver.Rows, error) {
	started := time.Now()
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil || rows == nil {
		c.record(ctx, query, started, err)
		return rows, err
	}
	return &Rows{Rows: rows, once: countOnce{end: func(err error) { c.record(ctx, query, started, err) }}}, nil
}

// QueryRow answers once the server has begun its answer; the row itself
// comes with Scan, which is when it is counted. One that failed straight
// away is counted then.
func (c *Conn) QueryRow(ctx context.Context, query string, args ...any) driver.Row {
	started := time.Now()
	row := c.Conn.QueryRow(ctx, query, args...)
	if row == nil || row.Err() != nil {
		var err error
		if row != nil {
			err = row.Err()
		}
		c.record(ctx, query, started, err)
		return row
	}
	return &Row{Row: row, once: countOnce{end: func(err error) {
		if errors.Is(err, sql.ErrNoRows) {
			err = nil // no row is an answer, not a failure
		}
		c.record(ctx, query, started, err)
	}}}
}

func (c *Conn) Exec(ctx context.Context, query string, args ...any) error {
	started := time.Now()
	err := c.Conn.Exec(ctx, query, args...)
	c.record(ctx, query, started, err)
	return err
}

//nolint:staticcheck // AsyncInsert is the driver's, deprecated in newer versions but still there.
func (c *Conn) AsyncInsert(ctx context.Context, query string, wait bool, args ...any) error {
	started := time.Now()
	err := c.Conn.AsyncInsert(ctx, query, wait, args...)
	c.record(ctx, query, started, err)
	return err
}

func (c *Conn) PrepareBatch(ctx context.Context, query string, opts ...driver.PrepareBatchOption) (driver.Batch, error) {
	started := time.Now()
	batch, err := c.Conn.PrepareBatch(ctx, query, opts...)
	if err != nil || batch == nil {
		c.record(ctx, query, started, err)
		return batch, err
	}
	b := &Batch{Batch: batch, waited: time.Since(started)}
	b.once.end = func(err error) {
		b.mu.Lock()
		waited := b.waited
		b.mu.Unlock()
		c.p.RecordQuery(ctx, db, query, waited, err)
	}
	return b, nil
}

// Rows are a query's rows: the query is counted once, when they are closed
// or read to the end.
type Rows struct {
	driver.Rows
	once countOnce
}

func (r *Rows) Next() bool {
	more := r.Rows.Next()
	if !more {
		r.once.finish(r.Rows.Err())
	}
	return more
}

func (r *Rows) Close() error {
	err := r.Rows.Close()
	r.once.finish(r.Rows.Err())
	return err
}

// Row is QueryRow's row: counted once, when it is scanned.
type Row struct {
	driver.Row
	once countOnce
}

func (r *Row) Scan(dest ...any) error {
	err := r.Row.Scan(dest...)
	r.once.finish(err)
	return err
}

func (r *Row) ScanStruct(dest any) error {
	err := r.Row.ScanStruct(dest)
	r.once.finish(err)
	return err
}

// Batch is a prepared INSERT, counted once when Send answers, for the time
// spent waiting on the server: preparing it, each Flush and the Send. The
// app's own time filling it in between isn't the database's.
type Batch struct {
	driver.Batch
	once   countOnce
	mu     sync.Mutex
	waited time.Duration
}

func (b *Batch) wait(started time.Time) {
	b.mu.Lock()
	b.waited += time.Since(started)
	b.mu.Unlock()
}

func (b *Batch) Flush() error {
	started := time.Now()
	err := b.Batch.Flush()
	b.wait(started)
	return err
}

func (b *Batch) Send() error {
	started := time.Now()
	err := b.Batch.Send()
	b.wait(started)
	b.once.finish(err)
	return err
}

// Abort gives up the batch: not counted.
func (b *Batch) Abort() error {
	b.once.drop()
	return b.Batch.Abort()
}

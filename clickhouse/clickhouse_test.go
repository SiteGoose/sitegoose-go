package sitegooseclickhouse

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

// fakeConn answers every call itself; anything it doesn't override would
// panic on the nil embedded interface, which the test never reaches.
type fakeConn struct{ driver.Conn }

func failIf(query string) error {
	if strings.Contains(query, "FAIL") {
		return errors.New("Code: 62. Syntax error")
	}
	return nil
}

func (fakeConn) Query(_ context.Context, query string, _ ...any) (driver.Rows, error) {
	if err := failIf(query); err != nil {
		return nil, err
	}
	return &fakeRows{left: 2}, nil
}
func (fakeConn) QueryRow(_ context.Context, query string, _ ...any) driver.Row {
	if strings.Contains(query, "NONE") {
		return fakeRow{scan: sql.ErrNoRows}
	}
	return fakeRow{err: failIf(query)}
}
func (fakeConn) Select(_ context.Context, _ any, query string, _ ...any) error { return failIf(query) }
func (fakeConn) Exec(_ context.Context, query string, _ ...any) error          { return failIf(query) }
func (fakeConn) AsyncInsert(_ context.Context, query string, _ bool, _ ...any) error {
	return failIf(query)
}
func (fakeConn) PrepareBatch(_ context.Context, query string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
	return &fakeBatch{}, failIf(query)
}
func (fakeConn) Ping(context.Context) error { return nil }

type fakeRows struct {
	driver.Rows
	left int
}

func (r *fakeRows) Next() bool   { r.left--; return r.left >= 0 }
func (r *fakeRows) Close() error { return nil }
func (r *fakeRows) Err() error   { return nil }

type fakeRow struct {
	driver.Row
	err, scan error
}

func (r fakeRow) Err() error { return r.err }
func (r fakeRow) Scan(...any) error {
	if r.err != nil {
		return r.err
	}
	return r.scan
}

type fakeBatch struct{ driver.Batch }

func (*fakeBatch) Append(...any) error { return nil }
func (*fakeBatch) Send() error         { return nil }
func (*fakeBatch) Flush() error        { return nil }
func (*fakeBatch) Abort() error        { return nil }

func TestWrap(t *testing.T) {
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
	conn := Wrap(p, fakeConn{})
	if Wrap(p, conn) != conn {
		t.Fatal("wrapped twice")
	}

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sitegoose.SetRoute(r.Context(), "/report")
		ctx := r.Context()
		res, err := conn.Query(ctx, "SELECT count() FROM events WHERE site = 'abc' AND n > 5")
		if err != nil {
			t.Fatal(err)
		}
		for res.Next() {
		}
		res.Close() // counted once, not twice
		conn.QueryRow(ctx, "SELECT FAIL FROM t WHERE id = 1")
		var n int
		row := conn.QueryRow(ctx, "SELECT n FROM t WHERE id = 2")
		row.Scan(&n)
		row.Scan(&n) // counted once
		if err := conn.QueryRow(ctx, "SELECT n FROM t WHERE NONE = 3").Scan(&n); !errors.Is(err, sql.ErrNoRows) {
			t.Error("the driver's ErrNoRows must come through", err)
		}
		conn.Exec(ctx, "ALTER TABLE t DELETE WHERE id = 9")
		conn.AsyncInsert(ctx, "INSERT INTO t VALUES (1, 'a')", false)
		var dest []int
		conn.Select(ctx, &dest, "SELECT n FROM t LIMIT 10")
		b, _ := conn.PrepareBatch(ctx, "INSERT INTO t")
		b.Append(1)
		b.Flush()
		b.Append(2)
		b.Send()
		b.Send() // counted once
		b2, _ := conn.PrepareBatch(ctx, "INSERT INTO aborted")
		b2.Abort()
		if _, err := conn.Query(ctx, "SELECT FAIL"); err == nil {
			t.Error("the driver's error must come through")
		}
		w.WriteHeader(200)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/report", nil))
	conn.Exec(context.Background(), "OPTIMIZE TABLE t FINAL")
	p.Flush(context.Background())

	mu.Lock()
	defer mu.Unlock()
	want := map[string][2]float64{
		"GET /report clickhouse SELECT count() FROM events WHERE site = ? AND n > ?": {1, 0},
		"GET /report clickhouse SELECT FAIL FROM t WHERE id = ?":                     {1, 1},
		"GET /report clickhouse SELECT n FROM t WHERE id = ?":                        {1, 0},
		"GET /report clickhouse SELECT n FROM t WHERE NONE = ?":                      {1, 0}, // no row isn't a failure
		"GET /report clickhouse ALTER TABLE t DELETE WHERE id = ?":                   {1, 0},
		"GET /report clickhouse INSERT INTO t VALUES (?)":                            {1, 0},
		"GET /report clickhouse SELECT n FROM t LIMIT ?":                             {1, 0},
		"GET /report clickhouse INSERT INTO t":                                       {1, 0},
		"GET /report clickhouse SELECT FAIL":                                         {1, 1},
		"JOB (background) clickhouse OPTIMIZE TABLE t FINAL":                         {1, 0},
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

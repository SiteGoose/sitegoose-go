package sitegoose

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestQueryCases(t *testing.T) {
	var shared struct {
		Max   int `json:"max_statement"`
		Cases []struct {
			Statement string `json:"statement"`
			DB        string `json:"db"`
			Expected  string `json:"expected"`
		} `json:"cases"`
	}
	readShared(t, "query-cases.json", &shared)
	if shared.Max != maxStatement || len(shared.Cases) == 0 {
		t.Fatal(shared.Max, len(shared.Cases))
	}
	for _, c := range shared.Cases {
		if got := normalizeStatement(c.Statement, c.DB); got != c.Expected {
			t.Errorf("%s %q:\n got %q\nwant %q", c.DB, truncate(c.Statement, 120), got, c.Expected)
		}
	}
	// JavaScript's object key order: integer keys first, a repeated key in its first place.
	if got := normalizeStatement(`find t {"b":1,"2":1,"a":{"x":1},"1":2,"b":{"y":1}}`, "mongodb"); got != `find t {"1":"?","2":"?","b":{"y":"?"},"a":{"x":"?"}}` {
		t.Error(got)
	}
}

// The database's name is lower-cased as JavaScript's toLowerCase does: the
// Kelvin sign is a k, and İ is two characters, not an i.
func TestDatabaseOfLowersAsTheReference(t *testing.T) {
	for in, want := range map[string]string{"SQLite": "sqlite", "CLIC\u212aHOUSE": "clickhouse", "SQL\u0130TE": "other", "nonsense": "other"} {
		if got := databaseOf(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// ---- A database/sql driver of our own ----

var fakeSeen struct {
	sync.Mutex
	marked int // queries that reached the driver marked as timed
}

type fakeDriver struct{ legacy bool }

func (d fakeDriver) Open(string) (driver.Conn, error) {
	if d.legacy {
		return legacyConn{}, nil
	}
	return fakeConn{}, nil
}

type fakeConn struct{ legacyConn }

func fakeRun(ctx context.Context, query string) error {
	if timedOutside(ctx) {
		fakeSeen.Lock()
		fakeSeen.marked++
		fakeSeen.Unlock()
	}
	if strings.Contains(query, "FAIL") {
		return errors.New("syntax error")
	}
	return nil
}

func (fakeConn) QueryContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if err := fakeRun(ctx, query); err != nil {
		return nil, err
	}
	return &fakeRows{}, nil
}

func (fakeConn) ExecContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if err := fakeRun(ctx, query); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

// legacyConn has none of the optional interfaces: database/sql prepares
// every query on it.
type legacyConn struct{}

func (legacyConn) Prepare(query string) (driver.Stmt, error) { return fakeStmt{query}, nil }
func (legacyConn) Close() error                              { return nil }
func (legacyConn) Begin() (driver.Tx, error)                 { return fakeTx{}, nil }

type fakeStmt struct{ query string }

func (fakeStmt) Close() error  { return nil }
func (fakeStmt) NumInput() int { return -1 }
func (s fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	if err := fakeRun(context.Background(), s.query); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}
func (s fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	if err := fakeRun(context.Background(), s.query); err != nil {
		return nil, err
	}
	return &fakeRows{}, nil
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeRows struct{ done bool }

func (*fakeRows) Columns() []string { return []string{"n"} }
func (*fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = int64(7)
	return nil
}

func init() {
	sql.Register("fakepostgres", fakeDriver{})
	sql.Register("fakemysql-legacy", fakeDriver{legacy: true})
}

func queryRows(t *testing.T, c *collector) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, s := range c.requests("/events/server-queries") {
		if s.header.Get("Authorization") != "Bearer test-secret" || s.body["site_id"] != testSite || s.body["sitesecret"] != nil ||
			s.body["server_name"] != "shop-api" || !strings.HasPrefix(s.body["runtime"].(string), "Go ") {
			t.Fatal(s.header, s.body)
		}
		for _, row := range s.body["rows"].([]any) {
			r := row.(map[string]any)
			out[fmt.Sprint(r["method"], " ", r["route"], " ", r["db"], " ", r["statement"])] = r
		}
	}
	return out
}

func TestQueriesThroughDatabaseSQL(t *testing.T) {
	c := newCollector(t)
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, ServerName: "shop-api",
		Disable: allBut(ModulePerformance)})
	t.Cleanup(func() { p.Close(context.Background()) })
	db, err := p.OpenDB("fakepostgres", "x")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	legacy, err := OpenDB("fakemysql-legacy", "y") // the package function: the request's platform
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if err := db.Ping(); err != nil {
		t.Fatal("a driver without Ping must still ping", err)
	}

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetRoute(r.Context(), "/orders/{id}")
		ctx := r.Context()
		for _, id := range []int{1, 22, 333} {
			var n int
			if err := db.QueryRowContext(ctx, fmt.Sprintf("SELECT n FROM orders WHERE id = %d", id)).Scan(&n); err != nil || n != 7 {
				t.Error(err, n)
			}
		}
		if _, err := db.ExecContext(ctx, "UPDATE orders SET FAIL = 'x'"); err == nil {
			t.Error("the driver's error must come through")
		}
		if _, err := legacy.ExecContext(ctx, "INSERT INTO t VALUES (1, 'a'), (2, 'b')"); err != nil {
			t.Error(err)
		}
		tx, _ := db.BeginTx(ctx, nil)
		tx.ExecContext(ctx, "DELETE FROM carts WHERE id = $1", 5)
		tx.Commit()
		db.Exec("VACUUM") // no ctx: background
		w.WriteHeader(201)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/orders/9", nil))
	p.Job(context.Background(), "nightly", func(ctx context.Context) error {
		_, err := db.ExecContext(ctx, "DELETE FROM sessions WHERE age > 30")
		return err
	})
	p.Flush(context.Background())

	rows := queryRows(t, c)
	want := map[string][2]float64{ // count, errors
		"POST /orders/{id} postgresql SELECT n FROM orders WHERE id = ?":   {3, 0},
		"POST /orders/{id} postgresql UPDATE orders SET FAIL = ?":          {1, 1},
		"POST /orders/{id} mysql INSERT INTO t VALUES (?)":                 {1, 0},
		"POST /orders/{id} postgresql DELETE FROM carts WHERE id = $1":     {1, 0},
		"JOB (background) postgresql VACUUM":                               {1, 0},
		"JOB /(job) nightly postgresql DELETE FROM sessions WHERE age > ?": {1, 0},
	}
	for key, n := range want {
		r := rows[key]
		if r == nil || r["count"] != n[0] || r["errors"] != n[1] || len(r["buckets"].([]any)) != len(bucketEdgesMS)+1 ||
			!strings.HasSuffix(r["minute"].(string), ":00.000Z") {
			t.Errorf("%s: %v", key, r)
		}
	}
	if len(rows) != len(want) {
		t.Error(rows)
	}
	// The request's own row in Server speed has the same method and route.
	found := false
	for _, s := range c.requests("/events/server-requests") {
		for _, row := range s.body["rows"].([]any) {
			r := row.(map[string]any)
			found = found || (r["method"] == "POST" && r["route"] == "/orders/{id}")
		}
	}
	if !found {
		t.Error("no Server speed row to join")
	}
	fakeSeen.Lock()
	marked := fakeSeen.marked
	fakeSeen.Unlock()
	if marked == 0 {
		t.Error("a hook under database/sql would count these twice")
	}
}

func TestQueriesAreCountedOnceAndCapped(t *testing.T) {
	c := newCollector(t)
	p := New(Options{SiteID: testSite, Secret: "test-secret", Endpoint: c.server.URL, ServerName: "shop-api",
		Disable: allBut(ModulePerformance)})
	t.Cleanup(func() { p.Close(context.Background()) })
	p.RecordQuery(markTimed(context.Background()), "postgresql", "SELECT 1", time.Millisecond, nil)
	p.RecordQuery(context.Background(), "postgresql", "-- nothing left", time.Millisecond, nil)

	// One request: 50 statements, then (other).
	st := &reqState{platform: p, method: "GET", path: "/x", route: "/x"}
	ctx := withState(context.Background(), st)
	for i := 0; i < maxRequestStatements+10; i++ {
		p.RecordQuery(ctx, "mysql", fmt.Sprintf("SELECT * FROM t%d", i), 3*time.Millisecond, nil)
	}
	p.endQueries(st, "", "", 200)
	p.RecordQuery(ctx, "mysql", "SELECT late", time.Millisecond, nil) // after the request: still its route

	// One minute: 200 keys, then (other), then past 300 nothing new.
	for i := 0; i < maxMinuteKeys+50; i++ {
		p.RecordQuery(context.Background(), "postgresql", fmt.Sprintf("SELECT * FROM bg%d", i), time.Millisecond, nil)
	}
	for i := 0; i < maxMinuteKeys; i++ {
		r := &reqState{platform: p, method: "GET", path: "/r", route: fmt.Sprintf("/r%d", i)}
		p.RecordQuery(withState(context.Background(), r), "postgresql", "SELECT 1", time.Millisecond, nil)
		p.endQueries(r, "", "", 200)
	}
	p.Flush(context.Background())
	rows := queryRows(t, c)
	if len(rows) != maxMinuteKeys {
		t.Fatal(len(rows))
	}
	other := rows["GET /x mysql (other)"]
	if other == nil || other["count"] != float64(10) || other["sum_ms"] != float64(30) || other["max_ms"] != float64(3) {
		t.Fatal(other)
	}
	if rows["GET /x mysql SELECT late"] == nil || rows["JOB (background) postgresql SELECT ?"] != nil {
		t.Fatal("late or marked query")
	}
	if bg := rows["JOB (background) postgresql (other)"]; bg == nil {
		t.Fatal("no (other) row past 200 keys")
	}
}

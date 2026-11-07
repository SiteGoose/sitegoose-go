package sitegoose

// database/sql: a driver wrapped so every query it runs is timed for Server
// speed -> Queries, and nothing else about it changes. Each optional driver
// interface database/sql looks for is answered as database/sql itself would
// answer a driver without it, so the wrapped driver behaves exactly as the
// bare one did.
//
//	db, err := sitegoose.OpenDB("pgx", dsn) // instead of sql.Open("pgx", dsn)
//
// A query is timed from the call until the driver answers (for a query,
// until its rows can be read, not until they all were). The request it
// belongs to is found from the ctx it is given: db.QueryContext(r.Context(),
// ...) counts under that request's route, db.Query(...) as background.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
)

// sqlTimer is what every wrapper of one driver shares: the platform (nil:
// the request's, else the one New made last) and the database's name.
type sqlTimer struct {
	p  *Platform
	db string
}

func (t *sqlTimer) platform(ctx context.Context) *Platform {
	if t.p != nil {
		return t.p
	}
	if st := stateFrom(ctx); st != nil && st.platform != nil {
		return st.platform
	}
	return defaultPlatform.Load()
}

// time runs a query and counts it. driver.ErrSkip (database/sql then
// prepares the statement, whose run is counted) and driver.ErrBadConn
// (database/sql runs it again on another connection) never ran.
func (t *sqlTimer) time(ctx context.Context, query string, run func(ctx context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p := t.platform(ctx)
	if p == nil || p.queries == nil || timedOutside(ctx) {
		return run(ctx)
	}
	started := time.Now()
	err := run(markTimed(ctx))
	if err == driver.ErrSkip || errors.Is(err, driver.ErrBadConn) {
		return err
	}
	p.RecordQuery(ctx, t.db, query, time.Since(started), err)
	return err
}

// databaseFor guesses the database from a driver's registered name and its
// Go type ("pgx", "*pq.Driver", "mysql.MySQLDriver"...).
func databaseFor(name string, v any) string {
	text := strings.ToLower(name)
	if v != nil {
		t := reflect.TypeOf(v)
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		text += " " + strings.ToLower(t.PkgPath()+"."+t.Name())
	}
	for _, guess := range []struct{ db, words string }{
		{"clickhouse", "clickhouse"},
		{"postgresql", "pgx postgres lib/pq cockroach"},
		{"mariadb", "mariadb"},
		{"mysql", "mysql"},
		{"sqlite", "sqlite"},
		{"mssql", "sqlserver mssql azuresql"},
		{"oracle", "godror go-ora go_ora oracle"},
	} {
		for _, word := range strings.Fields(guess.words) {
			if strings.Contains(text, word) {
				return guess.db
			}
		}
	}
	return "other"
}

// OpenDB is sql.Open with the driver registered as driverName wrapped, so
// the queries run through the *sql.DB are timed (Server speed -> Queries).
// A query is counted on the platform its ctx's request belongs to, else on
// the one New made last.
func OpenDB(driverName, dsn string) (*sql.DB, error) { return openDB(nil, driverName, dsn) }

// OpenDB is sql.Open with the driver wrapped, so the queries run through
// the *sql.DB are timed (Server speed -> Queries).
func (p *Platform) OpenDB(driverName, dsn string) (*sql.DB, error) { return openDB(p, driverName, dsn) }

func openDB(p *Platform, driverName, dsn string) (*sql.DB, error) {
	// database/sql gives no other way to a registered driver; Open doesn't connect.
	probe, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	d := probe.Driver()
	probe.Close()
	w := &sqlDriver{inner: d, t: &sqlTimer{p: p, db: databaseFor(driverName, d)}}
	connector, err := w.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(connector), nil
}

// WrapConnector wraps a driver.Connector so the queries run through
// sql.OpenDB(connector) are timed, on the platform their ctx's request
// belongs to, else the one New made last.
func WrapConnector(c driver.Connector) driver.Connector { return wrapConnector(nil, c) }

// WrapConnector wraps a driver.Connector so the queries run through
// sql.OpenDB(p.WrapConnector(connector)) are timed.
func (p *Platform) WrapConnector(c driver.Connector) driver.Connector { return wrapConnector(p, c) }

func wrapConnector(p *Platform, c driver.Connector) driver.Connector {
	if c == nil {
		return nil
	}
	if w, ok := c.(*sqlConnector); ok {
		return w
	}
	d := c.Driver()
	t := &sqlTimer{p: p, db: databaseFor("", c)}
	if t.db == "other" {
		t.db = databaseFor("", d)
	}
	return &sqlConnector{inner: c, d: &sqlDriver{inner: d, t: t}}
}

// WrapDriver wraps a driver.Driver, for sql.Register under a name of your
// own; its queries are timed on the platform their ctx's request belongs
// to, else the one New made last.
func WrapDriver(d driver.Driver) driver.Driver { return wrapDriver(nil, d) }

// WrapDriver wraps a driver.Driver, for sql.Register under a name of your
// own, so its queries are timed.
func (p *Platform) WrapDriver(d driver.Driver) driver.Driver { return wrapDriver(p, d) }

func wrapDriver(p *Platform, d driver.Driver) driver.Driver {
	if d == nil {
		return nil
	}
	if w, ok := d.(*sqlDriver); ok {
		return w
	}
	return &sqlDriver{inner: d, t: &sqlTimer{p: p, db: databaseFor("", d)}}
}

// UnwrapConn is the driver's own connection under a wrapped one, for
// (*sql.Conn).Raw: conn.Raw(func(c any) error { pc := sitegoose.UnwrapConn(c).(*stdlib.Conn) ... }).
// Anything else is given back as it is.
func UnwrapConn(c any) any {
	if w, ok := c.(*sqlConn); ok {
		return w.inner
	}
	return c
}

// ---- Driver and connector ----

type sqlDriver struct {
	inner driver.Driver
	t     *sqlTimer
}

func (d *sqlDriver) Open(name string) (driver.Conn, error) {
	c, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &sqlConn{inner: c, t: d.t}, nil
}

// OpenConnector: the driver's own connector when it has one, else what
// database/sql would use (Open with the name).
func (d *sqlDriver) OpenConnector(name string) (driver.Connector, error) {
	if dc, ok := d.inner.(driver.DriverContext); ok {
		c, err := dc.OpenConnector(name)
		if err != nil {
			return nil, err
		}
		return &sqlConnector{inner: c, d: d}, nil
	}
	return &sqlConnector{inner: dsnConnector{name: name, d: d.inner}, d: d}, nil
}

type dsnConnector struct {
	name string
	d    driver.Driver
}

func (c dsnConnector) Connect(context.Context) (driver.Conn, error) { return c.d.Open(c.name) }
func (c dsnConnector) Driver() driver.Driver                        { return c.d }

type sqlConnector struct {
	inner driver.Connector
	d     *sqlDriver
}

func (c *sqlConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &sqlConn{inner: conn, t: c.d.t}, nil
}

func (c *sqlConnector) Driver() driver.Driver { return c.d }

// Close: database/sql's DB.Close closes a connector that can be.
func (c *sqlConnector) Close() error {
	if closer, ok := c.inner.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// ---- Connection ----

type sqlConn struct {
	inner driver.Conn
	t     *sqlTimer
}

var (
	_ driver.Conn               = (*sqlConn)(nil)
	_ driver.QueryerContext     = (*sqlConn)(nil)
	_ driver.ExecerContext      = (*sqlConn)(nil)
	_ driver.ConnPrepareContext = (*sqlConn)(nil)
	_ driver.ConnBeginTx        = (*sqlConn)(nil)
	_ driver.NamedValueChecker  = (*sqlConn)(nil)
	_ driver.SessionResetter    = (*sqlConn)(nil)
	_ driver.Validator          = (*sqlConn)(nil)
	_ driver.Pinger             = (*sqlConn)(nil)
)

// Unwrap is the driver's own connection.
func (c *sqlConn) Unwrap() driver.Conn { return c.inner }

func (c *sqlConn) Prepare(query string) (driver.Stmt, error) {
	s, err := c.inner.Prepare(query)
	if err != nil {
		return nil, err
	}
	return wrapStmt(s, c, query), nil
}

func (c *sqlConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	var s driver.Stmt
	var err error
	if pc, ok := c.inner.(driver.ConnPrepareContext); ok {
		s, err = pc.PrepareContext(ctx, query)
	} else {
		// As database/sql does without it.
		s, err = c.inner.Prepare(query)
		if err == nil {
			select {
			default:
			case <-ctx.Done():
				s.Close()
				return nil, ctx.Err()
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return wrapStmt(s, c, query), nil
}

func (c *sqlConn) Close() error { return c.inner.Close() }

//nolint:staticcheck // the driver.Conn interface
func (c *sqlConn) Begin() (driver.Tx, error) { return c.inner.Begin() }

func (c *sqlConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if bt, ok := c.inner.(driver.ConnBeginTx); ok {
		return bt.BeginTx(ctx, opts)
	}
	// As database/sql does without it.
	if opts.Isolation != driver.IsolationLevel(sql.LevelDefault) {
		return nil, errors.New("sql: driver does not support non-default isolation level")
	}
	if opts.ReadOnly {
		return nil, errors.New("sql: driver does not support read-only transactions")
	}
	if ctx.Done() == nil {
		return c.inner.Begin() //nolint:staticcheck
	}
	tx, err := c.inner.Begin() //nolint:staticcheck
	if err == nil {
		select {
		default:
		case <-ctx.Done():
			tx.Rollback()
			return nil, ctx.Err()
		}
	}
	return tx, err
}

// namedToValues is what database/sql does before calling a driver method
// that takes no ctx: the arguments without names, unless ctx is done.
func namedToValues(ctx context.Context, named []driver.NamedValue) ([]driver.Value, error) {
	values := make([]driver.Value, len(named))
	for i, nv := range named {
		if nv.Name != "" {
			return nil, errors.New("sql: driver does not support the use of Named Parameters")
		}
		values[i] = nv.Value
	}
	select {
	default:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return values, nil
}

func (c *sqlConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (rows driver.Rows, err error) {
	qc, hasCtx := c.inner.(driver.QueryerContext)
	q, has := c.inner.(driver.Queryer) //nolint:staticcheck
	if !hasCtx && !has {
		return nil, driver.ErrSkip // database/sql prepares it instead
	}
	err = c.t.time(ctx, query, func(ctx context.Context) error {
		if hasCtx {
			rows, err = qc.QueryContext(ctx, query, args)
			return err
		}
		values, err := namedToValues(ctx, args)
		if err != nil {
			return err
		}
		rows, err = q.Query(query, values)
		return err
	})
	return rows, err
}

func (c *sqlConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (result driver.Result, err error) {
	ec, hasCtx := c.inner.(driver.ExecerContext)
	e, has := c.inner.(driver.Execer) //nolint:staticcheck
	if !hasCtx && !has {
		return nil, driver.ErrSkip
	}
	err = c.t.time(ctx, query, func(ctx context.Context) error {
		if hasCtx {
			result, err = ec.ExecContext(ctx, query, args)
			return err
		}
		values, err := namedToValues(ctx, args)
		if err != nil {
			return err
		}
		result, err = e.Exec(query, values)
		return err
	})
	return result, err
}

// CheckNamedValue: the driver's own check, else driver.ErrSkip, which sends
// database/sql on to its default, as without one.
func (c *sqlConn) CheckNamedValue(nv *driver.NamedValue) error {
	if ch, ok := c.inner.(driver.NamedValueChecker); ok {
		return ch.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

func (c *sqlConn) ResetSession(ctx context.Context) error {
	if r, ok := c.inner.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *sqlConn) IsValid() bool {
	if v, ok := c.inner.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

func (c *sqlConn) Ping(ctx context.Context) error {
	if p, ok := c.inner.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

// ---- Statement ----

type sqlStmt struct {
	inner driver.Stmt
	conn  *sqlConn
	query string
}

// sqlStmtConverter is a statement whose driver converts its own columns
// (driver.ColumnConverter): only then is the wrapper one too, as
// database/sql treats a statement that is differently.
type sqlStmtConverter struct{ *sqlStmt }

func (s sqlStmtConverter) ColumnConverter(idx int) driver.ValueConverter {
	return s.inner.(driver.ColumnConverter).ColumnConverter(idx) //nolint:staticcheck
}

func wrapStmt(s driver.Stmt, c *sqlConn, query string) driver.Stmt {
	w := &sqlStmt{inner: s, conn: c, query: query}
	if _, ok := s.(driver.ColumnConverter); ok { //nolint:staticcheck
		return sqlStmtConverter{w}
	}
	return w
}

func (s *sqlStmt) Close() error  { return s.inner.Close() }
func (s *sqlStmt) NumInput() int { return s.inner.NumInput() }

//nolint:staticcheck // the driver.Stmt interface
func (s *sqlStmt) Exec(args []driver.Value) (driver.Result, error) { return s.inner.Exec(args) }

//nolint:staticcheck // the driver.Stmt interface
func (s *sqlStmt) Query(args []driver.Value) (driver.Rows, error) { return s.inner.Query(args) }

func (s *sqlStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (result driver.Result, err error) {
	err = s.conn.t.time(ctx, s.query, func(ctx context.Context) error {
		if ec, ok := s.inner.(driver.StmtExecContext); ok {
			result, err = ec.ExecContext(ctx, args)
			return err
		}
		values, err := namedToValues(ctx, args)
		if err != nil {
			return err
		}
		result, err = s.inner.Exec(values) //nolint:staticcheck
		return err
	})
	return result, err
}

func (s *sqlStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (rows driver.Rows, err error) {
	err = s.conn.t.time(ctx, s.query, func(ctx context.Context) error {
		if qc, ok := s.inner.(driver.StmtQueryContext); ok {
			rows, err = qc.QueryContext(ctx, args)
			return err
		}
		values, err := namedToValues(ctx, args)
		if err != nil {
			return err
		}
		rows, err = s.inner.Query(values) //nolint:staticcheck
		return err
	})
	return rows, err
}

// CheckNamedValue: the statement's own check, else its connection's, else
// driver.ErrSkip, the order database/sql asks them in.
func (s *sqlStmt) CheckNamedValue(nv *driver.NamedValue) error {
	if ch, ok := s.inner.(driver.NamedValueChecker); ok {
		return ch.CheckNamedValue(nv)
	}
	return s.conn.CheckNamedValue(nv)
}

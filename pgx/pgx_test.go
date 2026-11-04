package sitegoosepgx_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	sitegoose "github.com/sitegoose/sitegoose-go"
	sitegoosepgx "github.com/sitegoose/sitegoose-go/pgx"
)

func TestTracer(t *testing.T) {
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
	tracer := sitegoosepgx.Tracer(p)

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sitegoose.SetRoute(r.Context(), "/users/{id}")
		ctx := tracer.TraceQueryStart(r.Context(), nil, pgx.TraceQueryStartData{SQL: "SELECT * FROM users WHERE id = $1"})
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: pgx.ErrNoRows})
		ctx = tracer.TraceQueryStart(r.Context(), nil, pgx.TraceQueryStartData{SQL: "SELECT nope FROM users WHERE a = 'x'"})
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: errors.New("column does not exist")})
		ctx = tracer.TraceBatchStart(r.Context(), nil, pgx.TraceBatchStartData{})
		tracer.TraceBatchQuery(ctx, nil, pgx.TraceBatchQueryData{SQL: "INSERT INTO log VALUES (1)", CommandTag: pgconn.NewCommandTag("INSERT 0 1")})
		tracer.TraceBatchQuery(ctx, nil, pgx.TraceBatchQueryData{SQL: "INSERT INTO log VALUES (2)"})
		tracer.TraceBatchEnd(ctx, nil, pgx.TraceBatchEndData{})
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/users/4", nil))
	ctx := tracer.TraceCopyFromStart(context.Background(), nil, pgx.TraceCopyFromStartData{TableName: pgx.Identifier{"events"}})
	tracer.TraceCopyFromEnd(ctx, nil, pgx.TraceCopyFromEndData{})
	p.Flush(context.Background())

	mu.Lock()
	defer mu.Unlock()
	for key, want := range map[string][2]float64{
		"GET /users/{id} postgresql SELECT * FROM users WHERE id = $1":  {1, 0},
		"GET /users/{id} postgresql SELECT nope FROM users WHERE a = ?": {1, 1},
		"GET /users/{id} postgresql INSERT INTO log VALUES (?)":         {2, 0},
		`JOB (background) postgresql COPY "events" FROM STDIN`:          {1, 0},
	} {
		if r := rows[key]; r == nil || r["count"] != want[0] || r["errors"] != want[1] {
			t.Errorf("%s: %v", key, r)
		}
	}
	if len(rows) != 4 {
		t.Error(rows)
	}
}

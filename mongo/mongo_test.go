package sitegoosemongo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

func raw(t *testing.T, d bson.D) bson.Raw {
	data, err := bson.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestMonitor(t *testing.T) {
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
	m := Monitor(p)

	run := func(ctx context.Context, id int64, name string, cmd bson.D, err error) {
		m.Started(ctx, &event.CommandStartedEvent{Command: raw(t, cmd), CommandName: name, RequestID: id, ConnectionID: "c1"})
		done := event.CommandFinishedEvent{CommandName: name, RequestID: id, ConnectionID: "c1", Duration: 4 * time.Millisecond}
		if err != nil {
			m.Failed(ctx, &event.CommandFailedEvent{CommandFinishedEvent: done, Failure: err})
		} else {
			m.Succeeded(ctx, &event.CommandSucceededEvent{CommandFinishedEvent: done})
		}
	}
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sitegoose.SetRoute(r.Context(), "/users/{id}")
		ctx := r.Context()
		run(ctx, 1, "find", bson.D{{Key: "find", Value: "users"}, {Key: "filter", Value: bson.D{{Key: "email", Value: "a@b.c"},
			{Key: "age", Value: bson.D{{Key: "$gt", Value: 30}}}, {Key: "$or", Value: bson.A{bson.D{{Key: "a", Value: 1}}, bson.D{{Key: "a", Value: 2}}}}}}}, nil)
		run(ctx, 2, "find", bson.D{{Key: "find", Value: "users"}, {Key: "filter", Value: bson.D{{Key: "email", Value: "z@y.x"},
			{Key: "age", Value: bson.D{{Key: "$gt", Value: 1}}}, {Key: "$or", Value: bson.A{}}}}}, errors.New("timeout"))
		run(ctx, 3, "ping", bson.D{{Key: "ping", Value: 1}}, nil)
		run(ctx, 4, "delete", bson.D{{Key: "delete", Value: "carts"}, {Key: "deletes", Value: bson.A{bson.D{{Key: "q", Value: bson.D{{Key: "_id", Value: bson.NewObjectID()}}}, {Key: "limit", Value: 1}}}}}, nil)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/users/4", nil))
	run(context.Background(), 5, "insert", bson.D{{Key: "insert", Value: "logs"}, {Key: "documents", Value: bson.A{bson.D{{Key: "x", Value: 1}}}}}, nil)
	p.Flush(context.Background())

	mu.Lock()
	defer mu.Unlock()
	for key, want := range map[string][2]float64{
		`GET /users/{id} mongodb find users {"email":"?","age":{"$gt":"?"},"$or":[{"a":"?"}]}`: {1, 0},
		`GET /users/{id} mongodb find users {"email":"?","age":{"$gt":"?"},"$or":[]}`:          {1, 1},
		`GET /users/{id} mongodb delete carts {"_id":"?"}`:                                     {1, 0},
		`JOB (background) mongodb insert logs`:                                                 {1, 0},
	} {
		if r := rows[key]; r == nil || r["count"] != want[0] || r["errors"] != want[1] || r["sum_ms"] != float64(4) {
			t.Errorf("%s: %v", key, r)
		}
	}
	if len(rows) != 4 {
		t.Error(rows)
	}
}

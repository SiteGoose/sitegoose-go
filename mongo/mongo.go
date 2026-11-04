// Package sitegoosemongo times the commands the MongoDB Go driver (v2) runs,
// for Server speed -> Queries, through the driver's command monitor:
//
//	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetMonitor(sitegoosemongo.Monitor(p)))
//
// A command counts under the request its ctx belongs to
// (coll.Find(r.Context(), ...)), else as a background query. Each is
// recorded as "<command> <collection> <filter>", the filter's shape only:
// its values never leave the monitor, they are not even written out. The
// driver's own chatter (hello, ping, getMore, auth...) is left out.
//
// It is in a module of its own so the platform package needs nothing but
// the standard library.
package sitegoosemongo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

// chatter is the connection's own talk, never recorded (sdk/protocols/queries.md).
var chatter = map[string]bool{"hello": true, "isMaster": true, "ismaster": true, "ping": true, "buildInfo": true,
	"saslStart": true, "saslContinue": true, "getMore": true, "endSessions": true, "killCursors": true, "getLastError": true}

// filterField is where each command keeps its filter.
var filterField = map[string]string{"find": "filter", "aggregate": "pipeline", "count": "query", "distinct": "query",
	"findAndModify": "query"}

// maxPending bounds the commands started and not yet finished; a monitor that
// somehow never hears the end of one can't grow without end.
const maxPending = 10000

type pendingKey struct {
	conn string
	id   int64
}

type monitor struct {
	p       *sitegoose.Platform
	mu      sync.Mutex
	pending map[pendingKey]string
}

// Monitor is the command monitor to give options.Client().SetMonitor.
func Monitor(p *sitegoose.Platform) *event.CommandMonitor {
	m := &monitor{p: p, pending: map[pendingKey]string{}}
	return &event.CommandMonitor{
		Started: m.started,
		Succeeded: func(ctx context.Context, e *event.CommandSucceededEvent) {
			m.finished(ctx, e.CommandFinishedEvent, nil)
		},
		Failed: func(ctx context.Context, e *event.CommandFailedEvent) {
			err := e.Failure
			if err == nil {
				err = errors.New("failed")
			}
			m.finished(ctx, e.CommandFinishedEvent, err)
		},
	}
}

func (m *monitor) started(_ context.Context, e *event.CommandStartedEvent) {
	if e == nil || chatter[e.CommandName] {
		return
	}
	text := statement(e.CommandName, e.Command)
	if text == "" {
		return
	}
	m.mu.Lock()
	if len(m.pending) >= maxPending {
		m.pending = map[pendingKey]string{}
	}
	m.pending[pendingKey{e.ConnectionID, e.RequestID}] = text
	m.mu.Unlock()
}

func (m *monitor) finished(ctx context.Context, e event.CommandFinishedEvent, err error) {
	key := pendingKey{e.ConnectionID, e.RequestID}
	m.mu.Lock()
	statement, ok := m.pending[key]
	delete(m.pending, key)
	m.mu.Unlock()
	if ok {
		m.p.RecordQuery(ctx, "mongodb", statement, e.Duration, err)
	}
}

// statement is what a command is recorded as: "find users {"email":0}", the
// command, its collection and the shape of its filter (every value 0; the
// platform makes them "?").
func statement(name string, command bson.Raw) string {
	if name == "" {
		return ""
	}
	out := name
	first, err := command.IndexErr(0)
	if err != nil {
		return out
	}
	collection, ok := first.Value().StringValueOK()
	if !ok || collection == "" {
		return out
	}
	out += " " + collection
	var filter bson.RawValue
	switch name {
	case "delete", "update":
		list := "deletes"
		if name == "update" {
			list = "updates"
		}
		if items, ok := command.Lookup(list).ArrayOK(); ok {
			if values, err := items.Values(); err == nil && len(values) > 0 {
				if doc, ok := values[0].DocumentOK(); ok {
					filter = doc.Lookup("q")
				}
			}
		}
	default:
		if field := filterField[name]; field != "" {
			filter = command.Lookup(field)
		}
	}
	if filter.Type != bson.TypeEmbeddedDocument && filter.Type != bson.TypeArray {
		return out
	}
	var b bytes.Buffer
	shape(&b, filter, 0)
	return out + " " + b.String()
}

// shape writes a filter as JSON with every value 0, deep enough for the
// platform's six levels.
func shape(b *bytes.Buffer, v bson.RawValue, depth int) {
	if depth > 7 {
		b.WriteByte('0')
		return
	}
	switch v.Type {
	case bson.TypeEmbeddedDocument:
		elements, _ := v.Document().Elements()
		b.WriteByte('{')
		for i, e := range elements {
			if i > 0 {
				b.WriteByte(',')
			}
			key, _ := json.Marshal(e.Key())
			b.Write(key)
			b.WriteByte(':')
			shape(b, e.Value(), depth+1)
		}
		b.WriteByte('}')
	case bson.TypeArray:
		values, _ := v.Array().Values()
		b.WriteByte('[')
		for i, item := range values {
			if i > 0 {
				b.WriteByte(',')
			}
			shape(b, item, depth+1)
		}
		b.WriteByte(']')
	default:
		b.WriteByte('0')
	}
}

package sitegoose

// Analytics module: what only the server sees for sure (payments, sign-ups,
// plan changes), next to the browser tracker's visits. Not pageviews: the
// tracker counts those, and counting them here too would count them twice.
//
//   - Track: events, batched to POST /events/server-events in the
//     background. Each gets an event_uid, so a retried batch can be told
//     apart from new events.
//   - Identify: links the browser's visit to your user ID (/events/identify).
//   - Lead: adds or updates a lead (/events/lead).
//
// Identify and Lead wait for the answer (up to 5 seconds). The visit comes
// from the request's context (the X-Analytics-Session header the page sends),
// or pass session_id yourself.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	analyticsBatch    = 100
	analyticsQueueMax = 1000
	analyticsFlush    = 2 * time.Second
	analyticsRetry    = 15 * time.Second
)

// LeadResult is the collector's answer to Lead.
type LeadResult struct {
	Status string `json:"status"`
	LeadID string `json:"lead_id"`
}

type analytics struct {
	core  *core
	mu    sync.Mutex
	queue []json.RawMessage // each event encoded as it was queued
	job   *periodic
}

func newAnalytics(c *core) *analytics {
	a := &analytics{core: c}
	a.job = c.every(analyticsFlush, func() time.Duration {
		if a.flush(context.Background()) {
			return analyticsFlush
		}
		return analyticsRetry
	})
	return a
}

func uuid4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (a *analytics) track(ctx context.Context, name string, fields map[string]any) string {
	if name == "" || !a.core.isOn(ModuleAnalytics) {
		return ""
	}
	event := map[string]any{"timestamp": isoNow(), "session_id": sessionFrom(ctx)}
	for k, v := range fields {
		event[k] = v
	}
	event["event_name"] = truncate(name, 100)
	uid, _ := fields["event_uid"].(string)
	if uid == "" {
		uid = uuid4()
	}
	event["event_uid"] = uid
	switch n := event["numeric_value"].(type) {
	case int:
		event["numeric_value"] = strconv.Itoa(n)
	case int64:
		event["numeric_value"] = strconv.FormatInt(n, 10)
	case float64:
		event["numeric_value"] = strconv.FormatFloat(n, 'f', -1, 64)
	case float32:
		event["numeric_value"] = strconv.FormatFloat(float64(n), 'f', -1, 32)
	}
	// Encoded now: a value json can't take (NaN, a channel) loses this
	// event only, not the batch it would have gone in.
	data, err := json.Marshal(event)
	if err != nil {
		a.core.log("analytics", "event %q dropped, it can't be encoded: %v", name, err)
		return ""
	}
	a.mu.Lock()
	if len(a.queue) >= analyticsQueueMax {
		a.mu.Unlock()
		a.core.log("analytics", "queue full, event dropped")
		return ""
	}
	a.queue = append(a.queue, data)
	full := len(a.queue) >= analyticsBatch
	a.mu.Unlock()
	if full {
		a.job.runNow()
	}
	return uid
}

// flush sends what's waiting; false when some of it must be tried again.
func (a *analytics) flush(ctx context.Context) bool {
	a.mu.Lock()
	waiting := a.queue
	a.queue = nil
	a.mu.Unlock()
	ok := true
	for i := 0; i < len(waiting); i += analyticsBatch {
		end := i + analyticsBatch
		if end > len(waiting) {
			end = len(waiting)
		}
		batch := waiting[i:end]
		res := a.core.send(ctx, "analytics", "/events/server-events", http.MethodPost, map[string]any{"events": batch}, authBody, nil)
		if failed(res) {
			ok = false
			a.mu.Lock()
			a.queue = append(append([]json.RawMessage{}, batch...), a.queue...)
			if len(a.queue) > analyticsQueueMax {
				a.queue = a.queue[:analyticsQueueMax]
			}
			a.mu.Unlock()
		} else if !res.ok() {
			a.core.log("analytics", "events refused: %s", truncate(string(res.body), 300))
		}
	}
	return ok
}

func (a *analytics) identify(ctx context.Context, userID, sessionID string) bool {
	if sessionID == "" {
		sessionID = sessionFrom(ctx)
	}
	if userID == "" || sessionID == "" || !a.core.isOn(ModuleAnalytics) {
		return false
	}
	res := a.core.send(ctx, "analytics", "/events/identify", http.MethodPost,
		map[string]any{"user_id": userID, "session_id": sessionID}, authBody, nil)
	return res.ok()
}

func (a *analytics) lead(ctx context.Context, fields map[string]any) *LeadResult {
	if !a.core.isOn(ModuleAnalytics) {
		return nil
	}
	body := map[string]any{"session_id": sessionFrom(ctx)}
	for k, v := range fields {
		body[k] = v
	}
	res := a.core.send(ctx, "analytics", "/events/lead", http.MethodPost, body, authBody, nil)
	if res == nil {
		return nil
	}
	if !res.ok() {
		a.core.log("analytics", "lead refused: %s", truncate(string(res.body), 300))
		return nil
	}
	var out LeadResult
	if !res.json(&out) {
		return nil
	}
	return &out
}

func (a *analytics) close(ctx context.Context) {
	a.job.halt(ctx)
	a.flush(ctx)
}

package sitegoose

// Audit log module: who did what on your site, sent to POST /events/audit in
// small batches in the background (Security -> Audit log). What goes in
// (names, emails) is up to you; the request's context adds the actor's
// address and visit.

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

const (
	auditBatch    = 100
	auditQueueMax = 1000
	auditFlush    = 5 * time.Second
)

// AuditEntry says who did it, to what, and anything else worth keeping.
type AuditEntry struct {
	Actor   string
	Target  string
	Details any
}

type audit struct {
	core  *core
	mu    sync.Mutex
	queue []json.RawMessage // each entry encoded as it was recorded
	job   *periodic
}

func newAudit(c *core) *audit {
	a := &audit{core: c}
	a.job = c.every(auditFlush, func() time.Duration {
		a.flush(context.Background())
		return auditFlush
	})
	return a
}

func (a *audit) record(action string, e AuditEntry, ip, session string) {
	if action == "" || !a.core.isOn(ModuleAudit) {
		return
	}
	entry := map[string]any{
		"at": isoNow(), "action": truncate(action, 64), "actor": truncate(e.Actor, 200), "target": truncate(e.Target, 300),
		"details": e.Details, "actor_ip": ip, "session_id": session,
	}
	// Encoded now: Details json can't take loses this entry only.
	data, err := json.Marshal(entry)
	if err != nil {
		a.core.log("audit", "entry %q dropped, its details can't be encoded: %v", action, err)
		return
	}
	a.mu.Lock()
	if len(a.queue) >= auditQueueMax {
		a.mu.Unlock()
		return
	}
	a.queue = append(a.queue, data)
	full := len(a.queue) >= auditBatch
	a.mu.Unlock()
	if full {
		a.job.runNow()
	}
}

func (a *audit) flush(ctx context.Context) {
	a.mu.Lock()
	waiting := a.queue
	a.queue = nil
	a.mu.Unlock()
	for i := 0; i < len(waiting); i += auditBatch {
		end := i + auditBatch
		if end > len(waiting) {
			end = len(waiting)
		}
		a.core.send(ctx, "audit", "/events/audit", http.MethodPost, map[string]any{"entries": waiting[i:end]}, authBody, nil)
	}
}

func (a *audit) close(ctx context.Context) {
	a.job.halt(ctx)
	a.flush(ctx)
}

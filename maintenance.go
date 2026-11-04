package sitegoose

// Maintenance mode module: while it's on (Site settings -> Server), visitors
// get a "back soon" page (503, so search engines know it's temporary), except
// allowed addresses and whoever opened the preview link
// (?site_preview=<code>, remembered for a day in a cookie).

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"sync"
)

const previewCookie = "site_preview"

// MaintenanceOptions configure maintenance mode.
type MaintenanceOptions struct {
	// Skip lets a request through when it returns true (health checks).
	Skip func(r *http.Request) bool
}

type maintenanceConfig struct {
	on      bool
	allow   []string
	bypass  string
	message string
}

func parseMaintenance(raw json.RawMessage) maintenanceConfig {
	var data map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &data) != nil {
		return maintenanceConfig{}
	}
	bypass, _ := data["bypass"].(string)
	message, _ := data["message"].(string)
	return maintenanceConfig{on: data["on"] == true, allow: stringList(data["allow"]), bypass: bypass, message: message}
}

func maintenancePage(message string) []byte {
	if message == "" {
		message = "We're doing some maintenance. Please check back in a few minutes."
	}
	return []byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>Back soon</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;` +
		`background:#f8fafc;color:#0f172a}main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.6rem;margin:0 0 .5rem}` +
		`p{color:#475569;margin:0}@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}p{color:#94a3b8}}</style></head>` +
		`<body><main><h1>Back soon</h1><p>` + html.EscapeString(message) + `</p></main></body></html>`)
}

type maintenance struct {
	core *core
	skip func(*http.Request) bool

	mu       sync.Mutex
	allowFor uint64
	allow    *ipSet
}

// decision: closed is the "back soon" page; setCookie remembers the preview link.
type maintenanceDecision struct {
	closed    bool
	setCookie string
}

func (m *maintenance) decide(r *http.Request, ip string) maintenanceDecision {
	if !m.core.isOn(ModuleMaintenance) {
		return maintenanceDecision{}
	}
	m.core.mu.RLock()
	config, version := m.core.maintenance, m.core.version
	m.core.mu.RUnlock()
	if !config.on || (m.skip != nil && m.skip(r)) {
		return maintenanceDecision{}
	}
	m.mu.Lock()
	if m.allow == nil || m.allowFor != version {
		m.allow, m.allowFor = newIPSet(config.allow), version
	}
	allow := m.allow
	m.mu.Unlock()
	if key, ok := ipKeyOf(ip); ok && allow.has(key) {
		return maintenanceDecision{}
	}
	if code := config.bypass; code != "" {
		if query, err := url.ParseQuery(r.URL.RawQuery); err == nil && query.Get(previewCookie) == code {
			return maintenanceDecision{setCookie: previewCookie + "=" + code + "; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax"}
		}
		if c, err := r.Cookie(previewCookie); err == nil && c.Value == code {
			return maintenanceDecision{}
		}
	}
	return maintenanceDecision{closed: true}
}

func (m *maintenance) message() string {
	m.core.mu.RLock()
	defer m.core.mu.RUnlock()
	return m.core.maintenance.message
}

package sitegoose

// The trail before an error: steps you add (AddBreadcrumb) and the outgoing
// requests made through Transport, both kept with the request or job whose
// context they were made in. A step outside a request or job is dropped.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AddBreadcrumb adds a step of your own to the trail shown before an error
// in the request or job ctx belongs to.
func (p *Platform) AddBreadcrumb(ctx context.Context, text string) {
	if p == nil || p.errors == nil {
		return
	}
	stateFrom(ctx).addCrumb("note", text, nil)
}

// Transport records the outgoing requests made through it as steps of the
// trail of the request or job their context belongs to (method, address and
// status, never a header or a body), and times each one for Server speed ->
// Calls by the host it went to (calls.go). base nil is http.DefaultTransport,
// which is used as it is, never changed:
//
//	client := &http.Client{Transport: p.Transport(nil)}
//	req, _ := http.NewRequestWithContext(r.Context(), "GET", url, nil)
func (p *Platform) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	// Wrapped twice, every call would count twice.
	if t, ok := base.(*breadcrumbTransport); ok && t.p == p {
		return t
	}
	return &breadcrumbTransport{p: p, base: base}
}

type breadcrumbTransport struct {
	p    *Platform
	base http.RoundTripper
}

// CloseIdleConnections passes http.Client.CloseIdleConnections on to base.
func (t *breadcrumbTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func (t *breadcrumbTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p := t.p
	if p == nil || req == nil || req.URL == nil {
		return t.base.RoundTrip(req)
	}
	st := stateFrom(req.Context())
	crumbs := st != nil && p.errors != nil
	timed := p.calls != nil && p.core.isOn(ModulePerformance)
	if !crumbs && !timed {
		return t.base.RoundTrip(req)
	}
	address := req.URL.Scheme + "://" + req.URL.Host + req.URL.EscapedPath()
	// The collector's own address and what's under it are the package's
	// calls, not steps of the request, nor the site's calls.
	if c := p.core.endpoint; c != "" && (address == c || strings.HasPrefix(address, c+"/")) {
		return t.base.RoundTrip(req)
	}
	host := ""
	if timed {
		host = callHost(req.URL)
		if host == "" || host == p.core.ownHost {
			timed = false
		}
	}
	started := time.Now()
	// RoundTrip returns once the response's headers are in: what the code
	// waited for. A body read afterwards isn't counted.
	res, err := t.base.RoundTrip(req)
	elapsed := time.Since(started)
	func() {
		defer func() { recover() }()
		status := 0
		if err != nil {
			// Cancelled by the app, as the tracker treats a cancelled fetch:
			// not a failure, and not a call.
			if errors.Is(err, context.Canceled) {
				return
			}
		} else if res != nil {
			status = res.StatusCode
		}
		if timed {
			p.recordCall(req.Context(), req.Method, host, elapsed, status)
		}
		if crumbs {
			st.addCrumb("request", strings.ToUpper(firstNonEmpty(req.Method, "GET"))+" "+address, &status)
		}
	}()
	return res, err
}

// SlogHandler wraps next (your log/slog handler) so the errors your code
// logs at Error or above are sent as well ("logged"): the first attribute
// whose value is an error. A record without one isn't sent: it has nothing
// to group it by. Logging goes on as before.
//
//	slog.SetDefault(slog.New(p.SlogHandler(slog.NewJSONHandler(os.Stderr, nil))))
//	slog.ErrorContext(r.Context(), "charge failed", "err", err)
func (p *Platform) SlogHandler(next slog.Handler) slog.Handler {
	return &slogHandler{p: p, next: next}
}

type slogHandler struct {
	p     *Platform
	next  slog.Handler
	attrs []slog.Attr
}

func (h *slogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= slog.LevelError || h.next.Enabled(ctx, level)
}

func (h *slogHandler) Handle(ctx context.Context, record slog.Record) error {
	var err error
	if h.next.Enabled(ctx, record.Level) {
		err = h.next.Handle(ctx, record)
	}
	if record.Level >= slog.LevelError && h.p != nil && h.p.errors != nil {
		func() {
			defer func() { recover() }()
			found := errorAttr(h.attrs)
			if found == nil {
				record.Attrs(func(a slog.Attr) bool {
					found = errorAttr([]slog.Attr{a})
					return found == nil
				})
			}
			if found != nil {
				h.p.errors.capture(ctx, found, "logged", 0, callers(0), false)
			}
		}()
	}
	return err
}

func errorAttr(attrs []slog.Attr) error {
	for _, a := range attrs {
		v := a.Value.Resolve()
		switch v.Kind() {
		case slog.KindAny:
			if err, ok := v.Any().(error); ok && err != nil {
				return err
			}
		case slog.KindGroup:
			if err := errorAttr(v.Group()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &slogHandler{p: h.p, next: h.next.WithAttrs(attrs), attrs: append(append([]slog.Attr{}, h.attrs...), attrs...)}
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	return &slogHandler{p: h.p, next: h.next.WithGroup(name), attrs: h.attrs}
}

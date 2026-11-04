# sitegoose-go

The server package for Go: firewall, error monitoring, Server speed, crawlers,
server analytics, forms, security headers, audit log, feature flags,
maintenance mode, software inventory, set-up checks, the machine's resources
and the first-party proxy. Standard library only; Go 1.21 or later.

```sh
go get github.com/sitegoose/sitegoose-go
go get github.com/sitegoose/sitegoose-go/gin    # gin apps
go get github.com/sitegoose/sitegoose-go/echo   # echo apps
go get github.com/sitegoose/sitegoose-go/chi    # chi apps
go get github.com/sitegoose/sitegoose-go/pgx    # pgx's own query timing
go get github.com/sitegoose/sitegoose-go/mongo  # MongoDB driver v2
```

## net/http

```go
p := sitegoose.New(sitegoose.Options{
	SiteID:     os.Getenv("ANALYTICS_SITE_ID"),
	Secret:     os.Getenv("ANALYTICS_SITE_SECRET"),
	Endpoint:   "https://collect.sitegoose.com",
	TrustProxy: "1", // behind one proxy (nginx); "cloudflare" behind Cloudflare
})

mux := http.NewServeMux()
mux.HandleFunc("GET /orders/{id}", order)
srv := &http.Server{Addr: ":8080", Handler: p.Middleware(mux)} // outermost
go srv.ListenAndServe()

// On SIGTERM: the server first, then what the package still holds.
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
srv.Shutdown(ctx)
p.Close(ctx)
```

Any of `SiteID`, `Secret`, `Endpoint`, `TrustProxy` and `ServerName` left
empty is read from `ANALYTICS_SITE_ID`, `ANALYTICS_SITE_SECRET`,
`ANALYTICS_ENDPOINT`, `ANALYTICS_TRUST_PROXY` and `ANALYTICS_SERVER_NAME`, so
`sitegoose.New(sitegoose.Options{})` works from the environment alone.

With a `*http.ServeMux` handed to `Middleware`, Server speed and errors name
each request by its pattern (`/orders/{id}`; wildcards need `go 1.22` or
later in your `go.mod`). Anything else: call
`sitegoose.SetRoute(r.Context(), "/orders/:id")`, or give
`Options.Performance.Route`. `p.Close` without a deadline sends for at most
five seconds.

## gin, echo, chi

```go
r := gin.Default()
r.Use(sitegoosegin.Middleware(p))          // after gin.Recovery

e := echo.New()
e.Use(middleware.Recover(), sitegooseecho.Middleware(p))

r := chi.NewRouter()
r.Use(sitegoosechi.Middleware(p))
```

Each names routes the router's way (`/orders/:id`, `/orders/{id}`); gin's
`c.Errors` and an echo handler's returned error are sent at the status they
were answered with. Each also works inside `p.Middleware(router)`. WebSocket
connections aren't timed. The echo adapter answers a handler's error
(`c.Error`) and then returns it, as echo's own middleware does: echo's error
handler leaves a response already sent alone, and a custom
`HTTPErrorHandler` should check `c.Response().Committed` too.

## Modules

All are on unless `Options.Disable` names them; the dashboard can switch each
off. Every module fails open: the collector away, a bug of ours or a timeout
never stops a request.

| Module | What | Options |
| --- | --- | --- |
| `firewall` | Allow/deny/lists/shared/banned/goodbots, probes, request rules, rate limit and local bans, the browser check, failed logins (`p.LoginFailed(r)`). IPv6 is counted and banned here by its /64; a page's own files (.css, .js, images, fonts) don't count towards the rate | `Firewall: FirewallOptions{Mode, CacheFile, TrustProxy, Counter, Skip, OnBlock}` |
| `errors` | Panics, 5xx answers, `p.CaptureError(ctx, err)`, `p.Recover(ctx)` in goroutines, `p.Job`, `p.SlogHandler`, breadcrumbs (`p.AddBreadcrumb`, `p.Transport`) | `Errors: ErrorsOptions{Release, Root, SpoolDir, ShouldCapture, BeforeSend, ...}` |
| `performance` | Server speed: per minute, method, route and status, and the database queries each route ran (below) | `Performance: PerformanceOptions{Route, DisableQueries}` |
| `crawlers` | Health → Crawlers | |
| `analytics` | `p.Track`, `p.Identify`, `p.Lead` | |
| `forms` | `p.CheckForm(r, o)`, `p.ProtectForm(o, onSpam)` | |
| `headers` | The dashboard's security headers, unless the app sets them | |
| `audit` | `p.Audit(ctx, action, AuditEntry{...})` | |
| `flags` | `p.IsEnabled(key, userID)` | |
| `maintenance` | The "back soon" page, allowed addresses, preview link | `Maintenance: MaintenanceOptions{Skip}` |
| `inventory` | The binary's Go modules (from its build info) and Go version | `Inventory: InventoryOptions{Host}` |
| `posture` | Runs as root, writable code (the binary too), net/http/pprof on the default mux, exposed files in `./public` and `./static` | `Posture: PostureOptions{Roots, Checks}` |
| `resources` | CPU, load, memory, disks, network (Linux /proc) | |
| `proxy` | The tracker and its beacon on the site's own domain: `p.Proxy().ScriptURL("")`, `p.Proxy().CollectURL()`. Denied and banned addresses are turned away first; a held tracker file is served at once and refreshed behind it; beacons time out after 3 s, and after five failures in a row are answered at once for 30 s | `Proxy: ProxyOptions{Prefix}` |

## Database queries

Server speed → Queries shows how many queries each route ran and how long
they took. Every value in a query is replaced by `?` here, before it is
counted; bound parameters are never read. A query counts under the request
whose context it was given, so pass `r.Context()`: `db.QueryContext(ctx, …)`,
not `db.Query(…)`, which counts as a background query. Inside `p.Job` it is
the job's.

```go
// database/sql: instead of sql.Open("pgx", dsn)
db, err := sitegoose.OpenDB("pgx", dsn)
// or around a connector / a driver you register yourself
db := sql.OpenDB(p.WrapConnector(connector))
sql.Register("mysql-timed", p.WrapDriver(mysql.MySQLDriver{}))

// pgx v5 natively: go get github.com/sitegoose/sitegoose-go/pgx
config.ConnConfig.Tracer = sitegoosepgx.Tracer(p)

// MongoDB driver v2: go get github.com/sitegoose/sitegoose-go/mongo
client, err := mongo.Connect(options.Client().ApplyURI(uri).SetMonitor(sitegoosemongo.Monitor(p)))
```

The database is told from the driver (`pgx`, `postgres`, `mysql`, `sqlite3`,
`sqlite`, `sqlserver`, `godror`...). A database/sql query is timed until the
driver answers, a pgx query until its rows are closed. pgx through
database/sql with both hooks on is counted once, by the wrapper.
`(*sql.Conn).Raw` hands you the wrapper: `sitegoose.UnwrapConn(c)` is the
driver's own connection. Anything else: `p.RecordQuery(ctx, "postgresql",
sql, elapsed, err)`. `Performance: PerformanceOptions{DisableQueries: true}`
keeps Server speed without queries; switching Server speed off in the
dashboard stops both.

## Errors

A handler's panic is sent with the line that panicked, then panics on, so
net/http answers it as always. A 5xx answer nothing was captured for is sent
too, its stack where the status was written (`http.Error`'s caller) and its
message the plain-text body's first line. `http.ErrAbortHandler` (how
`httputil.ReverseProxy` drops an answer) and a visitor who left before the
answer aren't errors.

**Goroutines you start are not covered by the middleware.** A panic in one
is only sent when it begins with `defer p.Recover(ctx)`:

```go
go func() {
	defer p.Recover(ctx)
	work(ctx)
}()
```

`Recover` sends the panic and panics on, so the program ends as it would
have. On Go 1.23 and later a panic nothing recovers is also written to a
file (`runtime/debug.SetCrashOutput`) and sent at the next start;
`DisableCrashCapture` leaves that off. Queue workers and cron tasks can run
through `p.Job(ctx, "name", fn)`, which sends their errors and times them.

Errors that couldn't be sent wait in a file (1 MB at most) and are sent
within a minute of the collector answering again. That file and the crash
file live in `ErrorsOptions.SpoolDir`, by default `os.TempDir()`, which a
container loses when it restarts: point `SpoolDir` at a volume to keep them.
The release is `ANALYTICS_RELEASE`, else the commit the binary was built from.

`slog` errors are sent when your handler is wrapped:

```go
slog.SetDefault(slog.New(p.SlogHandler(slog.NewJSONHandler(os.Stderr, nil))))
```

Outgoing requests become breadcrumbs through
`&http.Client{Transport: p.Transport(nil)}`.

## Background work

Everything is sent from goroutines with bounded queues. An event or audit
entry json can't encode (a NaN, a channel) is dropped alone and logged with
`Debug`. `p.Flush(ctx)` sends what's waiting (serverless: before returning);
`p.Close(ctx)` stops the background work and sends the rest. The security
headers from the dashboard are only ever plain values, and never the headers
that frame a response (`Content-Length`, `Set-Cookie`, `Connection`...).

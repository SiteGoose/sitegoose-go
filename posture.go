package sitegoose

// How the server is set up (sdk/protocols/posture.md): whether the app runs as
// root, code anyone on the machine can write (the binary itself included),
// whether net/http/pprof's handlers are on http.DefaultServeMux, and files in
// the folders it serves to the web that should never be public. Sent to POST
// /events/posture a few minutes after start and then once a day (the
// collector's `every`), so Security -> Security check can say what to change.
//
// It only reads: nothing here changes a setting, a permission or a file, and
// no file's contents are sent -- paths, sizes, times and short values only.
// The walk is bounded and runs in the background, never in a request; with
// no folder served to the web there is nothing to walk and only the settings
// are reported.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	postureFirst  = 180 * time.Second
	maxChecks     = 200
	maxExposure   = 50
	maxEntries    = 20000
	maxDepth      = 6
	maxPermChecks = 3000
	postureEvery  = 24 * time.Hour
	postureRetry  = time.Hour
	checkIDMax    = 60
	checkValueMax = 200
)

var (
	skipDirs = map[string]bool{".git": true, ".svn": true, ".hg": true, "node_modules": true, "vendor": true,
		"cache": true, ".cache": true, ".history": true, "__pycache__": true}
	codeFile = regexp.MustCompile(`(?i)\.(go|py|pyw|js|cjs|mjs|php[0-9]?|phtml|rb|pl|sh|tmpl|gohtml)$`)
	exposure = []struct {
		kind    string
		pattern *regexp.Regexp
	}{
		{"database_dump", regexp.MustCompile(`(?i)\.sql(\.(gz|bz2|xz|zip))?$`)},
		{"private_key", regexp.MustCompile(`(?i)^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(pem|key|p12|pfx|jks)$`)},
		{"env", regexp.MustCompile(`(?i)^\.env($|\.)|^env\.(ini|txt)$`)},
		{"archive", regexp.MustCompile(`(?i)\.(zip|tar|tgz|tar\.gz|tar\.bz2|rar|7z)$`)},
		{"backup", regexp.MustCompile(`(?i)\.(bak|old|orig|save|swp|copy|backup)$|~$|\.(go|py|json|conf|config|ini|ya?ml|toml)\.(bak|old|orig|save|txt)$`)},
		{"info", regexp.MustCompile(`(?i)^(phpinfo|info|adminer)\.php$`)},
		{"log", regexp.MustCompile(`(?i)^(debug|error|access)[-_.]?log$|\.log$`)},
	}
	checkIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.]*$`)
)

// Root is a folder the web serves, and the path it is served at
// ({Dir: "assets", Prefix: "static"} for http.StripPrefix("/static/", ...)).
type Root struct {
	Dir    string
	Prefix string
}

// Check is one posture check: State "pass", "fail" or "unknown".
type Check struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Value string `json:"value,omitempty"`
}

// PostureOptions configure the set-up checks.
type PostureOptions struct {
	// Roots are the folders the web serves. Default: ./public (served at /)
	// and ./static (served at /static/) when they exist.
	Roots []Root
	// Host is the server's name; default Options.ServerName, else the host name.
	Host string
	// Checks returns more checks of your own.
	Checks func() []Check
}

type exposed struct {
	Path  string `json:"path"`
	Kind  string `json:"kind"`
	Size  *int64 `json:"size,omitempty"`
	MTime string `json:"mtime,omitempty"`
}

func exposureKind(name string) string {
	for _, e := range exposure {
		if e.pattern.MatchString(name) {
			return e.kind
		}
	}
	return ""
}

type postureRoot struct{ dir, prefix string }

// rootsOf: a folder inside another on the list is already covered: without
// this, every file under it would be reported twice.
func rootsOf(given []Root) []postureRoot {
	if len(given) == 0 {
		// Not told: the conventional folders, when they're there, as Go
		// serves them: ./public at the site's root, ./static under /static/
		// (http.StripPrefix("/static/", http.FileServer(http.Dir("static")))).
		for _, d := range []Root{{Dir: "public"}, {Dir: "static", Prefix: "static"}} {
			if info, err := os.Stat(d.Dir); err == nil && info.IsDir() {
				given = append(given, d)
			}
		}
	}
	var roots []postureRoot
	seen := map[string]bool{}
	for _, r := range given {
		if r.Dir == "" {
			continue
		}
		dir, err := filepath.Abs(r.Dir)
		if err != nil || seen[dir] {
			continue
		}
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		seen[dir] = true
		roots = append(roots, postureRoot{dir, strings.Trim(r.Prefix, "/")})
	}
	var out []postureRoot
	for _, r := range roots {
		nested := false
		for _, other := range roots {
			if other.dir != r.dir && strings.HasPrefix(r.dir+string(filepath.Separator), other.dir+string(filepath.Separator)) {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, r)
		}
	}
	return out
}

type walkResult struct {
	exposure  []exposed
	writable  int
	checked   int
	examples  []string
	truncated bool
}

func walkRoots(roots []postureRoot) walkResult {
	var res walkResult
	entries := 0
	for _, root := range roots {
		type folder struct {
			path  string
			depth int
		}
		queue := []folder{{root.dir, 0}}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			list, err := os.ReadDir(current.path)
			if err != nil {
				continue
			}
			for _, entry := range list {
				entries++
				if entries > maxEntries {
					res.truncated = true
					return res
				}
				name := entry.Name()
				full := filepath.Join(current.path, name)
				if entry.Type()&os.ModeSymlink != 0 {
					continue
				}
				rel, _ := filepath.Rel(root.dir, full)
				relative := filepath.ToSlash(rel)
				if root.prefix != "" {
					relative = root.prefix + "/" + relative
				}
				if entry.IsDir() {
					switch name {
					case ".git", ".svn", ".hg", ".bzr":
						if len(res.exposure) < maxExposure {
							res.exposure = append(res.exposure, exposed{Path: relative + "/config", Kind: "vcs"})
						}
						continue
					}
					if current.depth+1 <= maxDepth && !skipDirs[name] {
						queue = append(queue, folder{full, current.depth + 1})
					}
					continue
				}
				if !entry.Type().IsRegular() {
					continue
				}
				info, infoErr := entry.Info()
				if kind := exposureKind(name); kind != "" && len(res.exposure) < maxExposure {
					row := exposed{Path: relative, Kind: kind}
					if infoErr == nil {
						size := info.Size()
						row.Size = &size
						row.MTime = isoMinuteMS(info.ModTime())
					}
					res.exposure = append(res.exposure, row)
				}
				if res.checked < maxPermChecks && codeFile.MatchString(name) && infoErr == nil {
					res.checked++
					if info.Mode().Perm()&0o002 != 0 {
						res.writable++
						if len(res.examples) < 3 {
							res.examples = append(res.examples, relative)
						}
					}
				}
			}
		}
	}
	return res
}

// pprofOnDefaultMux: net/http/pprof registers its handlers on
// http.DefaultServeMux as soon as it is imported, which shows any visitor
// the program's memory and lets them run a CPU profile when that mux is the
// one serving the site.
func pprofOnDefaultMux() bool {
	req, err := http.NewRequest(http.MethodGet, "http://localhost/debug/pprof/", nil)
	if err != nil {
		return false
	}
	_, pattern := http.DefaultServeMux.Handler(req)
	return strings.Contains(pattern, "/debug/pprof/")
}

type posture struct {
	core  *core
	roots []postureRoot
	extra func() []Check
	host  string
	job   *periodic
}

func newPosture(c *core, o PostureOptions) *posture {
	p := &posture{core: c, roots: rootsOf(o.Roots), extra: o.Checks, host: cleanHost(firstNonEmpty(o.Host, hostname()))}
	p.job = c.every(postureFirst, p.reportJob)
	return p
}

// report is what would be reported now.
func (p *posture) report() map[string]any {
	walk := walkRoots(p.roots)
	var checks []Check
	if uid, ok := userID(); ok {
		// Running the web app as root turns any hole in it into the whole machine.
		checks = append(checks, Check{ID: "server.runs_as_root", State: passFail(uid == 0)})
	}
	// The binary is the code: one anyone on the machine can replace is theirs at the next restart.
	if exe, err := os.Executable(); err == nil {
		if info, err := os.Stat(exe); err == nil {
			walk.checked++
			if info.Mode().Perm()&0o002 != 0 {
				walk.writable++
				walk.examples = append([]string{filepath.Base(exe)}, walk.examples...)
				if len(walk.examples) > 3 {
					walk.examples = walk.examples[:3]
				}
			}
		}
	}
	if walk.checked > 0 {
		row := Check{ID: "server.code_writable", State: passFail(walk.writable > 0)}
		if walk.writable > 0 {
			row.Value = truncate(fmt.Sprintf("%d files, e.g. %s", walk.writable, strings.Join(walk.examples, ", ")), checkValueMax)
		}
		checks = append(checks, row)
	}
	pprof := Check{ID: "app.go_pprof", State: passFail(pprofOnDefaultMux())}
	if pprof.State == "fail" {
		pprof.Value = "/debug/pprof/ on http.DefaultServeMux"
	}
	checks = append(checks, pprof)
	checks = append(checks, p.ownChecks()...)
	if len(checks) > maxChecks {
		checks = checks[:maxChecks]
	}
	body := map[string]any{
		"site_id": p.core.siteID, "host": p.host, "at": isoNow(), "checks": checks,
		"facts": map[string]string{"agent": "go/" + goVersion()},
	}
	if len(p.roots) > 0 {
		// Left out when there's no folder to walk: the dashboard then says
		// this wasn't checked, instead of taking an empty walk for a clean one.
		list := walk.exposure
		if list == nil {
			list = []exposed{}
		}
		body["exposure"] = list
		body["facts"].(map[string]string)["webroot"] = p.roots[0].dir
	}
	if walk.truncated {
		body["truncated"] = true
	}
	return body
}

func passFail(failed bool) string {
	if failed {
		return "fail"
	}
	return "pass"
}

func (p *posture) ownChecks() (out []Check) {
	if p.extra == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	for _, c := range p.extra() {
		id := strings.ToLower(truncate(c.ID, checkIDMax))
		if !checkIDPattern.MatchString(id) || (c.State != "pass" && c.State != "fail" && c.State != "unknown") {
			continue
		}
		out = append(out, Check{ID: id, State: c.State, Value: truncate(c.Value, checkValueMax)})
	}
	return out
}

func (p *posture) reportJob() time.Duration {
	// The set-up checks ride the software inventory switch.
	if !p.core.isOn(ModuleInventory) {
		return postureRetry
	}
	res := p.core.send(context.Background(), "posture", "/events/posture", http.MethodPost, p.report(), authBearer, nil)
	if !res.ok() {
		return postureRetry
	}
	var answer struct {
		Every float64 `json:"every"`
	}
	every := postureEvery
	if res.json(&answer) && answer.Every > 0 {
		every = time.Duration(answer.Every) * time.Second
	}
	if every < postureRetry {
		every = postureRetry
	}
	return every
}

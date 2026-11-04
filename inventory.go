package sitegoose

// Software inventory module (sdk/protocols/inventory.md): the Go modules
// compiled into the binary (runtime/debug.ReadBuildInfo, the list go version
// -m prints) and the Go version, sent to POST /events/inventory a minute
// after start and then once a day (the collector's `every`), so the Security
// check can match them against known security holes (OSV.dev's "Go"
// ecosystem, which also lists the standard library as "stdlib"). Runs in the
// background, never in a request; names and versions only.
//
// It is what the binary was built from, not a lock file next to it: a Go
// server is one binary, and the build info is the one list that can't
// disagree with what runs.

import (
	"context"
	"net/http"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

const (
	inventoryFirst = 60 * time.Second
	inventoryRetry = time.Hour
	inventoryEvery = 24 * time.Hour
	maxPackages    = 5000
)

// InventoryOptions configure the software inventory.
type InventoryOptions struct {
	// Host is the server's name; default Options.ServerName, else the host name.
	Host string
}

type inventoryPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

var hostChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func cleanHost(host string) string {
	if out := truncate(hostChars.ReplaceAllString(host, "-"), 100); out != "" {
		return out
	}
	return "server"
}

// moduleVersion is a module version as the protocol wants it: no leading
// "v", and nothing for a module built from a folder ("(devel)").
func moduleVersion(v string) string {
	if v == "" || v == "(devel)" {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}

// buildPackages lists the modules in info, each once, a replaced module
// under what replaced it (that is the code in the binary), plus the standard
// library at the Go version.
func buildPackages(info *debug.BuildInfo, goVer string) []inventoryPackage {
	found := map[string]inventoryPackage{}
	add := func(path, version string) {
		version = moduleVersion(version)
		if path == "" || version == "" {
			return
		}
		if _, seen := found[path]; !seen {
			found[path] = inventoryPackage{Ecosystem: "Go", Name: path, Version: version}
		}
	}
	if info != nil {
		add(info.Main.Path, info.Main.Version)
		for _, dep := range info.Deps {
			if dep.Replace != nil {
				add(dep.Replace.Path, dep.Replace.Version)
				continue
			}
			add(dep.Path, dep.Version)
		}
	}
	if goVer != "" {
		add("stdlib", goVer)
	}
	out := make([]inventoryPackage, 0, len(found))
	for _, p := range found {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

type inventory struct {
	core *core
	host string
	job  *periodic
}

func newInventory(c *core, o InventoryOptions) *inventory {
	i := &inventory{core: c, host: cleanHost(firstNonEmpty(o.Host, hostname()))}
	i.job = c.every(inventoryFirst, i.report)
	return i
}

func (i *inventory) body() map[string]any {
	info, _ := debug.ReadBuildInfo()
	packages := buildPackages(info, goVersion())
	truncated := len(packages) > maxPackages
	if truncated {
		packages = packages[:maxPackages]
	}
	return map[string]any{
		"site_id": i.core.siteID, "host": i.host, "at": isoNow(),
		"runtime": map[string]string{"go": goVersion()}, "packages": packages, "truncated": truncated,
	}
}

func (i *inventory) report() time.Duration {
	if !i.core.isOn(ModuleInventory) {
		return inventoryRetry
	}
	res := i.core.send(context.Background(), "inventory", "/events/inventory", http.MethodPost, i.body(), authBearer, nil)
	if !res.ok() {
		return inventoryRetry
	}
	var answer struct {
		Every float64 `json:"every"`
	}
	if res.json(&answer) && answer.Every > 0 {
		if every := time.Duration(answer.Every) * time.Second; every > inventoryRetry {
			return every
		}
		return inventoryRetry
	}
	return inventoryEvery
}

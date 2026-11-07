package sitegoose

// How close the app is to a wall, for the resources module
// (sdk/protocols/resources.md, "Limits"): its container's own caps, the
// machine's waiting time, connections refused before the app saw them, the
// process's open files, its Go memory limit, garbage collection pauses and
// the most requests in progress at once. A port of the Node package's
// lib/limits.js, which is the reference.
//
// The rest of resources.go says how busy the machine is. Inside Docker or
// Kubernetes that is the wrong question: /proc/meminfo is the host's, so
// memory reads 40% while the container is a few megabytes from being killed.
// The cgroup's files are the limits the kernel actually enforces.
//
// Same rule as the rest of the module: a figure this machine won't give us
// is left out of the row, never sent as a zero. Every reader here gives
// nothing for a file that isn't there, which on anything but Linux is all
// of them.

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"regexp"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"time"
)

// cgroup v1 says "no limit" with the largest page-aligned 64-bit number; v2
// says "max". Anything this size is not a cap a machine has.
const noLimitBytes = float64(1 << 62)

// processStart is when the package was loaded, which is when the process
// started as near as the standard library can say.
var processStart = time.Now()

// newProcKey is the random key a process picks once, so two processes under
// one server name (or one that restarted) aren't one line.
func newProcKey() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// limNum is the number in a file holding one; false for a missing or
// unreadable one. An empty file is not 0.
func limNum(text string) (float64, bool) {
	t := strings.TrimSpace(text)
	if t == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(t, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

// keyValues are "name value" lines (memory.stat, cpu.stat, memory.events) as numbers.
func keyValues(text string) map[string]float64 {
	out := map[string]float64{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if v, ok := limNum(f[1]); ok {
			out[f[0]] = v
		}
	}
	return out
}

// optF is a reading that may be missing.
type optF struct {
	v  float64
	ok bool
}

func have(v float64) optF { return optF{v, true} }

func kv(m map[string]float64, name string) optF {
	v, ok := m[name]
	return optF{v, ok}
}

// cgroupPathSet are the paths /proc/self/cgroup names; "" for one it doesn't.
type cgroupPathSet struct{ v2, memory, cpu string }

// cgroupPaths reads /proc/self/cgroup: the v2 path ("0::<path>") and the v1
// memory and cpu controllers' paths ("4:memory:<path>", "3:cpu,cpuacct:<path>").
func cgroupPaths(text string) cgroupPathSet {
	var out cgroupPathSet
	for _, line := range strings.Split(text, "\n") {
		id, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		controllers, at, ok := strings.Cut(rest, ":")
		at = strings.TrimSpace(at)
		if !ok || at == "" {
			continue
		}
		if id == "0" && controllers == "" {
			out.v2 = at
		}
		for _, c := range strings.Split(controllers, ",") {
			switch c {
			case "memory":
				out.memory = at
			case "cpu":
				out.cpu = at
			}
		}
	}
	return out
}

// cgroupDirs is where this process's cgroup files are: one directory for
// v2, the memory and cpu controllers' for v1 ("" when that one isn't there).
type cgroupDirs struct {
	version     int
	memory, cpu string
}

// findCgroup looks under the mount at the path /proc/self/cgroup names
// first, then the mount itself: in a container with its own cgroup
// namespace the path is "/" and the mount is already the container's;
// without one the path names the host's hierarchy. v2 needs the memory or
// cpu controller's own files, not just the directory: a hybrid machine
// lists a v2 path with no controllers in it while the limits live in v1.
func findCgroup(read func(string) string) *cgroupDirs {
	paths := cgroupPaths(read("/proc/self/cgroup"))
	under := func(base, at string, probes ...string) string {
		dirs := []string{base}
		if at != "" && at != "/" {
			dirs = []string{base + at, base}
		}
		for _, dir := range dirs {
			for _, probe := range probes {
				if read(dir+"/"+probe) != "" {
					return dir
				}
			}
		}
		return ""
	}
	if paths.v2 != "" {
		if dir := under("/sys/fs/cgroup", paths.v2, "memory.current", "cpu.max"); dir != "" {
			return &cgroupDirs{version: 2, memory: dir, cpu: dir}
		}
	}
	var memory, cpu string
	if paths.memory != "" {
		memory = under("/sys/fs/cgroup/memory", paths.memory, "memory.usage_in_bytes")
	}
	if paths.cpu != "" {
		cpu = under("/sys/fs/cgroup/cpu", paths.cpu, "cpu.cfs_quota_us")
	}
	if memory == "" && cpu == "" {
		return nil
	}
	return &cgroupDirs{version: 1, memory: memory, cpu: cpu}
}

// cgroupReading is one reading of the cgroup's caps and counters, in bytes
// and raw counts. The counters (periods, throttled, oom) need two readings.
type cgroupReading struct {
	memCap, memUsed, cpuCores, periods, throttled, oom optF
}

func readCgroup(cg *cgroupDirs, read func(string) string) *cgroupReading {
	if cg == nil {
		return nil
	}
	out := &cgroupReading{}
	if cg.version == 2 {
		if max := strings.TrimSpace(read(cg.memory + "/memory.max")); max != "max" {
			v, ok := limNum(max)
			out.memCap = optF{v, ok}
		}
		// The working set: page cache counts against the cgroup too, so
		// memory.current sits near the cap on a healthy container that reads
		// files. Less inactive_file is what Docker and the kubelet report.
		if current, ok := limNum(read(cg.memory + "/memory.current")); ok {
			stat := keyValues(read(cg.memory + "/memory.stat"))
			out.memUsed = have(math.Max(0, current-stat["inactive_file"]))
		}
		out.oom = kv(keyValues(read(cg.memory+"/memory.events")), "oom_kill")
		f := strings.Fields(read(cg.cpu + "/cpu.max"))
		if len(f) == 2 && f[0] != "max" {
			quota, ok1 := limNum(f[0])
			period, ok2 := limNum(f[1])
			if ok1 && ok2 && quota > 0 && period > 0 {
				out.cpuCores = have(quota / period)
			}
		}
		cpu := keyValues(read(cg.cpu + "/cpu.stat"))
		out.periods, out.throttled = kv(cpu, "nr_periods"), kv(cpu, "nr_throttled")
		return out
	}
	if cg.memory != "" {
		v, ok := limNum(read(cg.memory + "/memory.limit_in_bytes"))
		out.memCap = optF{v, ok}
		if usage, ok := limNum(read(cg.memory + "/memory.usage_in_bytes")); ok {
			stat := keyValues(read(cg.memory + "/memory.stat"))
			out.memUsed = have(math.Max(0, usage-stat["total_inactive_file"]))
		}
		// Kernels from 4.13 carry the count here.
		out.oom = kv(keyValues(read(cg.memory+"/memory.oom_control")), "oom_kill")
	}
	if cg.cpu != "" {
		quota, ok1 := limNum(read(cg.cpu + "/cpu.cfs_quota_us"))
		period, ok2 := limNum(read(cg.cpu + "/cpu.cfs_period_us"))
		if ok1 && ok2 && quota > 0 && period > 0 {
			out.cpuCores = have(quota / period)
		}
		cpu := keyValues(read(cg.cpu + "/cpu.stat"))
		out.periods, out.throttled = kv(cpu, "nr_periods"), kv(cpu, "nr_throttled")
	}
	return out
}

// countSince is how much a counter moved between two readings; false with
// no pair, or when it went down, which is a reset and not a negative count.
// Unlike a rate a count is never dropped for the pair being far apart: a
// kill is a kill.
func countSince(before, after optF) (float64, bool) {
	if !before.ok || !after.ok || after.v < before.v {
		return 0, false
	}
	return after.v - before.v, true
}

// cgroupFields are the row's cgroup fields from two readings. A cap at or
// above what the machine itself has isn't one (a systemd slice with no
// MemoryMax, or a container allowed more cores than the host), so neither
// half is sent. memTotalMB and cores are 0 when unknown.
func cgroupFields(before, after *cgroupReading, memTotalMB int64, cores int) map[string]any {
	out := map[string]any{}
	if after == nil {
		return out
	}
	if before == nil {
		before = &cgroupReading{}
	}
	if after.memCap.ok && after.memCap.v > 0 && after.memCap.v < noLimitBytes && after.memUsed.ok {
		capMB := int64(after.memCap.v / mb)
		if capMB > 0 && !(memTotalMB > 0 && capMB >= memTotalMB) {
			out["limit_mem_mb"] = capMB
			used := int64(after.memUsed.v / mb)
			if used > capMB {
				used = capMB
			}
			out["limit_mem_used_mb"] = used
		}
	}
	if after.cpuCores.ok && after.cpuCores.v > 0 && !(cores > 0 && after.cpuCores.v >= float64(cores)) {
		out["limit_cpu_cores"] = round(after.cpuCores.v, 2)
	}
	// Periods only pass while a quota is set, so no cap means nothing sent.
	periods, ok1 := countSince(before.periods, after.periods)
	throttled, ok2 := countSince(before.throttled, after.throttled)
	if ok1 && ok2 && periods > 0 {
		out["cpu_throttled_pct"] = round(math.Min(100, 100*throttled/periods), 1)
	}
	// Kills of other processes in this cgroup. This process's own kill can't
	// be reported by it: see the protocol.
	if oom, ok := countSince(before.oom, after.oom); ok {
		out["oom_kills"] = int64(oom)
	}
	return out
}

var pressureAvg60 = regexp.MustCompile(`(?m)^some\b[^\n]*\bavg60=([\d.]+)`)

// pressureSome is /proc/pressure/<resource>'s "some" line, avg60: the share
// of the last minute in which at least one task was waiting.
func pressureSome(text string) (float64, bool) {
	m := pressureAvg60.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return round(math.Min(100, v), 1), true
}

// pressureFields are the machine's waiting time, even in a container (where
// it is the host's). A kernel without PSI has no such files: left out.
func pressureFields(read func(string) string) map[string]any {
	out := map[string]any{}
	for _, x := range [][2]string{{"psi_cpu_pct", "cpu"}, {"psi_mem_pct", "memory"}, {"psi_io_pct", "io"}} {
		if v, ok := pressureSome(read("/proc/pressure/" + x[1])); ok {
			out[x[0]] = v
		}
	}
	return out
}

// listenOverflows is TcpExt ListenOverflows from /proc/net/netstat:
// connections refused since boot because the accept queue was full. A
// header line and a value line.
func listenOverflows(text string) optF {
	lines := strings.Split(text, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "TcpExt:") || !strings.HasPrefix(lines[i+1], "TcpExt:") {
			continue
		}
		names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		for at, name := range names {
			if name == "ListenOverflows" && at > 0 && at < len(values) {
				v, ok := limNum(values[at])
				return optF{v, ok}
			}
		}
		return optF{}
	}
	return optF{}
}

// conntrackPct is how full the connection-tracking table is. Only where the
// firewall loaded it, and usually unreadable inside a container.
func conntrackPct(read func(string) string) (float64, bool) {
	count, ok1 := limNum(read("/proc/sys/net/netfilter/nf_conntrack_count"))
	max, ok2 := limNum(read("/proc/sys/net/netfilter/nf_conntrack_max"))
	if !ok1 || !ok2 || max <= 0 {
		return 0, false
	}
	return round(math.Min(100, 100*count/max), 1), true
}

var maxOpenFiles = regexp.MustCompile(`(?m)^Max open files\s+(\S+)`)

// fdLimit is the soft "Max open files" from /proc/self/limits; false when
// unlimited or unknown.
func fdLimit(text string) (int64, bool) {
	m := maxOpenFiles.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

// fileFields are the open files against the soft limit. list is the count
// of /proc/self/fd's entries, less the one listing them takes.
func fileFields(read func(string) string, list func() (int64, bool)) map[string]any {
	out := map[string]any{}
	max, hasMax := fdLimit(read("/proc/self/limits"))
	if list != nil {
		if used, ok := list(); ok {
			if hasMax && used > max {
				used = max
			}
			out["fds_used"] = used
		}
	}
	if hasMax {
		out["fds_max"] = max
	}
	return out
}

// goMemory is what counts against Go's memory limit (everything the runtime
// has mapped and not given back) and the limit itself, in bytes; false with
// no limit set (GOMEMLIMIT or debug.SetMemoryLimit), which is the default.
func goMemory() (used, limit int64, ok bool) {
	limit = debug.SetMemoryLimit(-1) // -1 reads it without changing it
	if limit <= 0 || limit == math.MaxInt64 {
		return 0, 0, false
	}
	samples := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindUint64 || samples[1].Value.Kind() != metrics.KindUint64 {
		return 0, 0, false
	}
	total, released := samples[0].Value.Uint64(), samples[1].Value.Uint64()
	if released > total {
		released = total
	}
	return int64(total - released), limit, true
}

// heapFields: the Go runtime's memory against the limit it collects hard at,
// a different wall from the container's.
func heapFields(read func() (int64, int64, bool)) map[string]any {
	out := map[string]any{}
	if read == nil {
		return out
	}
	used, limit, ok := read()
	if !ok || used <= 0 || limit <= 0 {
		return out
	}
	out["heap_used_mb"] = used / mb
	out["heap_max_mb"] = limit / mb
	return out
}

// gcPauses is the total time the program has been stopped for garbage
// collection, from the runtime's own count (no stop of its own to read it).
func gcPauses() (time.Duration, bool) {
	var stats debug.GCStats
	debug.ReadGCStats(&stats)
	return stats.PauseTotal, true
}

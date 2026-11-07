package sitegoose

// How the machine is doing (sdk/protocols/resources.md): CPU, load, memory,
// swap, disks, disk and network throughput and this process's memory, and
// how close the app is to a limit (limits.go),
// sampled every minute and sent to POST /events/resources every few minutes.
// The companion of Server speed: that says how the requests went, this says
// whether the box can still serve them.
//
// Nothing is guessed. A reading this machine won't give us is left out of the
// row, never sent as a zero: the collector stores it as NULL and the
// dashboard shows "-". Linux has every reading (/proc and statfs); other
// systems send what they have, and a Windows server the disks it can't name
// here not at all.

import (
	"context"
	"math"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Keep in step with the collector (expresscollect/Analytics/resources.js) and
// the agent (sdk/vps-agent).
const (
	sampleEvery     = 60 * time.Second
	resourcesEvery  = 5 * time.Minute
	resourcesRetry  = 60 * time.Second
	resourcesOff    = 10 * time.Minute
	maxResourceRows = 500
	maxDisks        = 20
	minDiskMB       = 1024
	minCPUSeconds   = 1.0
	ioSector        = 512
	ioMaxPair       = 300.0
	mb              = 1024 * 1024
)

// Real on-disk filesystems only: no tmpfs, devtmpfs, proc, sysfs, cgroup or
// squashfs (snaps), none of which are the customer's disk. overlay is here so
// a containerised app still reports something sensible.
var fsTypes = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "ufs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true,
	"overlay": true, "apfs": true, "hfs": true}

var (
	// Not disks: loop and ram devices, optical drives, device-mapper and md,
	// each of which would count what is underneath it a second time.
	ioNotADisk = regexp.MustCompile(`^(?:loop|ram|zram|sr|fd|dm-|md\d)`)
	// Partitions, which must not be counted alongside their disk.
	ioPartition = regexp.MustCompile(`^(?:(?:sd|vd|xvd|hd)[a-z]+\d+|(?:nvme\d+n\d+|mmcblk\d+)p\d+)$`)
	// Loopback and the virtual ends of container and VM networking.
	netNotReal = regexp.MustCompile(`^(?:lo|veth|docker|br-|virbr|tap|tun|vnet)`)
)

func readText(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 65536)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

// cpuFields are the jiffy counters from /proc/stat's first line: user, nice,
// system, idle, iowait, irq, softirq, steal (as many as the kernel has).
func cpuFields(text string) []int64 {
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		var out []int64
		for _, f := range strings.Fields(line)[1:] {
			v, err := strconv.ParseInt(f, 10, 64)
			if err != nil {
				return nil
			}
			out = append(out, v)
		}
		if len(out) < 4 {
			return nil
		}
		return out
	}
	return nil
}

// cpuTotal counts every jiffy once. guest and guest_nice (columns 9 and 10)
// are already inside user and nice, so they are left out, as psutil and top
// do: counting them again reads a busy hypervisor as half idle.
func cpuTotal(f []int64) int64 {
	var total int64
	for i, v := range f {
		if i >= 8 {
			break
		}
		total += v
	}
	return total
}

func cpuTimes(f []int64) (busy, total int64) {
	total = cpuTotal(f)
	idle := f[3]
	if len(f) > 4 {
		idle += f[4]
	}
	return total - idle, total
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// cpuPercent is how busy the machine was between two readings; false when
// the pair can't say: the first sample, a counter reset, or no time passed.
func cpuPercent(before, after []int64) (float64, bool) {
	if len(before) < 4 || len(after) < 4 {
		return 0, false
	}
	b0, t0 := cpuTimes(before)
	b1, t1 := cpuTimes(after)
	busy, total := b1-b0, t1-t0
	if total <= 0 || busy < 0 {
		return 0, false
	}
	return round(math.Min(100, 100*float64(busy)/float64(total)), 1), true
}

// cpuShares is where the machine's time went between two readings: user
// (with nice, as top adds them), system, iowait and steal. A column the
// kernel is too old to carry is left out rather than sent as a zero.
func cpuShares(before, after []int64) map[string]float64 {
	out := map[string]float64{}
	if len(before) < 4 || len(after) < 4 {
		return out
	}
	total := cpuTotal(after) - cpuTotal(before)
	if total <= 0 {
		return out
	}
	shares := []struct {
		name    string
		columns []int
	}{{"cpu_user_pct", []int{0, 1}}, {"cpu_system_pct", []int{2}}, {"cpu_iowait_pct", []int{4}}, {"cpu_steal_pct", []int{7}}}
	for _, s := range shares {
		var moved int64
		missing := false
		for _, i := range s.columns {
			if i >= len(before) || i >= len(after) {
				missing = true
				break
			}
			moved += after[i] - before[i]
		}
		if missing {
			continue
		}
		if moved < 0 {
			return map[string]float64{}
		}
		out[s.name] = round(math.Min(100, 100*float64(moved)/float64(total)), 1)
	}
	return out
}

// diskCounters are bytes read and written since boot over the real disks.
func diskCounters(text string) (read, written int64, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		name := f[2]
		if ioNotADisk.MatchString(name) || ioPartition.MatchString(name) {
			continue
		}
		r, err1 := strconv.ParseInt(f[5], 10, 64)
		w, err2 := strconv.ParseInt(f[9], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		read += r * ioSector
		written += w * ioSector
		ok = true
	}
	return read, written, ok
}

// netCounters are bytes in and out since boot over the real interfaces.
func netCounters(text string) (rx, tx int64, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || netNotReal.MatchString(name) {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, err1 := strconv.ParseInt(f[0], 10, 64)
		t, err2 := strconv.ParseInt(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rx += r
		tx += t
		ok = true
	}
	return rx, tx, ok
}

// rateMBs is megabytes a second between two byte counters; false when the
// pair can't say: a reboot that reset them, no time, or too long a gap to
// call it a rate for this minute.
func rateMBs(before, after int64, seconds float64) (float64, bool) {
	if seconds <= 0 || seconds > ioMaxPair {
		return 0, false
	}
	moved := after - before
	if moved < 0 {
		return 0, false
	}
	return round(float64(moved)/seconds/mb, 1), true
}

// memoryMB reads MemTotal/MemAvailable/Swap from /proc/meminfo, in whole
// megabytes. Used is total - MemAvailable, never total - MemFree: page cache
// is not pressure, and counting it as used makes every healthy Linux box look full.
func memoryMB(text string) map[string]int64 {
	values := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		name, rest, _ := strings.Cut(line, ":")
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		if v, err := strconv.ParseInt(f[0], 10, 64); err == nil {
			values[name] = v / 1024
		}
	}
	out := map[string]int64{}
	if total, ok := values["MemTotal"]; ok {
		out["mem_total_mb"] = total
		if avail, ok := values["MemAvailable"]; ok {
			out["mem_used_mb"] = max64(0, total-avail)
		}
	}
	if total, ok := values["SwapTotal"]; ok {
		out["swap_total_mb"] = total
		if free, ok := values["SwapFree"]; ok {
			out["swap_used_mb"] = max64(0, total-free)
		}
	}
	return out
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// mountPoints are the real disks behind /proc/mounts, one per device under
// its shortest mount point, so a bind mount isn't reported as a second disk.
// A mount point has to be a directory (Docker bind-mounts single files such
// as /etc/hosts on the host's own device); a device whose mounts can't be
// confirmed keeps its shortest one. Without a mount table, the one
// filesystem we can name without guessing is the root.
func mountPoints(mounts string, isDir func(string) bool) []string {
	if mounts == "" {
		return []string{"/"}
	}
	if isDir == nil {
		isDir = func(p string) bool {
			info, err := os.Stat(p)
			return err == nil && info.IsDir()
		}
	}
	dirs, shortest := map[string]string{}, map[string]string{}
	var devices []string
	for _, line := range strings.Split(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		device, mount, fstype := f[0], strings.ReplaceAll(f[1], `\040`, " "), f[2]
		if !fsTypes[fstype] || !strings.HasPrefix(mount, "/") {
			continue
		}
		if old, seen := shortest[device]; !seen || len(mount) < len(old) {
			if !seen {
				devices = append(devices, device)
			}
			shortest[device] = mount
		}
		if isDir(mount) {
			if old, seen := dirs[device]; !seen || len(mount) < len(old) {
				dirs[device] = mount
			}
		}
	}
	set := map[string]bool{}
	for _, d := range devices {
		if m, ok := dirs[d]; ok {
			set[m] = true
		} else {
			set[shortest[d]] = true
		}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// fsStat is what statfs says about one filesystem, in its own blocks.
type fsStat struct {
	block, blocks, free, avail, files, filesFree uint64
}

// diskRows: both figures are df's, so a customer can check them: used is
// total minus free, and total is used plus what's available to us. The
// blocks reserved for root are in neither, which is what makes used/total
// the percentage df prints. One filesystem can sit behind two devices the
// kernel calls different (a container's overlay and a bind of the host disk
// under it), so a mount whose raw sizes match an earlier one is the same disk.
func diskRows(points []string, stat func(string) (fsStat, bool)) []map[string]any {
	if stat == nil {
		return nil
	}
	seen := map[[2]uint64]bool{}
	var rows []map[string]any
	for _, mount := range points {
		st, ok := stat(mount)
		if !ok || st.block == 0 || st.blocks == 0 {
			continue
		}
		used := (st.blocks - minU(st.free, st.blocks)) * st.block
		total := used + st.avail*st.block
		row := map[string]any{"mount": mount, "total_mb": total / mb, "used_mb": used / mb}
		if total/mb < minDiskMB {
			continue
		}
		if seen[[2]uint64{total, used}] {
			continue
		}
		seen[[2]uint64{total, used}] = true
		// A filesystem can refuse a write with gigabytes free once these meet.
		if st.files > 0 {
			row["inodes_total"] = st.files
			row["inodes_used"] = st.files - minU(st.filesFree, st.files)
		}
		rows = append(rows, row)
		if len(rows) >= maxDisks {
			break
		}
	}
	return rows
}

func minU(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func hostUptime(text string) (int64, bool) {
	f := strings.Fields(text)
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, false
	}
	return int64(v), true
}

func loadAverage(text string) map[string]float64 {
	f := strings.Fields(text)
	if len(f) < 3 {
		return nil
	}
	out := map[string]float64{}
	for i, name := range []string{"load1", "load5", "load15"} {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return nil
		}
		out[name] = round(v, 2)
	}
	return out
}

// processRSS is the application's own memory: the package runs inside it,
// so unlike the agent it can honestly say.
func processRSS(text string) (int64, bool) {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					return max64(1, v/1024), true
				}
			}
			return 0, false
		}
	}
	return 0, false
}

// machineCores counts the machine's CPUs (/proc/stat's cpuN lines), which is
// what makes a load figure readable; runtime.NumCPU is this process's share.
func machineCores(stat string) int {
	n := 0
	for _, line := range strings.Split(stat, "\n") {
		if len(line) > 3 && strings.HasPrefix(line, "cpu") && line[3] >= '0' && line[3] <= '9' {
			n++
		}
	}
	if n == 0 {
		n = runtime.NumCPU()
	}
	return n
}

// ResourcesOptions configure the machine's readings.
type ResourcesOptions struct {
	// ServerName is the server's name as the dashboard shows it; default
	// Options.ServerName, else the host name.
	ServerName string
}

type resources struct {
	core       *core
	serverName string

	mu       sync.Mutex
	rows     map[string]map[string]any
	every    time.Duration
	enabled  bool
	lastCPU  []int64
	lastDisk [2]int64
	hasDisk  bool
	lastNet  [2]int64
	hasNet   bool
	lastAt   time.Time
	sampler  *periodic
	job      *periodic
	read     func(string) string
	stat     func(string) (fsStat, bool)

	// The limits pass (limits.go).
	procKey       string
	cgroup        *cgroupDirs
	lastCgroup    *cgroupReading
	lastOverflows optF
	lastGC        optF // total GC pause, in ms
	inflight      func() (int64, bool)
	listFDs       func() (int64, bool)
	goMemory      func() (int64, int64, bool)
	gcPauses      func() (time.Duration, bool)
	uptime        func() time.Duration
}

func newResources(c *core, o ResourcesOptions) *resources { return newResourcesFor(c, o, nil) }

// newResourcesFor: perf, when Server speed is on, gives the most requests
// in progress at once.
func newResourcesFor(c *core, o ResourcesOptions, perf *performance) *resources {
	r := &resources{core: c, serverName: truncate(firstNonEmpty(o.ServerName, hostname()), 100),
		rows: map[string]map[string]any{}, every: resourcesEvery, enabled: true, read: readText, stat: statFS,
		procKey: newProcKey(), listFDs: openFiles, goMemory: goMemory, gcPauses: gcPauses,
		uptime: func() time.Duration { return time.Since(processStart) }}
	if perf != nil {
		r.inflight = perf.takeInflightPeak
	}
	r.prime(time.Now())
	r.sampler = c.every(sampleEvery, func() time.Duration {
		r.sample(time.Now())
		return sampleEvery
	})
	r.job = c.every(resourcesEvery, r.report)
	return r
}

func (r *resources) prime(at time.Time) {
	r.lastCPU = cpuFields(r.read("/proc/stat"))
	rd, wr, ok := diskCounters(r.read("/proc/diskstats"))
	r.lastDisk, r.hasDisk = [2]int64{rd, wr}, ok
	rx, tx, ok := netCounters(r.read("/proc/net/dev"))
	r.lastNet, r.hasNet = [2]int64{rx, tx}, ok
	r.lastAt = at
	r.cgroup = findCgroup(r.read)
	r.lastCgroup = readCgroup(r.cgroup, r.read)
	r.lastOverflows = listenOverflows(r.read("/proc/net/netstat"))
	if d, ok := r.gcPauses(); ok {
		r.lastGC = have(float64(d) / float64(time.Millisecond))
	}
}

// limitsRow is the limits pass for one sample: caps and counters diffed
// against the previous sample's, the rest read once. Only sample calls it,
// from the one sampling goroutine.
func (r *resources) limitsRow(row map[string]any) map[string]any {
	out := map[string]any{"proc_uptime_s": int64(r.uptime().Seconds())}
	if r.procKey != "" {
		out["proc_key"] = r.procKey
	}
	memTotal, _ := row["mem_total_mb"].(int64)
	cores, _ := row["cpu_cores"].(int)
	reading := readCgroup(r.cgroup, r.read)
	for k, v := range cgroupFields(r.lastCgroup, reading, memTotal, cores) {
		out[k] = v
	}
	r.lastCgroup = reading
	for k, v := range pressureFields(r.read) {
		out[k] = v
	}
	overflows := listenOverflows(r.read("/proc/net/netstat"))
	if drops, ok := countSince(r.lastOverflows, overflows); ok {
		out["listen_drops"] = int64(drops)
	}
	r.lastOverflows = overflows
	if pct, ok := conntrackPct(r.read); ok {
		out["conntrack_pct"] = pct
	}
	for k, v := range fileFields(r.read, r.listFDs) {
		out[k] = v
	}
	for k, v := range heapFields(r.goMemory) {
		out[k] = v
	}
	gc := optF{}
	if d, ok := r.gcPauses(); ok {
		gc = have(float64(d) / float64(time.Millisecond))
	}
	if ms, ok := countSince(r.lastGC, gc); ok {
		out["gc_ms"] = round(ms, 1)
	}
	r.lastGC = gc
	if r.inflight != nil {
		if peak, ok := r.inflight(); ok && peak >= 0 {
			out["inflight_peak"] = peak
		}
	}
	return out
}

// sample takes one sample, covering the time since the last one.
func (r *resources) sample(at time.Time) map[string]any {
	statText := r.read("/proc/stat")
	cpu := cpuFields(statText)
	rd, wr, diskOK := diskCounters(r.read("/proc/diskstats"))
	rx, tx, netOK := netCounters(r.read("/proc/net/dev"))
	r.mu.Lock()
	lastCPU, lastDisk, hasDisk, lastNet, hasNet, lastAt := r.lastCPU, r.lastDisk, r.hasDisk, r.lastNet, r.hasNet, r.lastAt
	r.lastCPU, r.lastDisk, r.hasDisk, r.lastNet, r.hasNet, r.lastAt = cpu, [2]int64{rd, wr}, diskOK, [2]int64{rx, tx}, netOK, at
	r.mu.Unlock()
	elapsed := at.Sub(lastAt).Seconds()
	// The minute the interval started in, not the one it ended in.
	row := map[string]any{"minute": isoMinute(time.Unix(lastAt.Unix()/60*60, 0))}
	for k, v := range cpuShares(lastCPU, cpu) {
		row[k] = v
	}
	if hasDisk && diskOK {
		if v, ok := rateMBs(lastDisk[0], rd, elapsed); ok {
			row["disk_read_mbs"] = v
		}
		if v, ok := rateMBs(lastDisk[1], wr, elapsed); ok {
			row["disk_write_mbs"] = v
		}
	}
	if hasNet && netOK {
		if v, ok := rateMBs(lastNet[0], rx, elapsed); ok {
			row["net_rx_mbs"] = v
		}
		if v, ok := rateMBs(lastNet[1], tx, elapsed); ok {
			row["net_tx_mbs"] = v
		}
	}
	if pct, ok := cpuPercent(lastCPU, cpu); ok && elapsed >= minCPUSeconds {
		row["cpu_pct"] = pct
	}
	row["cpu_cores"] = machineCores(statText)
	for k, v := range loadAverage(r.read("/proc/loadavg")) {
		row[k] = v
	}
	for k, v := range memoryMB(r.read("/proc/meminfo")) {
		row[k] = v
	}
	if disks := diskRows(mountPoints(r.read("/proc/mounts"), nil), r.stat); len(disks) > 0 {
		row["disks"] = disks
	}
	if rss, ok := processRSS(r.read("/proc/self/status")); ok {
		row["proc_rss_mb"] = rss
	}
	if up, ok := hostUptime(r.read("/proc/uptime")); ok {
		row["host_uptime_s"] = up
	}
	for k, v := range r.limitsRow(row) {
		row[k] = v
	}
	r.mu.Lock()
	if !r.enabled {
		// Off in the dashboard: only the newest minute is kept, as the one
		// row that asks the collector, now and then, whether it is back on.
		r.rows = map[string]map[string]any{}
	}
	r.rows[row["minute"].(string)] = row
	// Oldest first out: a long outage keeps the recent minutes.
	for len(r.rows) > maxResourceRows {
		oldest := ""
		for m := range r.rows {
			if oldest == "" || m < oldest {
				oldest = m
			}
		}
		delete(r.rows, oldest)
	}
	r.mu.Unlock()
	return row
}

// flush sends what's buffered. Rows are kept only when the collector
// couldn't take them and retrying may work.
func (r *resources) flush(ctx context.Context) bool {
	r.mu.Lock()
	minutes := make([]string, 0, len(r.rows))
	for m := range r.rows {
		minutes = append(minutes, m)
	}
	sort.Strings(minutes)
	rows := make([]map[string]any, len(minutes))
	for i, m := range minutes {
		rows[i] = r.rows[m]
	}
	r.mu.Unlock()
	if len(rows) == 0 {
		return true
	}
	res := r.core.send(ctx, "resources", "/events/resources", http.MethodPost, map[string]any{
		"site_id": r.core.siteID, "server_name": r.serverName, "runtime": runtimeName(), "rows": rows,
	}, authBearer, nil)
	if res == nil {
		return false
	}
	if !res.ok() {
		// Unreachable or storage down: these rows are still good. A 4xx
		// means resending won't make them acceptable.
		if res.status >= 500 {
			return false
		}
		r.drop(minutes)
		return true
	}
	var answer struct {
		Every   float64 `json:"every"`
		Enabled *bool   `json:"enabled"`
	}
	if res.json(&answer) {
		r.mu.Lock()
		if answer.Every > 0 {
			r.every = time.Duration(answer.Every) * time.Second
			if r.every < resourcesRetry {
				r.every = resourcesRetry
			}
		}
		r.enabled = answer.Enabled == nil || *answer.Enabled
		r.mu.Unlock()
	}
	r.drop(minutes)
	return true
}

func (r *resources) drop(minutes []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range minutes {
		delete(r.rows, m)
	}
}

func (r *resources) report() time.Duration {
	r.mu.Lock()
	every := r.every
	r.mu.Unlock()
	off := resourcesOff
	if every > off {
		off = every
	}
	if !r.core.isOn(ModuleResources) {
		// Switched off: keep nothing, and ask again later.
		r.mu.Lock()
		r.rows = map[string]map[string]any{}
		r.mu.Unlock()
		return off
	}
	sent := r.flush(context.Background())
	r.mu.Lock()
	enabled, every := r.enabled, r.every
	r.mu.Unlock()
	if !enabled {
		// The collector said the module is off: ask again later, as the agent does.
		if every > resourcesOff {
			return every
		}
		return resourcesOff
	}
	if sent {
		return every
	}
	return resourcesRetry
}

func (r *resources) close(ctx context.Context) {
	r.sampler.halt(ctx)
	r.job.halt(ctx)
	r.mu.Lock()
	enabled := r.enabled
	r.mu.Unlock()
	// What's buffered goes out, as with every other module.
	if r.core.isOn(ModuleResources) && enabled {
		r.flush(ctx)
	}
}

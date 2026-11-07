package sitegoose

import (
	"context"
	"testing"
	"time"
)

func fakeFiles(files map[string]string) func(string) string {
	return func(p string) string { return files[p] }
}

func TestCgroupV2(t *testing.T) {
	files := map[string]string{
		"/proc/self/cgroup":             "0::/system.slice/docker-abc.scope\n",
		"/sys/fs/cgroup/memory.current": "600000000\n", // namespaced: the mount is the container's
		"/sys/fs/cgroup/memory.max":     "1073741824\n",
		"/sys/fs/cgroup/memory.stat":    "anon 400000000\ninactive_file 75000000\nactive_file 1\n",
		"/sys/fs/cgroup/memory.events":  "low 0\nhigh 0\nmax 4\noom 1\noom_kill 1\n",
		"/sys/fs/cgroup/cpu.max":        "150000 100000\n",
		"/sys/fs/cgroup/cpu.stat":       "usage_usec 1\nnr_periods 1000\nnr_throttled 50\n",
	}
	read := fakeFiles(files)
	cg := findCgroup(read)
	if cg == nil || cg.version != 2 || cg.memory != "/sys/fs/cgroup" {
		t.Fatalf("%+v", cg)
	}
	before := readCgroup(cg, read)
	files["/sys/fs/cgroup/cpu.stat"] = "nr_periods 1600\nnr_throttled 200\n"
	files["/sys/fs/cgroup/memory.events"] = "oom_kill 3\n"
	after := readCgroup(cg, read)
	got := cgroupFields(before, after, 7954, 4)
	if got["limit_mem_mb"] != int64(1024) || got["limit_mem_used_mb"] != int64(500) || got["limit_cpu_cores"] != 1.5 ||
		got["cpu_throttled_pct"] != 25.0 || got["oom_kills"] != int64(2) {
		t.Fatal(got)
	}
	// The first sample has no pair: caps only.
	if first := cgroupFields(nil, after, 7954, 4); first["cpu_throttled_pct"] != nil || first["oom_kills"] != nil || first["limit_mem_mb"] == nil {
		t.Fatal(first)
	}
	// A counter that went down was reset: nothing.
	files["/sys/fs/cgroup/memory.events"] = "oom_kill 0\n"
	if reset := cgroupFields(after, readCgroup(cg, read), 7954, 4); reset["oom_kills"] != nil {
		t.Fatal(reset)
	}
	// No cap: "max", or a cap the machine itself doesn't have.
	files["/sys/fs/cgroup/memory.max"] = "max\n"
	files["/sys/fs/cgroup/cpu.max"] = "max 100000\n"
	if none := cgroupFields(nil, readCgroup(cg, read), 7954, 4); none["limit_mem_mb"] != nil || none["limit_mem_used_mb"] != nil || none["limit_cpu_cores"] != nil {
		t.Fatal(none)
	}
	files["/sys/fs/cgroup/memory.max"] = "17179869184\n" // 16 GB on an 8 GB machine
	if none := cgroupFields(nil, readCgroup(cg, read), 7954, 4); none["limit_mem_mb"] != nil {
		t.Fatal(none)
	}
}

func TestCgroupV1(t *testing.T) {
	files := map[string]string{
		"/proc/self/cgroup": "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n0::/\n",
		// Without a namespace the path is the host's: found under it.
		"/sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes": "300000000",
		"/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes": "9223372036854771712", // no limit
		"/sys/fs/cgroup/memory/docker/abc/memory.stat":           "total_inactive_file 1000\n",
		"/sys/fs/cgroup/memory/docker/abc/memory.oom_control":    "oom_kill_disable 0\nunder_oom 0\noom_kill 5\n",
		"/sys/fs/cgroup/cpu/docker/abc/cpu.cfs_quota_us":         "50000",
		"/sys/fs/cgroup/cpu/docker/abc/cpu.cfs_period_us":        "100000",
		"/sys/fs/cgroup/cpu/docker/abc/cpu.stat":                 "nr_periods 10\nnr_throttled 1\n",
	}
	read := fakeFiles(files)
	cg := findCgroup(read)
	if cg == nil || cg.version != 1 || cg.memory != "/sys/fs/cgroup/memory/docker/abc" || cg.cpu != "/sys/fs/cgroup/cpu/docker/abc" {
		t.Fatalf("%+v", cg)
	}
	got := cgroupFields(readCgroup(cg, read), readCgroup(cg, read), 7954, 4)
	if got["limit_mem_mb"] != nil || got["limit_cpu_cores"] != 0.5 || got["oom_kills"] != int64(0) || got["cpu_throttled_pct"] != nil {
		t.Fatal(got) // no periods passed between two equal readings
	}
	if findCgroup(fakeFiles(nil)) != nil {
		t.Fatal("no cgroup files, no cgroup")
	}
}

func TestPressureNetworkFiles(t *testing.T) {
	read := fakeFiles(map[string]string{
		"/proc/pressure/cpu":    "some avg10=1.00 avg60=12.34 avg300=0.50 total=1\nfull avg10=0 avg60=0 avg300=0 total=0\n",
		"/proc/pressure/memory": "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
		"/proc/net/netstat": "TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 17 19\n" +
			"IpExt: InNoRoutes\nIpExt: 0\n",
		"/proc/sys/net/netfilter/nf_conntrack_count": "6553\n",
		"/proc/sys/net/netfilter/nf_conntrack_max":   "65536\n",
		"/proc/self/limits": "Limit                     Soft Limit           Hard Limit           Units\n" +
			"Max open files            1024                 1048576              files\n",
	})
	psi := pressureFields(read)
	if psi["psi_cpu_pct"] != 12.3 || psi["psi_mem_pct"] != 0.0 || psi["psi_io_pct"] != nil {
		t.Fatal(psi)
	}
	if o := listenOverflows(read("/proc/net/netstat")); !o.ok || o.v != 17 {
		t.Fatal(o)
	}
	if pct, ok := conntrackPct(read); !ok || pct != 10.0 {
		t.Fatal(pct)
	}
	files := fileFields(read, func() (int64, bool) { return 40, true })
	if files["fds_used"] != int64(40) || files["fds_max"] != int64(1024) {
		t.Fatal(files)
	}
	if max, ok := fdLimit("Max open files            unlimited            unlimited            files\n"); ok {
		t.Fatal("unlimited is no fds_max", max)
	}
}

func TestLimitsRow(t *testing.T) {
	c := newCollector(t)
	r := newResources(testCore(c), ResourcesOptions{ServerName: "box"})
	// Stopped first: the sampler is the one goroutine limitsRow runs on.
	r.sampler.halt(context.Background())
	r.job.halt(context.Background())
	files := map[string]string{"/proc/net/netstat": "TcpExt: ListenOverflows\nTcpExt: 5\n"}
	r.read = fakeFiles(files)
	pause := 100 * time.Millisecond
	r.gcPauses = func() (time.Duration, bool) { return pause, true }
	r.goMemory = func() (int64, int64, bool) { return 300 * mb, 512 * mb, true }
	r.uptime = func() time.Duration { return 90 * time.Second }
	r.inflight = func() (int64, bool) { return 7, true }
	r.lastGC, r.lastOverflows = have(40), listenOverflows(files["/proc/net/netstat"])
	files["/proc/net/netstat"] = "TcpExt: ListenOverflows\nTcpExt: 9\n"
	row := r.limitsRow(map[string]any{"mem_total_mb": int64(8000), "cpu_cores": 4})
	key, _ := row["proc_key"].(string)
	if len(key) != 12 || row["proc_uptime_s"] != int64(90) || row["gc_ms"] != 60.0 || row["listen_drops"] != int64(4) ||
		row["heap_used_mb"] != int64(300) || row["heap_max_mb"] != int64(512) || row["inflight_peak"] != int64(7) {
		t.Fatal(row)
	}
	for _, missing := range []string{"limit_mem_mb", "psi_cpu_pct", "conntrack_pct", "fds_max", "oom_kills"} {
		if _, has := row[missing]; has {
			t.Fatal("a figure this machine didn't give is left out, not 0:", missing, row)
		}
	}
	// No memory limit set: no heap figures at all.
	r.goMemory = goMemory
	if used, limit, ok := goMemory(); ok {
		t.Fatal("GOMEMLIMIT is unset in the tests", used, limit)
	}
	if row := r.limitsRow(map[string]any{}); row["heap_max_mb"] != nil || row["gc_ms"] != 0.0 {
		t.Fatal(row) // the pauses didn't move: 0 is a real reading here
	}
}

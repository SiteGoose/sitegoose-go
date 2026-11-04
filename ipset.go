package sitegoose

import (
	"encoding/binary"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ipKey is an address in IPv6 space; IPv4 is kept as ::ffff:a.b.c.d, so one
// sorted list holds both and an IPv4-mapped IPv6 address is the IPv4 one.
type ipKey struct{ hi, lo uint64 }

func (a ipKey) less(b ipKey) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) }

func (a ipKey) next() (ipKey, bool) {
	if a.lo == ^uint64(0) {
		if a.hi == ^uint64(0) {
			return a, false
		}
		return ipKey{a.hi + 1, 0}, true
	}
	return ipKey{a.hi, a.lo + 1}, true
}

func keyOfAddr(addr netip.Addr) ipKey {
	b := addr.As16()
	return ipKey{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

// parseAddr reads an address, its zone dropped; false when it isn't one.
func parseAddr(text string) (netip.Addr, bool) {
	text = strings.TrimSpace(text)
	if i := strings.IndexByte(text, '%'); i >= 0 {
		text = text[:i]
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

func ipKeyOf(text string) (ipKey, bool) {
	addr, ok := parseAddr(text)
	if !ok {
		return ipKey{}, false
	}
	return keyOfAddr(addr), true
}

var (
	mappedStart = ipKey{0, 0xFFFF << 32}
	mappedEnd   = ipKey{0, 0xFFFF<<32 | 0xFFFFFFFF}
)

// parseRange: "1.2.3.0/24" -> its first and last keys. false too for an
// IPv6 range that holds all of ::ffff:0:0/96 (::/64, ::/0): with IPv4 kept as
// ::ffff:a.b.c.d it would match every IPv4 visitor, a /64 that is one machine
// in IPv6 being the whole IPv4 internet here.
func parseRange(entry string) (start, end ipKey, ok bool) {
	entry = strings.TrimSpace(entry)
	var prefix netip.Prefix
	if strings.Contains(entry, "/") {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return start, end, false
		}
		prefix = p
	} else {
		addr, ok := parseAddr(entry)
		if !ok {
			return start, end, false
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	bits := prefix.Bits()
	v4 := prefix.Addr().Is4()
	if v4 {
		bits += 96
	}
	start = keyOfAddr(prefix.Masked().Addr())
	end = start
	if bits < 64 {
		end.hi |= ^uint64(0) >> uint(bits)
		end.lo = ^uint64(0)
	} else if bits < 128 {
		end.lo |= ^uint64(0) >> uint(bits-64)
	}
	if !v4 && !mappedStart.less(start) && !end.less(mappedEnd) {
		return start, end, false
	}
	return start, end, true
}

// ipSet holds addresses and ranges, merged and sorted, looked up by binary search.
type ipSet struct {
	starts []ipKey
	ends   []ipKey
}

func newIPSet(entries []string) *ipSet {
	type span struct{ start, end ipKey }
	var spans []span
	for _, entry := range entries {
		if s, e, ok := parseRange(entry); ok {
			spans = append(spans, span{s, e})
		}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end.less(spans[j].end)
		}
		return spans[i].start.less(spans[j].start)
	})
	set := &ipSet{}
	for _, sp := range spans {
		n := len(set.ends)
		if n > 0 {
			after, more := set.ends[n-1].next()
			if !more || !after.less(sp.start) {
				if set.ends[n-1].less(sp.end) {
					set.ends[n-1] = sp.end
				}
				continue
			}
		}
		set.starts = append(set.starts, sp.start)
		set.ends = append(set.ends, sp.end)
	}
	return set
}

func (s *ipSet) has(key ipKey) bool {
	if s == nil || len(s.starts) == 0 {
		return false
	}
	// The last range starting at or before key.
	i := sort.Search(len(s.starts), func(i int) bool { return key.less(s.starts[i]) }) - 1
	return i >= 0 && !s.ends[i].less(key)
}

func (s *ipSet) size() int {
	if s == nil {
		return 0
	}
	return len(s.starts)
}

// cloudflareRanges are Cloudflare's published ranges (cloudflare.com/ips), the
// same list as sdk/protocols/cloudflare-ranges.json (cloudflare_test.go
// compares them): CF-Connecting-IP is believed only from these, since anyone
// who reaches the origin directly can send it.
var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
	"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
	"2a06:98c0::/29", "2c0f:f248::/32",
}

var (
	cloudflareOnce sync.Once
	cloudflareSet  *ipSet
)

// fromCloudflare: a connection's address is one of Cloudflare's.
func fromCloudflare(ip string) bool {
	key, ok := ipKeyOf(ip)
	if !ok {
		return false
	}
	cloudflareOnce.Do(func() { cloudflareSet = newIPSet(cloudflareRanges) })
	return cloudflareSet.has(key)
}

// cleanIP is an address a header gave, or "" when it isn't one: a port
// ("198.51.100.7:5555", as Azure's front door sends), brackets
// ("[2001:db8::1]") and a zone are taken off; an IPv4-mapped address is its
// IPv4. Anything else (a name, "unknown", junk) is refused, so the caller
// falls back to the connection's address rather than checking nothing.
func cleanIP(text string) string {
	text = strings.TrimSpace(text)
	if text == "" || len(text) > 100 {
		return ""
	}
	if ap, err := netip.ParseAddrPort(text); err == nil {
		return ap.Addr().WithZone("").Unmap().String()
	}
	text = strings.TrimSuffix(strings.TrimPrefix(text, "["), "]")
	addr, ok := parseAddr(text)
	if !ok {
		return ""
	}
	return addr.Unmap().String()
}

// clientIPOf is the visitor's address. trust: "" the connection's address; a
// number of proxies in X-Forwarded-For ("true" = 1); "cloudflare" reads
// CF-Connecting-IP, believed only when the connection comes from one of
// Cloudflare's addresses. A header that doesn't hold an address gives the
// connection's.
func clientIPOf(remote string, h http.Header, trust string) string {
	if clean := cleanIP(remote); clean != "" {
		remote = clean
	}
	trust = strings.ToLower(strings.TrimSpace(trust))
	switch trust {
	case "", "0", "false", "none":
		return remote
	case "cloudflare":
		if fromCloudflare(remote) {
			if v := cleanIP(h.Get("CF-Connecting-IP")); v != "" {
				return v
			}
		}
		return remote
	}
	hops := 1
	if trust != "true" {
		n, err := strconv.Atoi(trust)
		if err != nil || n <= 0 {
			return remote
		}
		hops = n
	}
	var chain []string
	for _, field := range h.Values("X-Forwarded-For") {
		for _, part := range strings.Split(field, ",") {
			if part = strings.TrimSpace(part); part != "" {
				chain = append(chain, part)
			}
		}
	}
	if len(chain) == 0 {
		return remote
	}
	i := len(chain) - hops
	if i < 0 {
		i = 0
	}
	if v := cleanIP(chain[i]); v != "" {
		return v
	}
	return remote
}

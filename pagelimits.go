package sitegoose

// Page limits (sdk/protocols/firewall.md, "Page limits"): the site-wide rate
// treats every page alike; a page limit caps one kind of request on its own
// -- a login form posted ten times a minute, a checkout tried five times, a
// search hammered. Matched as a request rule is (the same preparation, the
// same sections), without regex, so the agent's nginx can carry the same
// limit. The shared cases are in sdk/protocols/page-limits-cases.json, run by
// pagelimits_test.go.

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxPageLimits = 50

// limitBody is what a visitor over a blocking page limit reads, with its 429.
const limitBody = "Too many requests to this page. Please wait a little and try again."

var limitID = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,39}$`)

type pageLimit struct {
	requestRule
	limit, window int64
	// each: a count per page (the routed path), not one for every page matched.
	each bool
}

type pageLimits struct {
	exempt *ipSet
	rules  []*pageLimit
}

// limitCount is one page limit's count for one address (and page).
type limitCount struct {
	window, hits int64
	ends         time.Time
}

// wholeIn is v as a whole number between low and high, or false.
func wholeIn(v any, low, high int64) (int64, bool) {
	n, ok := v.(float64)
	if !ok || n != math.Trunc(n) || n < float64(low) || n > float64(high) {
		return 0, false
	}
	return int64(n), true
}

// compilePageLimits: the rules' page limits, or nil when there are none. A
// limit that doesn't parse is left out, not the others: a bad id, a limit
// outside 1-100,000, a window outside 1-3,600 seconds, or nothing to match
// on (a section with a regex only is no section).
func compilePageLimits(data any) *pageLimits {
	holder, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	given, ok := holder["rules"].([]any)
	if !ok {
		return nil
	}
	if len(given) > maxPageLimits {
		given = given[:maxPageLimits]
	}
	out := &pageLimits{exempt: newIPSet(stringList(holder["exempt"]))}
	for _, raw := range given {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, _ := rule["id"].(string)
		limit, limitOK := wholeIn(rule["limit"], 1, 100000)
		window, windowOK := wholeIn(rule["window"], 1, 3600)
		if !limitID.MatchString(id) || !limitOK || !windowOK {
			continue
		}
		compiled := &pageLimit{
			requestRule: requestRule{id: id, action: "monitor", sections: map[string]*ruleSection{}},
			limit:       limit,
			window:      window,
			each:        rule["each"] == "path",
		}
		if rule["action"] == "block" {
			compiled.action = "block"
		}
		if methods, ok := rule["methods"].([]any); ok {
			compiled.methods = upperList(methods)
		}
		for _, name := range []string{"path", "query"} {
			section, ok := rule[name].(map[string]any)
			if !ok {
				continue
			}
			plain := map[string]any{}
			for k, v := range section {
				if k != "regex" {
					plain[k] = v
				}
			}
			if s := compileSection(plain); s != nil {
				compiled.sections[name] = s
			}
		}
		if len(compiled.sections) == 0 {
			continue
		}
		out.rules = append(out.rules, compiled)
	}
	if len(out.rules) == 0 {
		return nil
	}
	return out
}

func upperList(entries []any) []string {
	var out []string
	for _, e := range entries {
		if s, ok := e.(string); ok {
			out = append(out, strings.ToUpper(s))
		}
	}
	return out
}

// overLimits counts the request toward every page limit it matches
// (firewall.md, step 6) and returns those now over their count, in the order
// sent. Every matching limit counts, not just the first, so one that is over
// can't hide the requests another should see. A fixed window per limit, as
// the rate; each: "path" keeps a count per page, which stays here: one key
// per page in a shared counter would be as many keys as a crawler can make up.
func (f *Firewall) overLimits(key ipKey, limits []*pageLimit, req *preparedRequest, peek bool) []*pageLimit {
	key = localKey(key)
	who := localName(key)
	now := f.now()
	var over []*pageLimit
	for _, limit := range limits {
		if !limit.matches(req) {
			continue
		}
		window := now.Unix() / limit.window
		if f.counter != nil && !limit.each {
			shared := "afw:" + f.core.siteID + ":l:" + limit.id + ":" + who + ":" + strconv.FormatInt(window, 10)
			if peek {
				// Seen over, else the count kept here while the counter failed.
				if f.noted(shared) {
					over = append(over, limit)
					continue
				}
			} else {
				hits, err := f.counter(shared, time.Duration(limit.window*2)*time.Second)
				if err == nil {
					if f.noteOver(shared, hits > limit.limit) {
						over = append(over, limit)
					}
					continue
				}
				f.core.log("firewall", "shared counter failed, counted here: %v", err)
			}
		}
		name := limit.id + " " + strconv.FormatInt(limit.window, 10) + " " + who
		if limit.each {
			// Matched on the whole path, counted under its first 2,000
			// characters: pages alike that far share a count, and a key
			// stays small however long the path.
			name += " " + truncate(req.routedPath, maxRuleText)
		}
		if f.countLimit(name, window, limit, now, peek) {
			over = append(over, limit)
		}
	}
	return over
}

// countLimit adds one to a page limit's count here and says whether it is
// now over. A full table is swept of the windows that ended, as the rate
// counters are; what is still live is never dropped. Per-page counts have a
// table of their own, so a crawler walking many pages can fill only that one.
func (f *Firewall) countLimit(name string, window int64, limit *pageLimit, now time.Time, peek bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	table, swept := f.limitCounts, &f.limitsSwept
	if limit.each {
		table, swept = f.pathCounts, &f.pathsSwept
	}
	entry := table[name]
	if peek {
		// Only compared with the count so far, nothing added (a static file).
		return entry != nil && entry.window == window && entry.hits > limit.limit
	}
	if entry == nil || entry.window != window {
		if entry == nil && !f.room(len(table), swept, func(now time.Time) {
			for k, e := range table {
				if !e.ends.After(now) {
					delete(table, k)
				}
			}
		}) && len(table) >= counterMax {
			return false // full of live counts: this one isn't counted here
		}
		entry = &limitCount{window: window, ends: time.Unix((window+1)*limit.window, 0)}
		table[name] = entry
	}
	entry.hits++
	return entry.hits > limit.limit
}

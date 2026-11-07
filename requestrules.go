package sitegoose

// Request rules (virtual patching; protocol in sdk/protocols/firewall.md): the
// firewall has always matched addresses, these match the request -- its
// method, path, query string and user agent -- so an attack is turned away
// before the vulnerable code runs. They arrive with the other rules and are
// compiled once per fetch; matching is plain string work on text we already
// have.
//
// The matching is the same in every package: the shared cases are in
// sdk/protocols/request-rules-cases.json, run by requestrules_test.go.
//
// Go's regexp is RE2, which runs in linear time whatever the pattern, so a
// careless pattern can't hang a request here. safePattern refuses the same
// patterns the other clients do all the same, so every client keeps the
// same rules; a pattern RE2 can't compile (a lookahead) is dropped, and the
// rule's other parts stay, as a pattern that doesn't compile is anywhere.

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	maxRequestRules = 200
	maxRuleText     = 2000
	maxRegex        = 200
)

var ruleSections = []string{"path", "query", "ua"}

type ruleSection struct {
	exact    []string
	prefix   []string
	suffix   []string
	contains []string
	regex    *regexp.Regexp
}

type requestRule struct {
	id       string
	action   string
	ban      int64
	methods  []string
	sections map[string]*ruleSection
}

var (
	alnum         = regexp.MustCompile(`(?i)^[a-z0-9]$`)
	boundsPattern = regexp.MustCompile(`^\{(\d*)(,(\d*))?\}`)
)

// safePattern checks a pattern's shape instead of trusting what it was
// handed. A repeated group that can match the same text more than one way
// takes exponential time in a backtracking engine on input that nearly
// matches; a group can do that when it holds a quantifier ("(a+)+",
// "(\w\d?)+") or an alternation ("(a|ab)*"), so a group followed by * + or {
// holds neither. Backreferences and lookbehind are refused too. The same
// check as backend/services/firewall/requestRules.js, free repeats included.
func safePattern(pattern string) bool {
	if pattern == "" || utf8.RuneCountInString(pattern) > maxRegex {
		return false
	}
	// Per open group: whether anything in it, nested groups too, repeats or branches.
	var open []bool
	p := pattern
	for i := 0; i < len(p); {
		c := p[i]
		if c == '\\' {
			// Escapes that refer to a group (\1-\9, \g, \k), and \N.
			if i+1 < len(p) && strings.IndexByte("123456789gkN", p[i+1]) >= 0 {
				return false
			}
			i += 2
			continue
		}
		if c == '[' {
			for i < len(p) && p[i] != ']' {
				if p[i] == '\\' {
					i += 2
				} else {
					i++
				}
			}
			i++
			continue
		}
		next := byte(0)
		if i+1 < len(p) {
			next = p[i+1]
		}
		switch {
		case c == '(':
			open = append(open, false)
			// "(*": a PCRE verb ("(*FAIL)"). Of "(?" only "(?:", "(?=" and
			// "(?!" are in the subset every package shares: no named groups,
			// conditionals, atomic groups, inline flags, comments or recursion.
			if next == '*' {
				return false
			}
			if next == '?' {
				if i+2 >= len(p) || strings.IndexByte(":=!", p[i+2]) < 0 {
					return false
				}
				i += 2
			}
		case strings.IndexByte("*+?", c) >= 0 && next == '+' && i > 0 && p[i-1] != '(':
			return false // possessive: a++, a*+, a?+
		case c == '}' && next == '+' && possessiveCount.MatchString(p[:i]):
			return false // possessive: a{2,}+
		case c == ')':
			if len(open) == 0 {
				return false
			}
			ambiguous := open[len(open)-1]
			open = open[:len(open)-1]
			if ambiguous && strings.IndexByte("*+{", next) >= 0 && next != 0 {
				return false
			}
			if ambiguous && len(open) > 0 {
				open[len(open)-1] = true
			}
		case len(open) > 0 && strings.IndexByte("|*+?{", c) >= 0:
			open[len(open)-1] = true
		}
		i++
	}
	return len(open) == 0 && freeRepeats(pattern) <= 1
}

var possessiveCount = regexp.MustCompile(`\{\d*(,\d*)?$`)

// literalAt is the character at i when it can only match itself, else "".
func literalAt(p string, i int) (string, bool) {
	if i >= len(p) {
		return "", false
	}
	c := p[i]
	if c == '\\' {
		if i+1 >= len(p) {
			return "", false
		}
		_, size := utf8.DecodeRuneInString(p[i+1:])
		following := p[i+1 : i+1+size]
		if alnum.MatchString(following) {
			return "", false
		}
		return following, true
	}
	if strings.IndexByte(".[](){}*+?|^$", c) >= 0 {
		return "", false
	}
	_, size := utf8.DecodeRuneInString(p[i:])
	return p[i : i+size], true
}

// freeRepeats counts repeats that can take the same text as what follows
// them: two of those multiply each other's work (".*=.*=.*x" against a query
// of "=" that never ends in "x"). A repeat is pinned when the character
// straight after it is one it can't match ("[^/]+/" ends at the first "/");
// any other is free, and a pattern may hold one free repeat.
func freeRepeats(p string) int {
	free := 0
	for i := 0; i < len(p); {
		start := i
		c := p[i]
		switch {
		case c == '\\':
			i += 2
		case c == '[':
			i++
			for i < len(p) && p[i] != ']' {
				if p[i] == '\\' {
					i += 2
				} else {
					i++
				}
			}
			i++
		case c == '(':
			if i+1 < len(p) && p[i+1] == '?' {
				i += 3
			} else {
				i++
			}
			continue
		case c == '|' || c == '^' || c == '$':
			i++
			continue
		default:
			_, size := utf8.DecodeRuneInString(p[i:])
			i += size
		}
		if i > len(p) {
			i = len(p)
		}
		atom := ""
		if c != ')' {
			atom = p[start:i]
		}
		quantifier := byte(0)
		if i < len(p) {
			quantifier = p[i]
		}
		repeats := quantifier == '*' || quantifier == '+'
		if quantifier == '{' {
			m := boundsPattern.FindStringSubmatchIndex(p[i:])
			if m == nil {
				continue
			}
			low := p[i+m[2] : i+m[3]]
			hasComma := m[4] >= 0
			high := ""
			if m[6] >= 0 {
				high = p[i+m[6] : i+m[7]]
			}
			// "{3}" is one length, not a choice; "{2,}" and "{2,9}" are choices.
			repeats = hasComma && high != low
			i += m[1] - 1
		} else if quantifier != '?' && !repeats {
			continue
		}
		i++
		if i < len(p) && p[i] == '?' {
			i++
		}
		if !repeats {
			continue
		}
		next, isLiteral := literalAt(p, i)
		pinned := false
		if atom != "" && isLiteral {
			if re, err := regexp.Compile(`(?i)^(?:` + atom + `)$`); err == nil {
				pinned = !re.MatchString(next)
			}
		}
		if !pinned {
			free++
		}
	}
	return free
}

func lowerList(entries []any, allowEmpty bool) []string {
	var out []string
	for _, e := range entries {
		if s, ok := e.(string); ok && (allowEmpty || s != "") {
			out = append(out, strings.ToLower(s))
		}
	}
	return out
}

func compileSection(raw any) *ruleSection {
	section, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := &ruleSection{}
	found := false
	for _, matcher := range []string{"exact", "prefix", "suffix", "contains"} {
		entries, ok := section[matcher].([]any)
		if !ok {
			continue
		}
		values := lowerList(entries, matcher == "exact")
		if len(values) == 0 {
			continue
		}
		found = true
		switch matcher {
		case "exact":
			out.exact = values
		case "prefix":
			out.prefix = values
		case "suffix":
			out.suffix = values
		case "contains":
			out.contains = values
		}
	}
	if pattern, ok := section["regex"].(string); ok && safePattern(pattern) {
		// A pattern we can't compile is dropped; the rule's other parts stay.
		if re, err := regexp.Compile("(?i)" + pattern); err == nil {
			out.regex = re
			found = true
		}
	}
	if !found {
		return nil
	}
	return out
}

// compileRequestRules: the rules as they will be matched; nil when there are none.
func compileRequestRules(data any) []*requestRule {
	holder, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	given, ok := holder["rules"].([]any)
	if !ok {
		return nil
	}
	if len(given) > maxRequestRules {
		given = given[:maxRequestRules]
	}
	var rules []*requestRule
	for _, raw := range given {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, ok := rule["id"].(string)
		if !ok || id == "" {
			continue
		}
		// We are called before the body is read, so a rule that needs the
		// body is skipped whole rather than matched on the rest of it.
		if _, needsBody := rule["body"]; needsBody {
			continue
		}
		compiled := &requestRule{id: id, action: "monitor", sections: map[string]*ruleSection{}}
		if rule["action"] == "block" {
			compiled.action = "block"
		}
		if ban, ok := rule["ban"].(float64); ok && int64(ban) > 0 {
			compiled.ban = int64(ban)
		}
		if methods, ok := rule["methods"].([]any); ok {
			for _, m := range methods {
				if s, ok := m.(string); ok {
					compiled.methods = append(compiled.methods, strings.ToUpper(s))
				}
			}
		}
		for _, name := range ruleSections {
			if section := compileSection(rule[name]); section != nil {
				compiled.sections[name] = section
			}
		}
		// A rule with nothing to match would match everything.
		if len(compiled.sections) == 0 {
			continue
		}
		rules = append(rules, compiled)
	}
	return rules
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// decodeOnce is one pass only, as the protocol says: enough for %2e%2e, and no
// risk of decoding a visitor's own text into something that looks like an
// attack. "+" is a space, a "%" that isn't followed by two hex digits stays as
// it is, and bytes that aren't UTF-8 become U+FFFD (Python's unquote_plus).
func decodeOnce(text string) string {
	if !strings.ContainsAny(text, "%+") {
		return text
	}
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '+':
			out = append(out, ' ')
		case c == '%' && i+2 < len(text) && isHex(text[i+1]) && isHex(text[i+2]):
			out = append(out, unhex(text[i+1])<<4|unhex(text[i+2]))
			i += 2
		default:
			out = append(out, c)
		}
	}
	if utf8.Valid(out) {
		return string(out)
	}
	return strings.ToValidUTF8(string(out), "�")
}

var (
	repeatedSlashes = regexp.MustCompile(`/{2,}`)
	segmentParams   = regexp.MustCompile(`;[^/]*`)
)

func normalizeRulePath(path string) string {
	return repeatedSlashes.ReplaceAllString(strings.ReplaceAll(strings.ToLower(path), `\`, "/"), "/")
}

// routerPath is the path as a router reads it: ";params" dropped from each
// segment (Tomcat, Jetty and some proxies do; "/x;y/../admin" is "/admin"
// to them), decoded once, "\" as "/", "//" as "/", "." and ".." resolved
// (never above the root), lower-cased.
func routerPath(path string) string {
	text := normalizeRulePath(decodeOnce(segmentParams.ReplaceAllString(path, "")))
	segments := strings.Split(text, "/")
	var parts []string
	for i, seg := range segments {
		switch {
		case seg == "..":
			if len(parts) > 1 {
				parts = parts[:len(parts)-1]
			}
		case seg != "." && (seg != "" || i == 0):
			parts = append(parts, seg)
		}
	}
	resolved := strings.Join(parts, "/")
	if last := segments[len(segments)-1]; (last == "" || last == "." || last == "..") && len(segments) > 1 && !strings.HasSuffix(resolved, "/") {
		resolved += "/"
	}
	if strings.HasPrefix(text, "/") && !strings.HasPrefix(resolved, "/") {
		resolved = "/" + resolved
	}
	return resolved
}

// normalizeTarget is a request target's path (no query) as the router reads
// it: what the probes, the static-file check and the rules' path also match.
func normalizeTarget(target string) string {
	if loc := queryOrFragment.FindStringIndex(target); loc != nil {
		target = target[:loc[0]]
	}
	return truncate(routerPath(truncate(target, maxRuleText)), maxRuleText)
}

func (s *ruleSection) hits(forms ...string) bool {
	var texts []string
	for _, f := range forms {
		if !containsString(texts, f) {
			texts = append(texts, f)
		}
	}
	for _, text := range texts {
		for _, e := range s.exact {
			if text == e {
				return true
			}
		}
		for _, e := range s.prefix {
			if strings.HasPrefix(text, e) {
				return true
			}
		}
		for _, e := range s.suffix {
			if e != "" && strings.HasSuffix(text, e) {
				return true
			}
		}
		for _, e := range s.contains {
			if e != "" && strings.Contains(text, e) {
				return true
			}
		}
		if s.regex != nil && s.regex.MatchString(text) {
			return true
		}
	}
	return false
}

// preparedRequest is a request's parts, prepared once for every request rule
// and page limit: the method upper-cased, the path raw, decoded and routed,
// the query raw and decoded, the user agent.
type preparedRequest struct {
	method, rawPath, decodedPath, routedPath, rawQuery, decodedQuery, ua string
}

// prepareRequest: target is the request target as the server received it,
// query string and all.
func prepareRequest(method, target, userAgent string) *preparedRequest {
	pathPart, query := target, ""
	if i := strings.IndexByte(target, '?'); i >= 0 {
		pathPart, query = target[:i], target[i+1:]
	}
	pathPart = truncate(pathPart, maxRuleText)
	query = truncate(query, maxRuleText)
	return &preparedRequest{
		method:      strings.ToUpper(method),
		rawPath:     normalizeRulePath(pathPart),
		decodedPath: normalizeRulePath(truncate(decodeOnce(pathPart), maxRuleText)),
		// And as the router reads it: "/x;y/../admin" is "/admin" there, so a
		// rule on "/admin" catches it; a hit on any of the three counts.
		routedPath: truncate(routerPath(pathPart), maxRuleText),
		rawQuery:   strings.ToLower(query),
		// Lower-cased after decoding: %55NION decodes to "UNION", which a
		// lower-cased "union select" rule would otherwise never see.
		decodedQuery: strings.ToLower(truncate(decodeOnce(query), maxRuleText)),
		ua:           strings.ToLower(truncate(userAgent, maxRuleText)),
	}
}

// matches: every section the rule names matches the request.
func (rule *requestRule) matches(req *preparedRequest) bool {
	if len(rule.methods) > 0 && !containsString(rule.methods, req.method) {
		return false
	}
	if s := rule.sections["path"]; s != nil && !s.hits(req.rawPath, req.decodedPath, req.routedPath) {
		return false
	}
	if s := rule.sections["query"]; s != nil && !s.hits(req.rawQuery, req.decodedQuery) {
		return false
	}
	if s := rule.sections["ua"]; s != nil && !s.hits(req.ua, req.ua) {
		return false
	}
	return true
}

// matchRequest is the first rule that matches, or nil. target is the request
// target as the server received it, query string and all.
func matchRequest(rules []*requestRule, method, target, userAgent string) *requestRule {
	if len(rules) == 0 {
		return nil
	}
	return matchPrepared(rules, prepareRequest(method, target, userAgent))
}

func matchPrepared(rules []*requestRule, req *preparedRequest) *requestRule {
	for _, rule := range rules {
		if rule.matches(req) {
			return rule
		}
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

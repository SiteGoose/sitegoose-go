package sitegoose

// Database queries with their values taken out (sdk/protocols/queries.md),
// before a query is counted, so no value ever leaves this server. A port of
// the collector's expresscollect/Analytics/queryText.js, which is the
// reference: the tests run sdk/protocols/query-cases.json against this, and
// lengths are counted in code points (runes), as there.
//
//	SELECT * FROM users WHERE email = 'a@b.c' AND id IN (1, 2, 3)
//	-> SELECT * FROM users WHERE email = ? AND id IN (?)

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxStatement   = 1000
	otherStatement = "(other)"
)

// databases a row may name; anything else is "other".
var databases = map[string]bool{"postgresql": true, "mysql": true, "mariadb": true, "sqlite": true, "mssql": true,
	"oracle": true, "clickhouse": true, "mongodb": true, "other": true}

// databaseOf lower-cases as JavaScript's toLowerCase does for these names:
// the Kelvin sign is a k, but İ is "i̇" (two characters) where Go's
// strings.ToLower makes it an i, so "SQLİTE" stays "other" as in the
// reference. No other non-ASCII character lower-cases to a letter of a name.
func databaseOf(db string) string {
	db = strings.ReplaceAll(db, "K", "k")
	for i := 0; i < len(db); i++ {
		if db[i] >= 0x80 {
			return "other"
		}
	}
	db = strings.ToLower(db)
	if databases[db] {
		return db
	}
	return "other"
}

// qJsSpace is what JavaScript's \s and trim() take for whitespace.
func qJsSpace(c rune) bool {
	switch c {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00a0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return c >= 0x2000 && c <= 0x200a
}

const jsSpaceClass = `[\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`

var (
	placeholderList = regexp.MustCompile(`\(` + jsSpaceClass + `*(?:\?|\$\d+|:\w+|@\w+)(?:` + jsSpaceClass + `*,` +
		jsSpaceClass + `*(?:\?|\$\d+|:\w+|@\w+))*` + jsSpaceClass + `*\)`)
	placeholderRows = regexp.MustCompile(`\(\?\)(?:` + jsSpaceClass + `*,` + jsSpaceClass + `*\(\?\))+`)
	mongoParts      = regexp.MustCompile(`^([^` + jsSpaceClass[1:len(jsSpaceClass)-1] + `]+)(?: ([^` +
		jsSpaceClass[1:len(jsSpaceClass)-1] + `]+))?(?: ((?s:.)*))?$`)
)

func qTrimJS(s string) string { return strings.TrimFunc(s, qJsSpace) }

func qIsDigit(c rune) bool { return c >= '0' && c <= '9' }

func qIsHex(c rune) bool { return qIsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }

func qIsAlnum(c rune) bool {
	return qIsDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

// qIsWord: a digit right after one of these is part of a name or a
// placeholder (table2, $1, @p1, :1), not a value. ASCII only.
func qIsWord(c rune) bool { return qIsAlnum(c) || c == '$' || c == '@' || c == ':' }

func qAt(r []rune, i int) rune {
	if i < 0 || i >= len(r) {
		return -1
	}
	return r[i]
}

func qIndexFrom(r []rune, sub []rune, from int) int {
	for i := from; i+len(sub) <= len(r); i++ {
		match := true
		for j, c := range sub {
			if r[i+j] != c {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// qQuoteEnd is the index after the quoted run starting at start (its opening
// quote), or the text's length when it never closes. A doubled quote
// escapes, and a backslash too unless backslash is false.
func qQuoteEnd(r []rune, start int, quote rune, backslash bool) int {
	i := start + 1
	for i < len(r) {
		c := r[i]
		switch {
		case c == '\\' && backslash:
			i += 2
		case c == quote:
			if qAt(r, i+1) == quote {
				i += 2
			} else {
				return i + 1
			}
		default:
			i++
		}
	}
	return len(r)
}

// qDollarTag is the length of $tag$ or $$ at i, within 64 characters, or 0.
func qDollarTag(r []rune, i int) int {
	end := i + 64
	if end > len(r) {
		end = len(r)
	}
	if i+1 < end && r[i+1] == '$' {
		return 2
	}
	j := i + 1
	if j >= end || !(qIsAlnum(r[j]) && !qIsDigit(r[j])) {
		return 0
	}
	for j < end && qIsAlnum(r[j]) {
		j++
	}
	if j < end && r[j] == '$' {
		return j + 1 - i
	}
	return 0
}

// qNumberLen is the length of the number at i (0x1F, 12, 1.5, .5, 1., 2e-3),
// looking at most 400 characters ahead.
func qNumberLen(r []rune, i int) int {
	w := r[i:]
	if len(w) > 400 {
		w = w[:400]
	}
	if len(w) >= 3 && w[0] == '0' && (w[1] == 'x' || w[1] == 'X') && qIsHex(w[2]) {
		j := 3
		for j < len(w) && qIsHex(w[j]) {
			j++
		}
		return j
	}
	j := 0
	if qIsDigit(w[0]) {
		for j < len(w) && qIsDigit(w[j]) {
			j++
		}
		if j < len(w) && w[j] == '.' {
			j++
			for j < len(w) && qIsDigit(w[j]) {
				j++
			}
		}
	} else {
		j = 1
		for j < len(w) && qIsDigit(w[j]) {
			j++
		}
	}
	if j < len(w) && (w[j] == 'e' || w[j] == 'E') {
		k := j + 1
		if k < len(w) && (w[k] == '+' || w[k] == '-') {
			k++
		}
		if k < len(w) && qIsDigit(w[k]) {
			for k < len(w) && qIsDigit(w[k]) {
				k++
			}
			j = k
		}
	}
	return j
}

func qStrPrefix(c rune) bool {
	switch c {
	case 'E', 'e', 'N', 'n', 'X', 'x', 'B', 'b':
		return true
	}
	return false
}

// backslashLiteral reports where a backslash in a string is just a
// character: PostgreSQL's plain strings (standard_conforming_strings, on
// since 9.1), SQLite, SQL Server and Oracle. Read as an escape there, 'C:\'
// ends late and lets what follows out. MySQL, MariaDB, ClickHouse and unknown
// databases escape.
func backslashLiteral(db string) bool {
	return db == "postgresql" || db == "sqlite" || db == "mssql" || db == "oracle"
}

func sqlShape(sql, db string) string {
	return sqlShapeAs(sql, db, backslashLiteral(db))
}

// sqlShapeAs is sqlShape with the backslash rule given.
func sqlShapeAs(sql, db string, literal bool) string {
	r := []rune(sql)
	mysql := db == "mysql" || db == "mariadb"
	postgres := db == "postgresql"
	out := make([]rune, 0, len(r))
	space := func() {
		if len(out) > 0 && out[len(out)-1] != ' ' {
			out = append(out, ' ')
		}
	}
	i := 0
	for i < len(r) {
		c, next, prev := r[i], qAt(r, i+1), qAt(r, i-1)
		switch {
		case c == '-' && next == '-', c == '#' && mysql:
			if end := qIndexFrom(r, []rune{'\n'}, i); end >= 0 {
				i = end
			} else {
				i = len(r)
			}
			space()
		case c == '/' && next == '*':
			if end := qIndexFrom(r, []rune{'*', '/'}, i+2); end >= 0 {
				i = end + 2
			} else {
				i = len(r)
			}
			space()
		case c == '\'' || (c == '"' && mysql):
			n := len(out)
			lone := n > 0 && (n == 1 || !qIsAlnum(out[n-2]))
			// Only PostgreSQL's E'..' escapes with a backslash where it is literal.
			escapes := !literal || (postgres && lone && (out[n-1] == 'E' || out[n-1] == 'e'))
			// A one-letter prefix (E'..' N'..' X'..' B'..') goes with the string.
			if lone && qStrPrefix(out[n-1]) {
				out = out[:n-1]
			}
			i = qQuoteEnd(r, i, c, escapes)
			out = append(out, '?')
		case c == '"' || c == '`':
			end := qQuoteEnd(r, i, c, !literal)
			out = append(out, r[i:end]...)
			i = end
		case c == '$' && !qIsWord(prev) && qDollarTag(r, i) > 0:
			n := qDollarTag(r, i)
			if end := qIndexFrom(r, r[i:i+n], i+n); end >= 0 {
				i = end + n
			} else {
				i = len(r)
			}
			out = append(out, '?')
		case (qIsDigit(c) || (c == '.' && qIsDigit(next))) && !qIsWord(prev):
			i += qNumberLen(r, i)
			out = append(out, '?')
		case qJsSpace(c):
			i++
			space()
		default:
			out = append(out, c)
			i++
		}
	}
	s := placeholderList.ReplaceAllString(string(out), "(?)")
	return qTrimJS(placeholderRows.ReplaceAllString(s, "(?)"))
}

// ---- MongoDB ----

// qJsonString writes s as JavaScript's JSON.stringify does: only quotes,
// backslashes and control characters escaped, everything else as itself.
func qJsonString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteString(strconv.FormatInt(int64(c)>>4, 16))
				b.WriteString(strconv.FormatInt(int64(c)&15, 16))
			} else {
				b.WriteRune(c)
			}
		}
	}
	b.WriteByte('"')
}

// qArrayIndex: a key JavaScript keeps first, in number order, in an object.
func qArrayIndex(key string) (uint64, bool) {
	if key == "" || len(key) > 10 || (len(key) > 1 && key[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(key, 10, 64)
	if err != nil || n >= 1<<32-1 {
		return 0, false
	}
	return n, true
}

type shapeEntry struct {
	key   string
	value string
}

// mongoShape reads one JSON value from dec and gives its shape, encoded:
// keys kept in the order JavaScript gives them, every value "?", an array
// whose items all have the same shape kept as one, anything at depth six or
// deeper "?".
func mongoShape(dec *json.Decoder, depth int) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return `"?"`, nil
	}
	if delim == '[' {
		var items []string
		for dec.More() {
			item, err := mongoShape(dec, depth+1)
			if err != nil {
				return "", err
			}
			items = append(items, item)
		}
		if _, err := dec.Token(); err != nil {
			return "", err
		}
		if depth >= 6 {
			return `"?"`, nil
		}
		same := len(items) > 0
		for _, item := range items {
			same = same && item == items[0]
		}
		if same {
			items = items[:1]
		}
		return "[" + strings.Join(items, ",") + "]", nil
	}
	var entries []shapeEntry
	seen := map[string]int{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", err
		}
		key, _ := keyTok.(string)
		value, err := mongoShape(dec, depth+1)
		if err != nil {
			return "", err
		}
		// A repeated key keeps its first place and its last value; JSON.parse's
		// "__proto__" is lost when the shape is built, as in the reference.
		if i, dup := seen[key]; dup {
			entries[i].value = value
		} else if key != "__proto__" {
			seen[key] = len(entries)
			entries = append(entries, shapeEntry{key, value})
		}
	}
	if _, err := dec.Token(); err != nil {
		return "", err
	}
	if depth >= 6 {
		return `"?"`, nil
	}
	// JavaScript objects list integer keys first, in number order.
	sort.SliceStable(entries, func(a, b int) bool {
		na, ia := qArrayIndex(entries[a].key)
		nb, ib := qArrayIndex(entries[b].key)
		if ia && ib {
			return na < nb
		}
		return ia && !ib
	})
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			b.WriteByte(',')
		}
		qJsonString(&b, e.key)
		b.WriteByte(':')
		b.WriteString(e.value)
	}
	b.WriteByte('}')
	return b.String(), nil
}

// mongoStatement: "find users {...}", the command, the collection and the
// filter's shape; a filter that isn't JSON is left out.
func mongoStatement(text string) string {
	m := mongoParts.FindStringSubmatch(qTrimJS(text))
	if m == nil {
		return ""
	}
	parts := []string{m[1]}
	collection, rest := m[2], m[3]
	// A "collection" with a brace, bracket or quote in it is the filter's start.
	if strings.ContainsAny(collection, "{}[]\"'") {
		if rest == "" {
			rest = collection
		} else {
			rest = collection + " " + rest
		}
		collection = ""
	}
	if collection != "" {
		parts = append(parts, collection)
	}
	if rest != "" && json.Valid([]byte(rest)) {
		dec := json.NewDecoder(strings.NewReader(rest))
		dec.UseNumber()
		if shape, err := mongoShape(dec, 0); err == nil && shape != "" {
			parts = append(parts, shape)
		}
	}
	return strings.Join(parts, " ")
}

func cutStatement(s string) string {
	if utf8.RuneCountInString(s) <= maxStatement {
		return s
	}
	return qTrimJS(string([]rune(s)[:maxStatement]))
}

// normalizeStatement is the statement to count, or "" when nothing is left of it.
func normalizeStatement(text, db string) string {
	if text == otherStatement {
		return text
	}
	text = strings.ToValidUTF8(text, "�")
	db = databaseOf(db)
	if db == "mongodb" {
		return cutStatement(mongoStatement(text))
	}
	if db == "other" && strings.ContainsRune(text, '\\') {
		// A database we don't know may or may not take a backslash as an
		// escape, and each reading leaks what the other hides. When they
		// disagree the query keeps its timing under (other) and its text is
		// left out.
		escaped := sqlShapeAs(text, db, false)
		if escaped != sqlShapeAs(text, db, true) {
			return cutStatement(otherStatement)
		}
		return cutStatement(escaped)
	}
	return cutStatement(sqlShape(text, db))
}

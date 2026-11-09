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
	"math"
	"reflect"
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
	"oracle": true, "clickhouse": true, "mongodb": true, "redis": true, "other": true}

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
	if db == "redis" {
		return cutStatement(redisStatement(text))
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

// ---- Redis ----

// Redis: the command and its first key's shape, never an argument or value
// (queries.md, "Redis"). A key keeps each ":" segment that is only letters
// and "_" (32 at most); every other segment is "?", so IDs, slugs, emails and
// hashes never leave the server: user:42:cart -> user:?:cart. ASCII only,
// as the reference's regexes are.

func redisSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

var (
	// Commands whose second word is a subcommand (CLIENT SETNAME, XINFO STREAM).
	redisContainers = redisSet("ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "DEBUG", "FUNCTION", "LATENCY", "MEMORY",
		"MODULE", "OBJECT", "PUBSUB", "SCRIPT", "SLOWLOG", "XGROUP", "XINFO")
	// Of those, the ones with a key after the subcommand.
	redisSubKey = redisSet("OBJECT", "MEMORY", "XGROUP", "XINFO")
	// No key: what follows is a password, a message, a number or nothing.
	redisNoKey = redisSet("PING", "ECHO", "INFO", "AUTH", "HELLO", "SELECT", "QUIT", "RESET", "MULTI", "EXEC", "DISCARD",
		"UNWATCH", "DBSIZE", "TIME", "FLUSHDB", "FLUSHALL", "SAVE", "BGSAVE", "BGREWRITEAOF", "LASTSAVE", "SCAN",
		"RANDOMKEY", "SWAPDB", "SHUTDOWN", "ROLE", "REPLICAOF", "SLAVEOF", "READONLY", "READWRITE", "LOLWUT", "FAILOVER",
		"PSYNC", "SYNC", "REPLCONF", "MIGRATE")
	// Script calls: script or name, then how many keys, then the keys.
	redisScripts = redisSet("EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL", "FCALL_RO")
	// How many keys first, then the keys.
	redisNumkeys = redisSet("ZUNION", "ZINTER", "ZDIFF", "SINTERCARD", "ZINTERCARD", "LMPOP", "ZMPOP")
	// Waiting, not working: a queue worker sits in these for seconds, so
	// timing them would put every idle worker at the top of the slow list.
	redisWaiting = redisSet("BLPOP", "BRPOP", "BRPOPLPUSH", "BLMOVE", "BLMPOP", "BZPOPMIN", "BZPOPMAX", "BZMPOP", "WAIT",
		"WAITAOF", "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE", "SUNSUBSCRIBE", "MONITOR")
	redisPrefixes = redisSet("PIPELINE", "MULTI")
)

func qIsLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// redisWord: /^[A-Za-z][A-Za-z0-9_.|-]{0,39}$/, a command or subcommand name.
func redisWord(s string) bool {
	if len(s) == 0 || len(s) > 40 || !qIsLetter(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !qIsLetter(c) && !(c >= '0' && c <= '9') && c != '_' && c != '.' && c != '|' && c != '-' {
			return false
		}
	}
	return true
}

// redisSegment: /^[A-Za-z_]{1,32}$/, a key segment kept as it is.
func redisSegment(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !qIsLetter(s[i]) && s[i] != '_' {
			return false
		}
	}
	return true
}

// asciiUpper upper-cases a-z only, as the reference does; Go's
// strings.ToUpper would turn other letters too.
func asciiUpper(s string) string {
	i := 0
	for i < len(s) && !(s[i] >= 'a' && s[i] <= 'z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// asciiUpperIs: asciiUpper(s) == upper, without making the string.
func asciiUpperIs(s, upper string) bool {
	if len(s) != len(upper) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c != upper[i] {
			return false
		}
	}
	return true
}

// redisArg is an argument as a string: a string, or []byte decoded.
// Anything else (a number, a value of the app's) isn't one.
func redisArg(v any) (string, bool) {
	switch s := v.(type) {
	case string:
		return s, true
	case []byte:
		return string(s), true
	}
	return "", false
}

// redisKeyShape keeps the key's letter-only segments; a key that isn't a
// string is "?".
func redisKeyShape(key any) string {
	s, ok := redisArg(key)
	if !ok || s == "" {
		// An empty key is "?" too: "GET " would come back from the collector as "GET".
		return "?"
	}
	var b strings.Builder
	b.Grow(len(s))
	for {
		i := strings.IndexByte(s, ':')
		part := s
		if i >= 0 {
			part = s[:i]
		}
		if part == "" || redisSegment(part) {
			b.WriteString(part)
		} else {
			b.WriteByte('?')
		}
		if i < 0 {
			return b.String()
		}
		b.WriteByte(':')
		s = s[i+1:]
	}
}

// jsNumberPositive is JavaScript's Number(v) > 0, for a count of keys.
func jsNumberPositive(v any) bool {
	if s, ok := redisArg(v); ok {
		return jsStringNumber(s) > 0
	}
	switch n := v.(type) {
	case nil:
		return false
	case bool:
		return n
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return r.Int() > 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return r.Uint() > 0
	case reflect.Float32, reflect.Float64:
		return r.Float() > 0
	}
	return false
}

// jsStringNumber is JavaScript's Number(s) as far as its sign: NaN for
// anything it doesn't read, and a 0x, 0o or 0b number only 1 or 0.
func jsStringNumber(s string) float64 {
	s = qTrimJS(s)
	if s == "" {
		return 0
	}
	if len(s) > 2 && s[0] == '0' {
		base := 0
		switch s[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base > 0 {
			nonzero := false
			for i := 2; i < len(s); i++ {
				d := -1
				switch c := s[i]; {
				case c >= '0' && c <= '9':
					d = int(c - '0')
				case c >= 'a' && c <= 'f':
					d = int(c-'a') + 10
				case c >= 'A' && c <= 'F':
					d = int(c-'A') + 10
				}
				if d < 0 || d >= base {
					return math.NaN()
				}
				nonzero = nonzero || d > 0
			}
			if nonzero {
				return 1
			}
			return 0
		}
	}
	sign, t := 1.0, s
	if t[0] == '+' || t[0] == '-' {
		if t[0] == '-' {
			sign = -1
		}
		t = t[1:]
	}
	if t == "Infinity" {
		return sign * math.Inf(1)
	}
	// (\d+\.?\d*|\.\d+)([eE][+-]?\d+)?
	i, digits := 0, 0
	for i < len(t) && qIsDigit(rune(t[i])) {
		i, digits = i+1, digits+1
	}
	if i < len(t) && t[i] == '.' {
		i++
		for i < len(t) && qIsDigit(rune(t[i])) {
			i, digits = i+1, digits+1
		}
	}
	if digits == 0 {
		return math.NaN()
	}
	if i < len(t) && (t[i] == 'e' || t[i] == 'E') {
		i++
		if i < len(t) && (t[i] == '+' || t[i] == '-') {
			i++
		}
		exp := i
		for i < len(t) && qIsDigit(rune(t[i])) {
			i++
		}
		if i == exp {
			return math.NaN()
		}
	}
	if i != len(t) {
		return math.NaN()
	}
	f, _ := strconv.ParseFloat(t, 64) // out of range is ±Inf or 0, as in JavaScript
	return sign * f
}

// redisWordIs: the argument, a string or []byte, is word (upper-cased).
func redisWordIs(arg any, word string) bool {
	s, ok := redisArg(arg)
	return ok && asciiUpperIs(s, word)
}

// redisCommand is a command as the client sends it (["GET", "user:42"]) ->
// "GET user:?", or false for one that isn't timed (blocking, or not a
// command). What a package sends is this; the collector checks it with
// redisStatement.
func redisCommand(args []any) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	first, ok := redisArg(args[0])
	if !ok || !redisWord(first) {
		return "", false
	}
	name := asciiUpper(first)
	if redisWaiting[name] {
		return "", false
	}
	xread := name == "XREAD" || name == "XREADGROUP"
	command, key := name, -1
	switch {
	case redisContainers[name]:
		if len(args) > 1 {
			if sub, ok := redisArg(args[1]); ok && redisWord(sub) {
				command = name + " " + asciiUpper(sub)
				// Only after a subcommand: "OBJECT user" would read back as OBJECT USER.
				if redisSubKey[name] {
					key = 2
				}
			}
		}
	case redisScripts[name]:
		if len(args) > 2 && jsNumberPositive(args[2]) {
			key = 3
		}
	case redisNumkeys[name]:
		if len(args) > 1 && jsNumberPositive(args[1]) {
			key = 2
		}
	case name == "BITOP":
		key = 2
	case xread:
		// Its options, then STREAMS and the keys. XREADGROUP's group and
		// consumer come first and may be named anything, as may a stream
		// ("block").
		from := 1
		if name == "XREADGROUP" {
			from = 4
		}
		for i := from; i < len(args); i++ {
			if redisWordIs(args[i], "BLOCK") {
				return "", false
			}
			if redisWordIs(args[i], "STREAMS") {
				key = i + 1
				break
			}
		}
	case !redisNoKey[name] && !redisPrefixes[name]:
		key = 1
	}
	if key >= 0 && key < len(args) {
		return command + " " + redisKeyShape(args[key]), true
	}
	return command, true
}

// redisStatement checks a statement a package sent:
// [PIPELINE|MULTI] COMMAND [SUBCOMMAND] [key]. Anything else (an argument
// a package let through) is (other).
func redisStatement(text string) string {
	words := strings.FieldsFunc(text, qJsSpace)
	if len(words) == 0 {
		return ""
	}
	out := make([]string, 0, 4)
	i := 0
	if first := asciiUpper(words[0]); redisPrefixes[first] && len(words) > 1 {
		out = append(out, first)
		i++
	}
	if !redisWord(words[i]) {
		return otherStatement
	}
	name := asciiUpper(words[i])
	i++
	if redisWaiting[name] {
		return otherStatement
	}
	out = append(out, name)
	if redisContainers[name] && i < len(words) && redisWord(words[i]) {
		out = append(out, asciiUpper(words[i]))
		i++
	}
	if i < len(words)-1 {
		return otherStatement
	}
	if i < len(words) {
		out = append(out, redisKeyShape(words[i]))
	}
	return strings.Join(out, " ")
}
